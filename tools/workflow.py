"""Workflow engine for Android pentest pipelines.

Defines a YAML-based workflow format with phases, steps, dependencies,
variable resolution, pipe transforms, conditional execution, and foreach loops.

The engine reads a workflow definition, resolves all variable references,
validates the dependency graph, and executes steps in topological order
while persisting all results to the StorageManager.
"""

import json
import logging
import re
import sys
from collections import OrderedDict
from datetime import datetime
from importlib import import_module
from pathlib import Path
from typing import Any, Callable

import yaml

from tools.storage import StorageManager

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# TOOL REGISTRY — maps abstract tool names → Python implementations
# ------------------------------------------------------------------

ToolFunc = Callable[..., Any]

class ToolEntry:
    """Metadata for a registered tool."""

    def __init__(self, name: str, func: ToolFunc, description: str = "",
                 params: dict | None = None, outputs: list | None = None):
        self.name = name
        self.func = func
        self.description = description
        self.params = params or {}
        self.outputs = outputs or []


class ToolRegistry:
    """Central tool registry.

    Tools can be registered programmatically or discovered from
    the ``tools/`` package.
    """

    def __init__(self):
        self._tools: dict[str, ToolEntry] = {}
        self._load_builtins()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, name: str, func: ToolFunc | None = None,
                 description: str = "", params: dict | None = None,
                 outputs: list | None = None) -> ToolFunc | ToolEntry:
        """Register a tool. Can be used as a decorator or directly."""

        def _register(fn: ToolFunc) -> ToolEntry:
            entry = ToolEntry(name, fn, description, params, outputs)
            self._tools[name] = entry
            return entry

        if func is not None:
            return _register(func)
        return _register  # decorator mode

    def get(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def list(self) -> list[str]:
        return list(self._tools.keys())

    def resolve_alias(self, name: str, aliases: dict[str, str]) -> ToolEntry | None:
        actual = aliases.get(name, name)
        return self.get(actual)

    # ------------------------------------------------------------------
    # Built-in tool discovery
    # ------------------------------------------------------------------

    def _load_builtins(self):
        """Discover tools from ``tools/`` package by convention.

        Each module can export a ``TOOLS`` dict mapping name → metadata.
        """
        import tools  # noqa: F811
        pkg = Path(tools.__file__).parent
        for mod_path in pkg.glob("*.py"):
            if mod_path.stem.startswith("_"):
                continue
            try:
                mod = import_module(f"tools.{mod_path.stem}")
            except Exception as e:
                logger.debug("Skipping tools.%s: %s", mod_path.stem, e)
                continue

            for attr_name in dir(mod):
                if attr_name.startswith("_"):
                    continue
                attr = getattr(mod, attr_name)
                if callable(attr) and hasattr(attr, "_tool_meta"):
                    meta = attr._tool_meta
                    self._tools[meta["name"]] = ToolEntry(
                        meta["name"], attr,
                        meta.get("description", ""),
                        meta.get("params", {}),
                        meta.get("outputs", []),
                    )


def tool_meta(name: str, description: str = "",
              params: dict | None = None,
              outputs: list | None = None):
    """Decorator to mark a function as a workflow tool."""
    def decorator(fn):
        fn._tool_meta = {
            "name": name,
            "description": description,
            "params": params or {},
            "outputs": outputs or [],
        }
        return fn
    return decorator


# ------------------------------------------------------------------
# VARIABLE RESOLVER
# ------------------------------------------------------------------

_VAR_PATTERN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.| \t\-\[\]()=!'\"<>,#@$%^&*+?/:;]*?)\}")

def resolve_vars(value: Any, ctx: dict[str, Any]) -> Any:
    """Resolve ``{var.path}`` and ``{var | pipe}`` references in a value.

    Supports:
      - ``{step_id}`` → ctx["step_id"]
      - ``{step_id.output_field}`` → ctx["step_id"]["output_field"]
      - ``{list | length}`` → len(list)
      - ``{list | unique}`` → dedup
      - ``{list | map(.field)}`` → [item["field"] for item in list]
      - ``{list | filter(.field == 'val')}`` → filtered list
      - ``{list | extract_domains}`` → extract domains from URLs
      - ``{a | length > 0}`` → condition check
    """
    if isinstance(value, str):
        return _resolve_str(value, ctx)
    if isinstance(value, list):
        return [_resolve_str(item, ctx) if isinstance(item, str) else item for item in value]
    if isinstance(value, dict):
        return {k: resolve_vars(v, ctx) for k, v in value.items()}
    return value


def _resolve_str(template: str, ctx: dict) -> str:
    """Resolve variables in a single string."""
    def _replace(m: re.Match) -> str:
        expr = m.group(1).strip()
        return str(_eval_expr(expr, ctx))

    result = _VAR_PATTERN.sub(_replace, template)
    return result


def _eval_expr(expr: str, ctx: dict) -> Any:
    """Evaluate a variable/piped expression.

    Examples: ``step_id``, ``step_id.field``, ``list | length``,
    ``list | map(.url)``, ``list | filter(.category == 'api')``,
    ``list | length > 0``, ``list | count == 5``.
    """
    parts = [p.strip() for p in expr.split("|")]
    base = parts[0].strip()
    val = _resolve_path(base, ctx)

    if len(parts) == 1:
        return val

    # Separate transformation pipes from final comparison
    trans_pipes = parts[1:-1] if len(parts) > 2 else []
    last_part = parts[-1]

    # Check if the last part is a comparison like "> 0", "== 5", "!= 0"
    cmp_match = re.match(r"(length|count)\s*([><=!]+)\s*(\d+)\s*$", last_part, re.IGNORECASE)

    if cmp_match:
        # Apply transformation pipes first
        for p in trans_pipes:
            val = _apply_pipe(val, p)
        # Apply the length pipe
        if hasattr(val, "__len__"):
            val = len(val)
        else:
            try:
                val = int(val)
            except (ValueError, TypeError):
                val = 0
        # Apply comparison
        op, num = cmp_match.group(2), int(cmp_match.group(3))
        if op == ">": return val > num
        if op == "<": return val < num
        if op == ">=": return val >= num
        if op == "<=": return val <= num
        if op == "==": return val == num
        if op == "!=": return val != num
        return False

    # All parts are transformation pipes
    for pipe_expr in parts[1:]:
        val = _apply_pipe(val, pipe_expr)

    return val


def _resolve_path(path: str, ctx: dict) -> Any:
    """Resolve a dotted path like ``step_id`` or ``step_id.field``."""
    segments = path.split(".")
    val = ctx
    for seg in segments:
        if isinstance(val, dict):
            val = val.get(seg, "")
        elif isinstance(val, list) and seg.isdigit():
            val = val[int(seg)]
        elif hasattr(val, seg):
            val = getattr(val, seg)
        else:
            return ""
    return val if val is not None else ""


def _apply_pipe(val: Any, pipe: str) -> Any:
    """Apply a single pipe transformation."""
    # length
    if pipe == "length" or pipe == "count":
        return len(val) if hasattr(val, "__len__") else 0

    # unique
    if pipe == "unique":
        if isinstance(val, list):
            seen: set = set()
            result = []
            for item in val:
                if isinstance(item, dict):
                    key = json.dumps(item, sort_keys=True)
                else:
                    key = item
                if key not in seen:
                    seen.add(key)
                    result.append(item)
            return result
        return val

    # extract_domains
    if pipe == "extract_domains":
        domains: set = set()
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    u = item.get("url", "")
                elif isinstance(item, str):
                    u = item
                else:
                    continue
                m = re.search(r"https?://([^/:/\s]+)", u)
                if m:
                    domains.add(m.group(1))
        return list(domains)

    # map(.field) or map(field)
    m_map = re.match(r"map\((.+?)\)", pipe)
    if m_map:
        field = m_map.group(1).strip()
        if field.startswith("."):
            field = field[1:]
        if isinstance(val, list):
            return [item.get(field, "") if isinstance(item, dict) else "" for item in val if isinstance(item, dict)]
        return []

    # filter(.field == 'value') or filter(.field != 'value')
    m_filter = re.match(r"filter\((.+?)\)", pipe)
    if m_filter:
        cond = m_filter.group(1).strip()
        m_op = re.match(r"\.(\w+)\s*(==|!=|>|<|>=|<=|in)\s*(.+)", cond)
        if m_op and isinstance(val, list):
            field, op = m_op.group(1), m_op.group(2)
            expected = m_op.group(3).strip().strip("'\"")
            result = []
            for item in val:
                if not isinstance(item, dict):
                    continue
                actual = item.get(field, "")
                if op == "==" and str(actual) == expected:
                    result.append(item)
                elif op == "!=" and str(actual) != expected:
                    result.append(item)
                elif op == "in" and expected in str(actual):
                    result.append(item)
            return result
        return val if isinstance(val, list) else []

    return val


# ------------------------------------------------------------------
# WORKFLOW ENGINE
# ------------------------------------------------------------------

class WorkflowError(Exception):
    """Base workflow exception."""


class StepError(WorkflowError):
    """Step execution error."""


class WorkflowEngine:
    """Executes Android pentest workflows defined in YAML.

    Usage::

        storage = StorageManager("workspace").init()
        engine = WorkflowEngine(storage)
        engine.load("workflows/default.yaml")
        engine.execute(target_id=1, apk_path="path/to.apk")
    """

    def __init__(self, storage: StorageManager, registry: ToolRegistry | None = None):
        self.storage = storage
        self.registry = registry or ToolRegistry()
        self._workflow: dict = {}
        self._ctx: dict[str, Any] = {}       # variable context
        self._step_results: dict[str, Any] = {}
        self._run_id: int | None = None
        self._target_id: int | None = None

    # ------------------------------------------------------------------
    # Load & validate
    # ------------------------------------------------------------------

    def load(self, path: str | Path) -> "WorkflowEngine":
        """Load and validate a workflow YAML file."""
        with open(path, encoding="utf-8") as f:
            self._workflow = yaml.safe_load(f)

        self._validate()
        logger.info("Workflow '%s' v%s loaded: %d phases, %d steps",
                     self._workflow.get("name", "?"),
                     self._workflow.get("version", "?"),
                     len(self._phases()),
                     sum(len(p.get("steps", [])) for p in self._phases()))
        return self

    def _validate(self):
        """Validate workflow structure."""
        wf = self._workflow
        if not wf:
            raise WorkflowError("Empty workflow definition")

        phases = wf.get("phases", [])
        if not phases:
            raise WorkflowError("Workflow has no phases")

        seen_ids: set = set()
        for phase in phases:
            for step in phase.get("steps", []):
                sid = step.get("id", "")
                if not sid:
                    raise WorkflowError(f"Step without id in phase '{phase.get('name')}'")
                if sid in seen_ids:
                    raise WorkflowError(f"Duplicate step id: {sid}")
                seen_ids.add(sid)

                # Check depends_on references
                for dep in step.get("depends_on", []):
                    if dep not in seen_ids and dep != sid:
                        raise WorkflowError(f"Step '{sid}' depends on unknown step '{dep}'")

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(self, target_id: int, apk_path: str = "",
                context: dict | None = None) -> dict[str, Any]:
        """Execute the full workflow for a target.

        Returns:
            Dict with all step results.
        """
        self._target_id = target_id
        self._step_results = {}

        target = self.storage.get_target(target_id)
        if not target:
            raise WorkflowError(f"Target {target_id} not found")

        # Build variable context
        self._ctx = {
            "target": {
                "id": target_id,
                "package": target.get("package_name", ""),
                "app_name": target.get("app_name", ""),
                "apk": apk_path,
            },
            "vars": self._workflow.get("vars", {}),
            "tools": self._workflow.get("tools", {}),
        }
        if context:
            self._ctx.update(context)

        # Start analysis run
        self._run_id = self.storage.start_run(
            target_id, self._workflow.get("name", "workflow"),
            tool_version=self._workflow.get("version", "?"),
        )

        logger.info("=== Starting workflow '%s' (run %d) ===",
                     self._workflow.get("name"), self._run_id)

        try:
            for phase in self._phases():
                self._execute_phase(phase)
        except WorkflowError:
            self.storage.complete_run(self._run_id, status="failed")
            raise
        except Exception as e:
            self.storage.complete_run(self._run_id, status="failed")
            raise WorkflowError(f"Workflow failed: {e}") from e

        self.storage.complete_run(self._run_id, status="completed")
        logger.info("=== Workflow '%s' completed (run %d) ===",
                     self._workflow.get("name"), self._run_id)

        return self._step_results

    def _phases(self) -> list[dict]:
        return self._workflow.get("phases", [])

    def _execute_phase(self, phase: dict):
        """Execute all steps in a phase in dependency order."""
        name = phase.get("name", "?")
        logger.info("--- Phase: %s ---", name)

        # Check `when` condition
        when_cond = phase.get("when")
        if when_cond:
            resolved = resolve_vars(when_cond, self._ctx)
            if not resolved:
                logger.info("Phase '%s' skipped (when condition false)", name)
                return

        steps = phase.get("steps", [])
        if not steps:
            return

        # Topological sort by depends_on
        ordered = _topological_sort(steps)
        phase_on_fail = phase.get("on_fail", "stop")

        for step_def in ordered:
            self._execute_step(phase, step_def, phase_on_fail)

    def _execute_step(self, phase: dict, step_def: dict,
                      phase_on_fail: str = "stop"):
        """Execute a single workflow step."""
        sid = step_def["id"]
        logger.info("  Step: %s (%s)", sid, step_def.get("tool", "?"))

        # Check `when`
        when_cond = step_def.get("when")
        if when_cond:
            resolved = resolve_vars(when_cond, self._ctx)
            if not resolved:
                logger.info("    Skipped (when=false)")
                self._step_results[sid] = {"skipped": True}
                return

        # Resolve params with variables
        raw_params = step_def.get("params", {})
        params = resolve_vars(raw_params, self._ctx)

        # `foreach` — run multiple times
        foreach_list = step_def.get("foreach")
        if foreach_list:
            items = resolve_vars(foreach_list, self._ctx)
            if isinstance(items, str):
                items = [items]
            results = []
            for item in items:
                iter_params = dict(params)
                iter_params["_item"] = item
                result = self._call_tool(sid, step_def, iter_params, phase_on_fail)
                if result is not None:
                    results.append(result)
            self._step_results[sid] = results
            self._ctx[sid] = results
            return

        # Normal single execution
        result = self._call_tool(sid, step_def, params, phase_on_fail)
        self._step_results[sid] = result
        self._ctx[sid] = result

    def _call_tool(self, sid: str, step_def: dict,
                    params: dict, phase_on_fail: str) -> Any:
        """Resolve and call the tool function."""
        tool_name_raw = step_def.get("tool", "")
        tool_name = resolve_vars(tool_name_raw, self._ctx)

        # Resolve via aliases
        aliases = self._workflow.get("tools", {})
        entry = self.registry.resolve_alias(tool_name, aliases)

        if not entry:
            logger.warning("    Tool '%s' not found in registry, trying direct import...", tool_name)
            try:
                mod_path, func_name = tool_name.rsplit(".", 1)
                mod = import_module(mod_path)
                fn = getattr(mod, func_name)
            except (ImportError, AttributeError, ValueError) as e:
                logger.error("    Tool '%s' unavailable: %s", tool_name, e)
                return self._handle_failure(sid, step_def, phase_on_fail, f"Tool not found: {tool_name}")
            entry = ToolEntry(tool_name, fn)

        step_on_fail = step_def.get("on_fail", phase_on_fail)

        # Inject context
        params["_storage"] = self.storage
        params["_target_id"] = self._target_id
        params["_run_id"] = self._run_id
        params["_workflow"] = self._workflow

        try:
            result = entry.func(**params)
            return result
        except Exception as e:
            logger.error("    Step '%s' failed: %s", sid, e)
            return self._handle_failure(sid, step_def, step_on_fail, str(e))

    def _handle_failure(self, sid: str, step_def: dict,
                         on_fail: str, reason: str) -> Any:
        """Handle step failure based on on_fail policy."""
        if on_fail == "continue":
            logger.warning("    Continuing after failure")
            return {"error": reason, "skipped": True}

        if on_fail == "skip":
            logger.warning("    Skipping remaining steps in phase")
            raise StepError(f"Step '{sid}' failed: {reason}")

        # on_fail == "stop" (default)
        raise WorkflowError(f"Step '{sid}' failed: {reason}")

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def get_result(self, step_id: str) -> Any:
        return self._step_results.get(step_id)

    def all_results(self) -> dict[str, Any]:
        return dict(self._step_results)


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------

def _topological_sort(steps: list[dict]) -> list[dict]:
    """Topological sort of steps based on ``depends_on``.

    Uses Kahn's algorithm. Raises WorkflowError on cycle.
    """
    step_map = {s["id"]: s for s in steps}
    in_degree: dict[str, int] = {s["id"]: 0 for s in steps}
    graph: dict[str, list[str]] = {s["id"]: [] for s in steps}

    for s in steps:
        sid = s["id"]
        for dep in s.get("depends_on", []):
            if dep in step_map:
                graph[dep].append(sid)
                in_degree[sid] = in_degree.get(sid, 0) + 1

    queue = [sid for sid, deg in in_degree.items() if deg == 0]
    ordered = []
    visited = set()

    while queue:
        sid = queue.pop(0)
        if sid in visited:
            continue
        visited.add(sid)
        ordered.append(step_map[sid])
        for neighbor in graph.get(sid, []):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if len(ordered) != len(steps):
        raise WorkflowError("Circular dependency detected in workflow steps")

    return ordered
