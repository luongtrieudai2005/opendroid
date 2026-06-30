"""Central workspace storage: global SQLite + FTS5 + filesystem for Android pentest.

Supports:
  - Multiple APK files per target (different versions, debug/prod, AAB splits)
  - Multiple analysis runs with per-run tracking
  - Categorized endpoints (external, internal, cloud, third-party)
  - Full-text search via FTS5 across all data
"""

import json
import logging
import hashlib
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.INTERNET",
}

_SCHEMA_SQL = """

-- ============================================================
-- TARGETS (one app/company)
-- ============================================================
CREATE TABLE IF NOT EXISTS targets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    package_name    TEXT NOT NULL,
    app_name        TEXT,
    description     TEXT,
    version_name    TEXT,
    tags            TEXT DEFAULT '[]',
    notes           TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP,
    UNIQUE(package_name)
);

-- ============================================================
-- APK FILES (many per target: versions, debug/prod, AAB splits)
-- ============================================================
CREATE TABLE IF NOT EXISTS apk_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    filename        TEXT NOT NULL,
    file_hash       TEXT,
    file_size       INTEGER,
    version_name    TEXT,
    version_code    TEXT,
    build_type      TEXT DEFAULT 'unknown',    -- debug | release | aab-split | bundle
    source          TEXT DEFAULT 'file',       -- file | playstore | pure
    imported_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- ANALYSIS RUNS (each decompilation/analysis session)
-- ============================================================
CREATE TABLE IF NOT EXISTS analysis_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    apk_id          INTEGER REFERENCES apk_files(id),
    label           TEXT,                       -- e.g. "jadx-v1", "recon-2024-01"
    tool_version    TEXT,
    status          TEXT DEFAULT 'running',     -- running | completed | failed
    started_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at    TIMESTAMP
);

-- ============================================================
-- MANIFEST COMPONENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS manifest_components (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    type            TEXT NOT NULL,              -- activity | service | receiver | provider
    name            TEXT NOT NULL,
    exported        INTEGER DEFAULT 0,
    intent_filters  TEXT
);

CREATE TABLE IF NOT EXISTS permissions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    name            TEXT NOT NULL,
    is_dangerous    INTEGER DEFAULT 0
);

-- ============================================================
-- SECRETS (API keys, tokens, passwords)
-- ============================================================
CREATE TABLE IF NOT EXISTS secrets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    type            TEXT NOT NULL,              -- api_key | jwt | password | token | firebase_url | aws_key | secret_key | generic
    value           TEXT NOT NULL,
    confidence      TEXT DEFAULT 'medium',
    source_file     TEXT,
    line_number     INTEGER,
    context         TEXT,
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- ENDPOINTS / URLs
-- ============================================================
CREATE TABLE IF NOT EXISTS endpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    url             TEXT NOT NULL,
    method          TEXT DEFAULT 'GET',
    category        TEXT DEFAULT 'unknown',     -- external | internal | cloud | third-party | cdn | otp
    source          TEXT DEFAULT 'unknown',     -- jadx | wayback | crawler | burp | gau | katana
    source_file     TEXT,
    params          TEXT,
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- FIREBASE
-- ============================================================
CREATE TABLE IF NOT EXISTS firebase_instances (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    url             TEXT NOT NULL,
    accessible      INTEGER DEFAULT 0,
    data_preview    TEXT,
    checked_at      TIMESTAMP
);

-- ============================================================
-- NATIVE LIBRARIES (.so)
-- ============================================================
CREATE TABLE IF NOT EXISTS native_libraries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    path            TEXT,
    architecture    TEXT,
    functions       TEXT,
    strings         TEXT
);

-- ============================================================
-- SUBDOMAINS (from recon)
-- ============================================================
CREATE TABLE IF NOT EXISTS subdomains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    domain          TEXT NOT NULL,
    source          TEXT DEFAULT 'subfinder',
    resolved        INTEGER DEFAULT 0,
    ip_address      TEXT,
    tech_stack      TEXT,
    discovered_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- FINDINGS / VULNERABILITIES
-- ============================================================
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    title           TEXT,
    description     TEXT,
    evidence        TEXT,
    url             TEXT,
    source          TEXT DEFAULT 'manual',      -- nuclei | apk_analyzer | manual | burp
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- HTTP TRAFFIC (captured via Burp/mitmproxy)
-- ============================================================
CREATE TABLE IF NOT EXISTS http_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    method          TEXT,
    url             TEXT,
    request_headers TEXT,
    request_body    TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body   TEXT,
    source          TEXT DEFAULT 'burp',
    captured_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- FUZZ RESULTS
-- ============================================================
CREATE TABLE IF NOT EXISTS fuzz_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    run_id          INTEGER REFERENCES analysis_runs(id),
    url             TEXT,
    param           TEXT,
    payload         TEXT,
    response_status INTEGER,
    response_length INTEGER,
    interesting     INTEGER DEFAULT 0,
    reason          TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- FTS5 FULL-TEXT SEARCH
-- ============================================================
CREATE VIRTUAL TABLE IF NOT EXISTS endpoints_fts USING fts5(
    url, method, params, source,
    content='endpoints', content_rowid='id'
);
CREATE VIRTUAL TABLE IF NOT EXISTS secrets_fts USING fts5(
    type, value, context,
    content='secrets', content_rowid='id'
);
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title, description, evidence,
    content='findings', content_rowid='id'
);

-- ============================================================
-- FTS5 TRIGGERS
-- ============================================================
CREATE TRIGGER IF NOT EXISTS endpoints_ai AFTER INSERT ON endpoints BEGIN
    INSERT INTO endpoints_fts(rowid, url, method, params, source)
    VALUES (new.id, new.url, new.method, new.params, new.source);
END;
CREATE TRIGGER IF NOT EXISTS endpoints_ad AFTER DELETE ON endpoints BEGIN
    INSERT INTO endpoints_fts(endpoints_fts, rowid, url, method, params, source)
    VALUES ('delete', old.id, old.url, old.method, old.params, old.source);
END;
CREATE TRIGGER IF NOT EXISTS endpoints_au AFTER UPDATE ON endpoints BEGIN
    INSERT INTO endpoints_fts(endpoints_fts, rowid, url, method, params, source)
    VALUES ('delete', old.id, old.url, old.method, old.params, old.source);
    INSERT INTO endpoints_fts(rowid, url, method, params, source)
    VALUES (new.id, new.url, new.method, new.params, new.source);
END;

CREATE TRIGGER IF NOT EXISTS secrets_ai AFTER INSERT ON secrets BEGIN
    INSERT INTO secrets_fts(rowid, type, value, context)
    VALUES (new.id, new.type, new.value, new.context);
END;
CREATE TRIGGER IF NOT EXISTS secrets_ad AFTER DELETE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, type, value, context)
    VALUES ('delete', old.id, old.type, old.value, old.context);
END;
CREATE TRIGGER IF NOT EXISTS secrets_au AFTER UPDATE ON secrets BEGIN
    INSERT INTO secrets_fts(secrets_fts, rowid, type, value, context)
    VALUES ('delete', old.id, old.type, old.value, old.context);
    INSERT INTO secrets_fts(rowid, type, value, context)
    VALUES (new.id, new.type, new.value, new.context);
END;

CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, title, description, evidence)
    VALUES (new.id, new.title, new.description, new.evidence);
END;
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence)
    VALUES ('delete', old.id, old.title, old.description, old.evidence);
END;
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence)
    VALUES ('delete', old.id, old.title, old.description, old.evidence);
    INSERT INTO findings_fts(rowid, title, description, evidence)
    VALUES (new.id, new.title, new.description, new.evidence);
END;
"""


class StorageManager:
    """Central workspace for Android pentest.

    Global SQLite database (with FTS5) + filesystem for binaries.
    One target = one app/company, can have many APK files.
    """

    def __init__(self, workspace_root: str | Path = "workspace"):
        self.root = Path(workspace_root).resolve()
        self._db_path = self.root / "scan.db"
        self._targets_dir = self.root / "targets"
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def init(self) -> "StorageManager":
        self._targets_dir.mkdir(parents=True, exist_ok=True)
        self._connect()
        self._ensure_schema()
        n = self._count("targets")
        logger.info("Storage: %s | %d targets | %d findings | %d endpoints",
                     self.root, n, self._count("findings"), self._count("endpoints"))
        return self

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self.init()

    def __exit__(self, *args):
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self):
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")

    def _ensure_schema(self):
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def _execute(self, sql: str, params=None) -> sqlite3.Cursor:
        if params is None:
            return self._conn.execute(sql)
        return self._conn.execute(sql, params)

    def _fetchone(self, sql: str, params=None) -> dict | None:
        cur = self._execute(sql, params or ())
        row = cur.fetchone()
        return dict(row) if row else None

    def _fetchall(self, sql: str, params=None) -> list[dict]:
        cur = self._execute(sql, params or ())
        return [dict(r) for r in cur.fetchall()]

    def _count(self, table: str, target_id: int | None = None) -> int:
        if target_id:
            row = self._fetchone(
                f"SELECT COUNT(*) AS c FROM {table} WHERE target_id = ?", (target_id,)
            )
        else:
            row = self._fetchone(f"SELECT COUNT(*) AS c FROM {table}")
        return row["c"] if row else 0

    def _tdir(self, target_id: int) -> Path:
        """Target directory on filesystem."""
        t = self.get_target(target_id)
        if not t:
            raise ValueError(f"Unknown target {target_id}")
        safe = t["package_name"].replace(".", "_").replace("/", "_")
        return self._targets_dir / f"{safe}_{target_id}"

    # ------------------------------------------------------------------
    # TARGETS
    # ------------------------------------------------------------------

    def create_target(self, package_name: str, **kw) -> int:
        t = self._fetchone(
            "SELECT id FROM targets WHERE package_name = ?", (package_name,)
        )
        if t:
            tid = t["id"]
            updates = {k: v for k, v in kw.items() if v is not None}
            if updates:
                updates["updated_at"] = datetime.utcnow().isoformat()
                set_clause = ", ".join(f"{k}=?" for k in updates)
                self._execute(
                    f"UPDATE targets SET {set_clause} WHERE id=?",
                    list(updates.values()) + [tid],
                )
            self._tdir(tid).mkdir(parents=True, exist_ok=True)
            return tid

        fields = ["package_name"] + [k for k in kw if kw[k] is not None]
        vals = [package_name] + [kw[k] for k in fields[1:]]
        cur = self._execute(
            f"INSERT INTO targets ({', '.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            vals,
        )
        self._conn.commit()
        tid = cur.lastrowid
        self._tdir(tid).mkdir(parents=True, exist_ok=True)
        logger.info("Target %d: %s", tid, package_name)
        return tid

    def get_target(self, target_id: int) -> dict | None:
        return self._fetchone("SELECT * FROM targets WHERE id = ?", (target_id,))

    def find_target(self, package_or_id: str | int) -> dict | None:
        if isinstance(package_or_id, int) or package_or_id.isdigit():
            return self.get_target(int(package_or_id))
        return self._fetchone(
            "SELECT * FROM targets WHERE package_name = ?", (package_or_id,)
        )

    def list_targets(self) -> list[dict]:
        return self._fetchall(
            "SELECT id, package_name, app_name, tags, created_at, updated_at, "
            "(SELECT COUNT(*) FROM apk_files WHERE target_id=t.id) AS apk_count, "
            "(SELECT COUNT(*) FROM findings WHERE target_id=t.id) AS findings_count, "
            "(SELECT COUNT(*) FROM endpoints WHERE target_id=t.id) AS endpoints_count "
            "FROM targets t ORDER BY updated_at DESC"
        )

    def delete_target(self, target_id: int) -> bool:
        t = self.get_target(target_id)
        if not t:
            return False
        d = self._tdir(target_id)
        if d.exists():
            shutil.rmtree(d)
        for tbl in ("apk_files", "analysis_runs", "manifest_components", "permissions",
                     "secrets", "endpoints", "firebase_instances", "native_libraries",
                     "subdomains", "findings", "http_requests", "fuzz_results"):
            self._execute(f"DELETE FROM {tbl} WHERE target_id=?", (target_id,))
        self._execute("DELETE FROM targets WHERE id=?", (target_id,))
        self._conn.commit()
        logger.info("Deleted target %d: %s", target_id, t["package_name"])
        return True

    def update_target(self, target_id: int, **kw):
        if not kw:
            return
        kw["updated_at"] = datetime.utcnow().isoformat()
        set_clause = ", ".join(f"{k}=?" for k in kw)
        self._execute(
            f"UPDATE targets SET {set_clause} WHERE id=?",
            list(kw.values()) + [target_id],
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # APK FILES (many per target)
    # ------------------------------------------------------------------

    def save_apk(self, target_id: int, apk_path: str,
                 version_name: str = "", version_code: str = "",
                 build_type: str = "unknown",
                 source: str = "file") -> dict:
        """Copy APK into workspace and register in DB."""
        src = Path(apk_path)
        if not src.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        apk_dir = self._tdir(target_id) / "sources" / "apks"
        apk_dir.mkdir(parents=True, exist_ok=True)
        dest = apk_dir / src.name
        shutil.copy2(str(src), str(dest))

        file_hash = hashlib.sha256(dest.read_bytes()).hexdigest()[:16]
        file_size = dest.stat().st_size

        cur = self._execute(
            "INSERT INTO apk_files (target_id, filename, file_hash, file_size, "
            "version_name, version_code, build_type, source) VALUES (?,?,?,?,?,?,?,?)",
            (target_id, src.name, file_hash, file_size,
             version_name, version_code, build_type, source),
        )
        self._conn.commit()
        apk_id = cur.lastrowid

        entry = {
            "id": apk_id,
            "filename": src.name,
            "hash": file_hash,
            "size": file_size,
            "version": version_name or "?",
            "build": build_type,
            "path": str(dest),
        }
        logger.info("APK saved: %s (%s, %s, %s)", src.name, build_type, version_name,
                     _fmt_size(file_size))
        return entry

    def list_apks(self, target_id: int) -> list[dict]:
        return self._fetchall(
            "SELECT * FROM apk_files WHERE target_id=? ORDER BY imported_at DESC",
            (target_id,),
        )

    def get_apk_path(self, apk_id: int) -> Path | None:
        row = self._fetchone(
            "SELECT f.*, t.package_name FROM apk_files f "
            "JOIN targets t ON t.id=f.target_id WHERE f.id=?",
            (apk_id,),
        )
        if not row:
            return None
        tdir = self._tdir(row["target_id"])
        return tdir / "sources" / "apks" / row["filename"]

    # ------------------------------------------------------------------
    # ANALYSIS RUNS
    # ------------------------------------------------------------------

    def start_run(self, target_id: int, label: str,
                  apk_id: int | None = None,
                  tool_version: str = "") -> int:
        cur = self._execute(
            "INSERT INTO analysis_runs (target_id, apk_id, label, tool_version, status) "
            "VALUES (?,?,?,?,'running')",
            (target_id, apk_id, label, tool_version),
        )
        self._conn.commit()
        return cur.lastrowid

    def complete_run(self, run_id: int, status: str = "completed"):
        self._execute(
            "UPDATE analysis_runs SET status=?, completed_at=? WHERE id=?",
            (status, datetime.utcnow().isoformat(), run_id),
        )
        self._conn.commit()

    def list_runs(self, target_id: int) -> list[dict]:
        return self._fetchall(
            "SELECT r.*, f.filename AS apk_filename "
            "FROM analysis_runs r LEFT JOIN apk_files f ON f.id=r.apk_id "
            "WHERE r.target_id=? ORDER BY r.started_at DESC",
            (target_id,),
        )

    # ------------------------------------------------------------------
    # DECOMPILED SOURCE (filesystem storage)
    # ------------------------------------------------------------------

    def save_jadx_output(self, target_id: int, jadx_dir: str,
                         label: str = "jadx") -> Path | None:
        src = Path(jadx_dir)
        if not src.exists():
            return None
        dest = self._tdir(target_id) / "sources" / f"jadx_{label}"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(str(src), str(dest), dirs_exist_ok=True)
        return dest

    def get_jadx_path(self, target_id: int, label: str = "jadx") -> Path | None:
        d = self._tdir(target_id) / "sources" / f"jadx_{label}"
        return d if d.exists() else None

    # ------------------------------------------------------------------
    # MANIFEST
    # ------------------------------------------------------------------

    def save_manifest(self, target_id: int, components: list[dict],
                      permissions: list[str], run_id: int | None = None):
        for c in components:
            self._execute(
                "INSERT INTO manifest_components (target_id,run_id,type,name,exported,intent_filters) "
                "VALUES (?,?,?,?,?,?)",
                (target_id, run_id, c.get("type", "activity"), c.get("name", ""),
                 1 if c.get("exported") else 0,
                 json.dumps(c.get("intent_filters", []))),
            )
        for p in permissions:
            self._execute(
                "INSERT INTO permissions (target_id,run_id,name,is_dangerous) VALUES (?,?,?,?)",
                (target_id, run_id, p, 1 if p in _DANGEROUS_PERMS else 0),
            )
        self._conn.commit()

    # ------------------------------------------------------------------
    # SECRETS
    # ------------------------------------------------------------------

    def add_secret(self, target_id: int, **sec) -> int:
        fields = ["target_id", "type", "value"]
        vals = [target_id, sec.get("type", "generic"), sec.get("value", "")]
        for opt in ("run_id", "confidence", "source_file", "line_number", "context"):
            if opt in sec and sec[opt] is not None:
                fields.append(opt)
                vals.append(sec[opt])
        cur = self._execute(
            f"INSERT INTO secrets ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            vals,
        )
        self._conn.commit()
        return cur.lastrowid

    def add_secrets_bulk(self, target_id: int, secrets: list[dict],
                         run_id: int | None = None) -> int:
        for s in secrets:
            if run_id is not None:
                s.setdefault("run_id", run_id)
            self.add_secret(target_id, **s)
        return len(secrets)

    def search_secrets(self, query: str, limit: int = 50) -> list[dict]:
        return self._fetchall(
            "SELECT s.*, t.package_name FROM secrets s "
            "JOIN targets t ON t.id=s.target_id "
            "WHERE s.id IN (SELECT rowid FROM secrets_fts WHERE secrets_fts MATCH ?) "
            "ORDER BY s.id DESC LIMIT ?",
            (query, limit),
        )

    # ------------------------------------------------------------------
    # ENDPOINTS
    # ------------------------------------------------------------------

    def add_endpoint(self, target_id: int, url: str, **kw) -> int:
        fields = ["target_id", "url"]
        vals = [target_id, url]
        for opt in ("run_id", "method", "category", "source", "source_file", "params"):
            if opt in kw and kw[opt] is not None:
                fields.append(opt)
                vals.append(json.dumps(kw[opt]) if opt == "params" else str(kw[opt]))
        cur = self._execute(
            f"INSERT INTO endpoints ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            vals,
        )
        self._conn.commit()
        return cur.lastrowid

    def add_endpoints_bulk(self, target_id: int, endpoints: list[dict],
                           run_id: int | None = None,
                           category: str = "unknown") -> int:
        for ep in endpoints:
            if isinstance(ep, str):
                ep = {"url": ep}
            if run_id is not None:
                ep.setdefault("run_id", run_id)
            ep.setdefault("category", category)
            self.add_endpoint(target_id, **ep)
        return len(endpoints)

    def auto_categorize_endpoint(self, url: str) -> str:
        """Guess endpoint category from URL."""
        url_lower = url.lower()
        if any(d in url_lower for d in (".firebaseio.com", "firestore.googleapis.com",
                                         "cloudfunctions.net")):
            return "cloud"
        if any(d in url_lower for d in (".s3.amazonaws.com", "s3-", ".s3.")):
            return "cloud"
        if any(d in url_lower for d in (".amazonaws.com", ".googleapis.com",
                                         ".azure.com", ".azurewebsites.net")):
            return "cloud"
        if any(d in url_lower for d in ("staging", "dev.", "development", "test.",
                                         "sandbox", "beta.", "internal", "private",
                                         "jenkins", "jira", "grafana", "kibana",
                                         "gitlab", "git.", "svn")):
            return "internal"
        if any(d in url_lower for d in (".facebook.com", ".google.com", ".apple.com",
                                         "graph.")):
            return "third-party"
        if any(d in url_lower for d in (".cdn.", "cloudfront.net", "cloudflare.com")):
            return "cdn"
        return "external"

    def search_endpoints(self, query: str, limit: int = 50) -> list[dict]:
        return self._fetchall(
            "SELECT e.*, t.package_name FROM endpoints e "
            "JOIN targets t ON t.id=e.target_id "
            "WHERE e.id IN (SELECT rowid FROM endpoints_fts WHERE endpoints_fts MATCH ?) "
            "ORDER BY e.id DESC LIMIT ?",
            (query, limit),
        )

    # ------------------------------------------------------------------
    # FIREBASE
    # ------------------------------------------------------------------

    def add_firebase(self, target_id: int, url: str,
                     accessible: bool = False,
                     data_preview: str = "") -> int:
        cur = self._execute(
            "INSERT INTO firebase_instances (target_id,url,accessible,data_preview,checked_at) "
            "VALUES (?,?,?,?,?)",
            (target_id, url, 1 if accessible else 0, data_preview,
             datetime.utcnow().isoformat()),
        )
        self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------
    # SUBDOMAINS
    # ------------------------------------------------------------------

    def add_subdomains(self, target_id: int, domains: list[str],
                       source: str = "subfinder",
                       run_id: int | None = None) -> int:
        count = 0
        for d in domains:
            d = d.strip().lower()
            if not d:
                continue
            try:
                self._execute(
                    "INSERT OR IGNORE INTO subdomains (target_id,run_id,domain,source) "
                    "VALUES (?,?,?,?)",
                    (target_id, run_id, d, source),
                )
                count += 1
            except Exception:
                continue
        self._conn.commit()
        return count

    def get_subdomains(self, target_id: int, resolved: bool | None = None) -> list[dict]:
        if resolved is True:
            return self._fetchall(
                "SELECT * FROM subdomains WHERE target_id=? AND resolved=1 ORDER BY domain",
                (target_id,),
            )
        if resolved is False:
            return self._fetchall(
                "SELECT * FROM subdomains WHERE target_id=? AND resolved=0 ORDER BY domain",
                (target_id,),
            )
        return self._fetchall(
            "SELECT * FROM subdomains WHERE target_id=? ORDER BY domain",
            (target_id,),
        )

    def update_subdomain_resolved(self, domain_id: int, ip: str = "",
                                   tech: list[str] | None = None):
        self._execute(
            "UPDATE subdomains SET resolved=1, ip_address=?, tech_stack=?, discovered_at=CURRENT_TIMESTAMP "
            "WHERE id=?",
            (ip, json.dumps(tech or []), domain_id),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # FINDINGS
    # ------------------------------------------------------------------

    def add_finding(self, target_id: int, **finding) -> int:
        fields = ["target_id", "type", "severity"]
        vals = [target_id, finding.get("type", "info"), finding.get("severity", "info")]
        for opt in ("run_id", "title", "description", "evidence", "url", "source"):
            if opt in finding and finding[opt] is not None:
                fields.append(opt)
                vals.append(str(finding[opt]))
        cur = self._execute(
            f"INSERT INTO findings ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            vals,
        )
        self._conn.commit()
        return cur.lastrowid

    def add_findings_bulk(self, target_id: int, findings: list[dict],
                          run_id: int | None = None) -> int:
        for f in findings:
            if run_id is not None:
                f.setdefault("run_id", run_id)
            self.add_finding(target_id, **f)
        return len(findings)

    def get_findings(self, target_id: int | None = None,
                     severity: str | None = None,
                     finding_type: str | None = None,
                     limit: int = 200) -> list[dict]:
        where, params = [], []
        if target_id is not None:
            where.append("f.target_id=?")
            params.append(target_id)
        if severity:
            where.append("f.severity=?")
            params.append(severity)
        if finding_type:
            where.append("f.type=?")
            params.append(finding_type)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        return self._fetchall(
            f"SELECT f.*, t.package_name FROM findings f "
            f"JOIN targets t ON t.id=f.target_id {clause} "
            f"ORDER BY f.created_at DESC LIMIT ?",
            params + [limit],
        )

    def search_findings(self, query: str, limit: int = 50) -> list[dict]:
        return self._fetchall(
            "SELECT f.*, t.package_name FROM findings f "
            "JOIN targets t ON t.id=f.target_id "
            "WHERE f.id IN (SELECT rowid FROM findings_fts WHERE findings_fts MATCH ?) "
            "ORDER BY f.created_at DESC LIMIT ?",
            (query, limit),
        )

    # ------------------------------------------------------------------
    # HTTP TRAFFIC
    # ------------------------------------------------------------------

    def add_http_request(self, target_id: int, **req) -> int:
        fields, vals = ["target_id"], [target_id]
        for opt in ("run_id", "method", "url", "request_headers", "request_body",
                     "response_status", "response_headers", "response_body", "source"):
            if opt in req and req[opt] is not None:
                fields.append(opt)
                v = req[opt]
                vals.append(json.dumps(v) if isinstance(v, (dict, list)) else str(v))
        cur = self._execute(
            f"INSERT INTO http_requests ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            vals,
        )
        self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------
    # FUZZ RESULTS
    # ------------------------------------------------------------------

    def add_fuzz_results(self, target_id: int, results: list[dict],
                         run_id: int | None = None) -> int:
        for r in results:
            self._execute(
                "INSERT INTO fuzz_results (target_id,run_id,url,param,payload,"
                "response_status,response_length,interesting,reason) VALUES (?,?,?,?,?,?,?,?,?)",
                (target_id, run_id, r.get("url", ""), r.get("param", ""),
                 r.get("payload", ""), r.get("status", 0), r.get("length", 0),
                 1 if r.get("interesting") else 0, r.get("reason", "")),
            )
        self._conn.commit()
        return len(results)

    # ------------------------------------------------------------------
    # GLOBAL SEARCH (across ALL targets)
    # ------------------------------------------------------------------

    def global_search(self, query: str, limit: int = 20) -> dict:
        return {
            "endpoints": self.search_endpoints(query, limit),
            "secrets": self.search_secrets(query, limit),
            "findings": self.search_findings(query, limit),
        }

    def get_all_summary(self) -> list[dict]:
        return self._fetchall(
            "SELECT t.id, t.package_name, t.app_name, t.tags, t.created_at, t.updated_at, "
            "(SELECT COUNT(*) FROM apk_files WHERE target_id=t.id) AS apks, "
            "(SELECT COUNT(*) FROM findings WHERE target_id=t.id) AS findings, "
            "(SELECT COUNT(*) FROM endpoints WHERE target_id=t.id) AS endpoints, "
            "(SELECT COUNT(*) FROM secrets WHERE target_id=t.id) AS secrets, "
            "(SELECT COUNT(*) FROM subdomains WHERE target_id=t.id) AS subdomains "
            "FROM targets t ORDER BY t.updated_at DESC"
        )

    # ------------------------------------------------------------------
    # REPORTS
    # ------------------------------------------------------------------

    def generate_report(self, target_id: int) -> str:
        t = self.get_target(target_id)
        if not t:
            return "# Target Not Found\n"

        apks = self.list_apks(target_id)
        findings = self.get_findings(target_id)
        endpoints = self._fetchall(
            "SELECT url, method, category, source FROM endpoints WHERE target_id=? ORDER BY id",
            (target_id,),
        )
        secrets = self._fetchall(
            "SELECT type, value, confidence FROM secrets WHERE target_id=? ORDER BY id",
            (target_id,),
        )
        subdomains = self._fetchall(
            "SELECT domain, source, resolved FROM subdomains WHERE target_id=? ORDER BY id",
            (target_id,),
        )

        lines = [
            f"# Report: {t['package_name']}",
            f"",
            f"- **App Name**: {t.get('app_name', 'N/A')}",
            f"- **Tags**: {t.get('tags', '[]')}",
            f"- **APK Files**: {len(apks)}",
            f"",
        ]

        for a in apks:
            lines.append(
                f"  - {a['filename']} ({a.get('build_type', '?')}, "
                f"v{a.get('version_name', '?')}, {_fmt_size(a.get('file_size', 0))})"
            )
        lines.append("")

        if findings:
            by_sev: dict[str, list] = {}
            for f in findings:
                by_sev.setdefault(f["severity"], []).append(f)
            lines.append("## Findings")
            for sev in ("critical", "high", "medium", "low", "info"):
                lst = by_sev.get(sev, [])
                if lst:
                    lines.append(f"\n### {sev.upper()} ({len(lst)})")
                    for f in lst:
                        lines.append(
                            f"- **{f['type']}**: {f.get('description', f.get('title', ''))[:200]}"
                        )
            lines.append("")

        if secrets:
            lines.append(f"## Secrets ({len(secrets)})")
            for s in secrets[:30]:
                lines.append(f"- [{s['confidence']}] {s['type']}: {s['value'][:80]}")
            if len(secrets) > 30:
                lines.append(f"- ... and {len(secrets) - 30} more")
            lines.append("")

        if endpoints:
            cats: dict[str, list] = {}
            for ep in endpoints:
                cats.setdefault(ep.get("category", "unknown"), []).append(ep)
            lines.append(f"## Endpoints ({len(endpoints)})")
            for cat in ("external", "internal", "cloud", "cdn", "third-party", "unknown"):
                lst = cats.get(cat, [])
                if lst:
                    lines.append(f"\n### {cat.upper()} ({len(lst)})")
                    for ep in lst[:20]:
                        lines.append(f"  - {ep.get('method', 'GET')} {ep['url']}")
                    if len(lst) > 20:
                        lines.append(f"  - ... and {len(lst) - 20} more")
            lines.append("")

        if subdomains:
            lines.append(f"## Subdomains ({len(subdomains)})")
            live = sum(1 for s in subdomains if s.get("resolved"))
            lines.append(f"  Live: {live} / Total: {len(subdomains)}")
            for sd in subdomains[:30]:
                status = "LIVE" if sd.get("resolved") else "?"
                lines.append(f"  [{status}] {sd['domain']} ({sd.get('source', '?')})")
            if len(subdomains) > 30:
                lines.append(f"  - ... and {len(subdomains) - 30} more")

        return "\n".join(lines)

    def export_json(self, target_id: int) -> str:
        return json.dumps({
            "target": self.get_target(target_id),
            "apks": self.list_apks(target_id),
            "findings": self.get_findings(target_id),
            "endpoints": self._fetchall("SELECT * FROM endpoints WHERE target_id=?", (target_id,)),
            "secrets": self._fetchall("SELECT * FROM secrets WHERE target_id=?", (target_id,)),
        }, indent=2, default=str)


def _fmt_size(b: int) -> str:
    if b > 10 * 1024 * 1024:
        return f"{b / 1024 / 1024:.0f} MB"
    if b > 1024:
        return f"{b / 1024:.0f} KB"
    return f"{b} B"
