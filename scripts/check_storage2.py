"""Check StorageManager data."""
import sys
sys.path.insert(0, 'D:\\AndroidPentest')
from tools.storage import StorageManager

s = StorageManager(r'D:\temp\workspace').init()

print('=== All Findings ===')
seen = set()
for f in s.get_findings():
    key = f['title'].strip().lower()
    if key in seen:
        print(f"  [DUPLICATE] [{f['severity']}] {f['title']}")
        continue
    seen.add(key)
    desc = (f['description'] or '')[:250]
    print(f"  [{f['severity']}] {f['title']}")
    if desc:
        print(f"    -> {desc}")

print()
print('=== Endpoints ===')
for e in s.get_endpoints():
    print(f"  {e['method']} {e['url']}")

print()
print('=== Stats ===')
s.print_stats()
