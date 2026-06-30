"""Check StorageManager data."""
import sys
sys.path.insert(0, 'D:\\AndroidPentest')
from tools.storage import StorageManager

s = StorageManager(r'D:\temp\workspace').init()

print('=== Findings ===')
for f in s.get_findings():
    print(f"  [{f['severity']}] {f['title']} ({f['type']})")
    print(f"    {f['description'][:200]}")

print()
print('=== Endpoints ===')
for e in s.get_endpoints():
    print(f"  {e['method']} {e['url']}")

print()
print('=== Summary ===')
print(s.get_all_summary())
