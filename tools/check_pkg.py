import json, urllib.request, sys

pkg = sys.argv[1]
ver = sys.argv[2] if len(sys.argv) > 2 else None

if ver:
    url = f"https://pypi.org/pypi/{pkg}/{ver}/json"
else:
    url = f"https://pypi.org/pypi/{pkg}/json"

try:
    with urllib.request.urlopen(url, timeout=15) as r:
        d = json.loads(r.read())
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

if ver:
    for u in d["urls"]:
        print(u["filename"], u["digests"]["sha256"])
else:
    print("Available versions:", list(d["releases"].keys()))
