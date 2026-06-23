"""
Fetch real sha256 hashes from PyPI JSON API for given package==version specs.
Outputs a requirements.txt block with all distribution hashes (wheel + sdist).
Usage: python gen_hashes.py fastapi==0.111.0 uvicorn==0.29.0 ...
"""
import json
import sys
import urllib.request
import urllib.error

def get_hashes(package: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  ERROR fetching {package}=={version}: HTTP {e.code}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  ERROR fetching {package}=={version}: {e}", file=sys.stderr)
        return []

    urls = data.get("urls", [])
    hashes = []
    for u in urls:
        digests = u.get("digests", {})
        sha = digests.get("sha256")
        if sha:
            hashes.append(sha)
    return hashes

def main():
    specs = sys.argv[1:]
    if not specs:
        print("Usage: gen_hashes.py pkg==ver [pkg==ver ...]")
        sys.exit(1)

    for spec in specs:
        # strip extras like [standard]
        base = spec.split("[")[0]
        if "==" not in base:
            print(f"# SKIP (no version pin): {spec}", flush=True)
            continue
        # reconstruct: keep original spec for display but use stripped name for API
        name_part, ver = base.split("==", 1)
        package_name = name_part.strip()
        version = ver.strip()
        display_spec = spec.strip()

        print(f"# Fetching {package_name}=={version} ...", file=sys.stderr, flush=True)
        hashes = get_hashes(package_name, version)
        if not hashes:
            print(f"{display_spec} \\")
            print(f"    --hash=sha256:FETCH_FAILED_CHECK_MANUALLY")
        elif len(hashes) == 1:
            print(f"{display_spec} \\")
            print(f"    --hash=sha256:{hashes[0]}")
        else:
            lines = [f"{display_spec} \\"]
            for i, h in enumerate(hashes):
                if i < len(hashes) - 1:
                    lines.append(f"    --hash=sha256:{h} \\")
                else:
                    lines.append(f"    --hash=sha256:{h}")
            print("\n".join(lines))

if __name__ == "__main__":
    main()
