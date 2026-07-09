# tenantprobe/cli.py — run TenantProbe against a target and exit non-zero on any leak.
#   python -m tenantprobe.cli [BASE_URL]
import sys
import json
from tenantprobe.core import run


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    res = run(base)
    print(json.dumps(res, indent=2))
    leaks = res["leaks"]
    if leaks:
        print(f"\nFAIL ❌  {len(leaks)} cross-tenant leak(s) found across {res['probes']} probes")
    else:
        print(f"\nPASS ✅  no cross-tenant leaks across {res['probes']} probes")
    sys.exit(1 if leaks else 0)


if __name__ == "__main__":
    main()
