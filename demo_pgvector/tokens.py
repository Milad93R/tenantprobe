"""Print shell exports for the two deliberately non-secret demo JWTs."""

import os
import shlex

import jwt


SECRET = os.environ.get("DEMO_JWT_SECRET", "tenantprobe-local-demo-secret-at-least-32-bytes")


def bearer(org_id: str) -> str:
    token = jwt.encode({"sub": f"tester-{org_id}", "org_id": org_id}, SECRET, algorithm="HS256")
    return f"Bearer {token}"


for name, org_id in (("TP_ACME_AUTH", "org-a"), ("TP_GLOBEX_AUTH", "org-b")):
    print(f"export {name}={shlex.quote(bearer(org_id))}")
print("export TP_DEMO_ADMIN=tenantprobe-local-admin")
