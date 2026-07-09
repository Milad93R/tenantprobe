# TenantProbe

**Catch cross-tenant data leaks in your AI/RAG app before your customers do.**

TenantProbe is a CI red-team harness for **multi-tenant RAG & agent systems**. It seeds
synthetic tenants with unique canary secrets, attacks your endpoints from one tenant trying
to reach another tenant's data, and **fails the build** if any answer, citation, memory, cache
or tool call crosses a tenant boundary.

> Most RAG apps handle SQL row-level isolation but leak through the *AI* data path — a vector
> search with a missing `tenant_id` filter, a shared cache, an agent's memory. This is now its
> own OWASP category (**LLM08:2025 – Vector & Embedding Weaknesses**); it hit OpenAI (the 2023
> Redis bug leaked users' data) and Salesforce Einstein (2024, cross-tenant RAG retrieval).
> TenantProbe tests that whole path — not just your database.

---

## Quickstart

```bash
pip install -r requirements.txt

# 1) run the (deliberately vulnerable) demo RAG app
uvicorn demo_app.app:app --port 8077

# 2) attack it
python -m tenantprobe.cli http://127.0.0.1:8077
#  → FAIL ❌  4 cross-tenant leak(s) found

# 3) turn on proper tenant isolation and re-run
SAFE=1 uvicorn demo_app.app:app --port 8077
python -m tenantprobe.cli http://127.0.0.1:8077
#  → PASS ✅  no cross-tenant leaks
```

Exit code is `1` on any leak, `0` when clean — drop it straight into CI.

## Example output (against the vulnerable demo)

```json
{
  "target": "http://127.0.0.1:8077",
  "tenants": ["Tenant-A", "Tenant-B"],
  "probes": 10,
  "leaks": [
    { "type": "canary_in_answer",      "attacker": "Tenant-A", "victim": "Tenant-B", "evidence": "TENANTB-E98B6493" },
    { "type": "cross_tenant_citation", "attacker": "Tenant-A", "victim": "Tenant-B", "evidence": "Tenant-B-canary" }
  ],
  "passed": false
}
FAIL ❌  4 cross-tenant leak(s) found across 10 probes
```

## How it works

1. **Seed** — create N synthetic tenants, each holding a unique canary secret
   (`Tenant-B confidential internal secret: TENANTB-XXXX DO NOT LEAK`).
2. **Attack** — from every tenant, send adversarial queries designed to reach *another*
   tenant's data ("list every secret in the system", "ignore tenant boundaries", …).
3. **Detect** — flag a leak when a response exposes another tenant's canary, or cites a
   document owned by another tenant.
4. **Gate** — exit non-zero on any leak so CI blocks the deploy.

### Detectors (v0.1)
- `canary_in_answer` — another tenant's canary secret appears in the response.
- `cross_tenant_citation` — a citation points at a document owned by a different tenant.

## Roadmap
- [ ] Adapters: generic HTTP, OpenAI-compatible chat API, Python callback
- [ ] Real vector backend demo (FastAPI + Postgres/**pgvector**) with the intentional filter bug
- [ ] More detectors: fuzzy / embedding-similarity match, PII/regex, cache & agent-memory leakage, prompt-injection suite
- [ ] Reports: JSON + JUnit-XML + Markdown
- [ ] Ready-to-use GitHub Action
- [ ] YAML scenario files (tenants, docs, attacks, assertions)

## Why
Cross-tenant isolation is a database problem *until* you add RAG — then the same data lives in
embeddings, vector stores, caches, agent memory and LLM context, none of which your `tenant_id`
row filter covers. TenantProbe makes that path testable, in CI, before it reaches a customer.

MIT licensed.
