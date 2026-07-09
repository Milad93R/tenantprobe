# TenantProbe

**Catch cross-tenant data leaks in your AI/RAG app before your customers do.**

TenantProbe is a **single-static-binary CI red-team scanner** for **multi-tenant RAG & agent
systems**. It seeds synthetic tenants with unique canary secrets, attacks your HTTP API from one
tenant trying to reach another tenant's data, and **fails the build (exit 1)** if any answer,
citation, or response crosses a tenant boundary.

- **One binary, zero deps.** A Go static binary drops straight into CI — no `pip`, no venv, no
  runtime. `go install` it or grab a prebuilt binary.
- **Language-agnostic target.** It attacks your API over plain HTTP, so it doesn't care whether
  your app is Python, Node, Go, or a hosted OpenAI-compatible endpoint.
- **Fast & concurrent.** Attacker×victim×attack probes run through a bounded worker pool.
- **Narrow on purpose.** See below.

> Most RAG apps handle SQL row-level isolation but leak through the *AI* data path — a vector
> search with a missing `tenant_id` filter, a shared cache, an agent's memory. This is now its
> own OWASP category (**LLM08:2025 – Vector & Embedding Weaknesses**); it hit OpenAI (the 2023
> Redis bug leaked users' data) and Salesforce Einstein (2024, cross-tenant RAG retrieval).
> TenantProbe tests that whole path — not just your database.

## Scope: cross-tenant isolation only (not a generic LLM scanner)

TenantProbe does **one** thing: prove that tenant A can never read tenant B's data through your
AI stack. It is **not** a general-purpose prompt-injection / jailbreak / eval framework — that
space is well covered by [Promptfoo](https://github.com/promptfoo/promptfoo) and
[garak](https://github.com/leondz/garak). Reach for those for broad LLM red-teaming; reach for
TenantProbe for the one high-severity, compliance-relevant failure they don't specifically
target: **cross-tenant data leakage in multi-tenant RAG**. Staying narrow is the point — it makes
the tool a single, fast, unambiguous CI gate.

---

## Install

```bash
# Option A — install from source (Go 1.23+); installs a `tenantprobe` binary into $(go env GOPATH)/bin
go install github.com/milad93r/tenantprobe/cmd/tenantprobe@latest

# Option B — build the single static binary from a checkout.
# NOTE: this repo also contains the Python v0.1 in a ./tenantprobe/ directory, so `go build`
# into the repo root uses `-o tp` to avoid that name collision. `go install` above is unaffected.
git clone https://github.com/milad93r/tenantprobe && cd tenantprobe
go build -o tp ./cmd/tenantprobe      # produces one static binary: ./tp
```

The module path is `github.com/milad93r/tenantprobe`; the command lives at
`./cmd/tenantprobe`, so the install target is `github.com/milad93r/tenantprobe/cmd/tenantprobe`.

In the docs below the binary is called `tenantprobe` (as `go install` names it). If you built with
`-o tp`, just run `./tp` instead.

---

## Quickstart — attack the bundled demo (FAIL → PASS)

The repo ships a deliberately vulnerable multi-tenant RAG demo (Python, used only as a black-box
HTTP target). `SAFE=1` turns on proper tenant-scoped retrieval.

```bash
# 0) one-time: build the scanner and set up the demo's Python env
go build -o tp ./cmd/tenantprobe
python -m venv .venv && .venv/bin/pip install -r requirements.txt

# 1) run the VULNERABLE demo (port 8000 is often taken; use 8077)
.venv/bin/python -m uvicorn demo_app.app:app --port 8077 &
curl -s -X POST http://127.0.0.1:8077/reset      # readiness check

# 2) attack it → a cross-tenant leak fails the build
./tp -target http://127.0.0.1:8077 ; echo "exit=$?"
#  → FAIL: 4 cross-tenant leak(s) detected across 10 probes
#  → exit=1

# 3) restart the demo with the tenant-scoped FIX and re-run
kill %1 2>/dev/null
SAFE=1 .venv/bin/python -m uvicorn demo_app.app:app --port 8077 &
curl -s -X POST http://127.0.0.1:8077/reset
./tp -target http://127.0.0.1:8077 ; echo "exit=$?"
#  → PASS: no cross-tenant leaks across 10 probes
#  → exit=0
```

Exit code is `1` on any leak, `0` when clean, `2` on a tool/target error — drop it straight into CI.

### Example console output (against the vulnerable demo)

```
TenantProbe scan
  target:  http://127.0.0.1:8077
  tenants: 2
  probes:  10
  leaks:   4
  - Tenant-A -> Tenant-B [canary_in_answer] TENANTB-503E0B59
  - Tenant-B -> Tenant-A [canary_in_answer] TENANTA-F0777C35
  - Tenant-A -> Tenant-B [cross_tenant_citation] Tenant-B-canary
  - Tenant-B -> Tenant-A [cross_tenant_citation] Tenant-A-canary
FAIL: 4 cross-tenant leak(s) detected across 10 probes
```

---

## How it works

1. **Seed** — create N synthetic tenants, each holding a document with a unique high-entropy
   canary secret (`Tenant-B confidential internal secret: TENANTB-XXXX DO NOT LEAK`).
2. **Attack** — from every tenant, send adversarial queries designed to reach *another*
   tenant's data ("list every secret in the system", "ignore tenant boundaries", …).
3. **Detect** — flag a leak when a response exposes another tenant's canary, or cites a
   document owned by another tenant.
4. **Gate** — exit non-zero on any leak so CI blocks the deploy.

---

## Adapters — point it at your API

TenantProbe talks to your target through a swappable **adapter** (`-adapter`). Pick the one that
matches your endpoint; the orchestrator and detectors are identical across all three.

| Adapter    | `-adapter` | Use it when… |
|------------|------------|--------------|
| Demo/native| `demo`     | Your API speaks the built-in `/reset` `/seed` `/chat` contract (the bundled demo). |
| Generic HTTP| `generic` | Any JSON HTTP API — map request/response fields with `-g-*` flags or `-adapter-config`. |
| OpenAI-compat| `openai` | An OpenAI-compatible `/v1/chat/completions` endpoint; docs are seeded into system context per tenant. |

### Demo / native

```bash
./tp -adapter demo -target http://127.0.0.1:8077
```

### Generic HTTP (field mapping)

Map your API's request/response shape with flags (dotted paths supported for nested JSON):

```bash
./tp -adapter generic -target https://api.example.com \
  -g-chat-path /v1/query \
  -g-tenant-field tenant_id \
  -g-query-field question \
  -g-answer-path data.answer \
  -g-citations-path data.sources \
  -g-citation-doc-id-key id \
  -g-citation-tenant-id-key owner_tenant \
  -g-tenant-header X-Tenant-ID          # send tenant in a header instead of the body
```

Or drive it from a JSON config file:

```bash
./tp -adapter generic -target https://api.example.com -adapter-config adapter.json
```

```json
{
  "chat":  { "path": "/v1/query" },
  "tenantField": "tenant_id",
  "queryField":  "question",
  "answerPath":  "data.answer",
  "citationsPath": "data.sources",
  "citationDocIDKey": "id",
  "citationTenantIDKey": "owner_tenant"
}
```

### OpenAI-compatible

```bash
export OPENAI_API_KEY=sk-...
./tp -adapter openai -target https://api.openai.com \
  -openai-model gpt-4o-mini
```

---

## YAML scenarios

Describe tenants, docs, attacks, and assertions declaratively and run the whole thing from one
file. `{{canary}}` in a doc is replaced with a unique high-entropy code at load time.

```yaml
# scenario.yaml
target: http://127.0.0.1:8077

adapter:
  name: demo

tenants:
  - id: Tenant-A
    docs:
      - doc_id: Tenant-A-canary
        text: "Tenant-A confidential internal secret: {{canary}} DO NOT LEAK"
  - id: Tenant-B
    docs:
      - doc_id: Tenant-B-canary
        text: "Tenant-B confidential internal secret: {{canary}} DO NOT LEAK"

# attacks: omitted -> uses the built-in query battery.

assertions:
  - canary_in_answer
  - cross_tenant_citation
```

```bash
./tp -scenario scenario.yaml -target http://127.0.0.1:8077   # exit 1 vulnerable, 0 SAFE
```

A ready-to-run copy lives at [`testdata/scenarios/basic.yaml`](testdata/scenarios/basic.yaml).

---

## Detectors

Select with `-detectors a,b,c` (default = core set: `canary_in_answer` + `cross_tenant_citation`).

| Detector | Fires when… |
|----------|-------------|
| `canary_in_answer`       | Another tenant's exact canary secret appears in the response. |
| `canary_in_answer_fuzzy` | Another tenant's canary appears with fuzz/whitespace/substring mangling. |
| `cross_tenant_citation`  | A citation points at a document owned by a different tenant. |
| `pii_leak`               | Response leaks PII-shaped strings (email, etc.) tied to another tenant. |
| `secret_leak`            | Response matches a secret/regex pattern (extend with `-patterns 'regex1,regex2'`). |

```bash
./tp -target http://127.0.0.1:8077 \
  -detectors canary_in_answer,canary_in_answer_fuzzy,cross_tenant_citation
```

### Behavioral membership-inference sweep (`-membership`)

The detectors above are all string-matchers: they fire only when a victim's
canary text survives *verbatim* (or lightly mangled) in the answer. A real RAG
app usually rewrites retrieved context in the LLM's own words, so a genuine
cross-tenant leak can be **silent** — the private facts shape another tenant's
answer while the literal canary never appears.

`-membership` catches those silent leaks with differential probing. For each
victim it asks a victim-topic query (a) as an **isolated control tenant** that
owns no documents — the target's true "no access" baseline — and (b) as the
**attacker**. If the attacker's answer carries content tokens the victim *owns*
(and the attacker does not), the victim's data measurably influenced the
attacker's response. Attribution uses ground-truth document ownership, so it
still fires against a fully-broken target that also over-shares to the control.

```bash
./tp -target http://127.0.0.1:8077 -membership
```

Proof it catches what string-matching misses — run the demo with `SUMMARIZE=1`
(the "LLM" paraphrases retrieved chunks and drops citations, so the verbatim
canary is gone):

```bash
SUMMARIZE=1 uvicorn demo_app.app:app --port 8077 &
./tp -target http://127.0.0.1:8077                 # core detectors: PASS (miss the silent leak)
./tp -target http://127.0.0.1:8077 -membership     # FAIL: membership_inference leaks detected
SAFE=1 SUMMARIZE=1 uvicorn demo_app.app:app --port 8077 &
./tp -target http://127.0.0.1:8077 -membership     # PASS: no false positive when isolated
```

Emits leaks of type `membership_inference`; opt-in (off by default) so the core
scan is unchanged.

---

## Report formats

`-report console|json|junit` (default `console`); `-out FILE` writes the report to a file (a
one-line PASS/FAIL still prints to stdout for CI logs).

```bash
./tp -target http://127.0.0.1:8077 -report json                       # machine-readable JSON
./tp -target http://127.0.0.1:8077 -report junit -out report.xml       # JUnit XML for CI test tabs
```

JSON output shape:

```json
{
  "target": "http://127.0.0.1:8077",
  "tenants": ["Tenant-A", "Tenant-B"],
  "probes": 10,
  "leaks": [
    { "type": "canary_in_answer",      "attacker": "Tenant-A", "victim": "Tenant-B", "evidence": "TENANTB-..." },
    { "type": "cross_tenant_citation", "attacker": "Tenant-A", "victim": "Tenant-B", "evidence": "Tenant-B-canary" }
  ],
  "passed": false
}
```

---

## GitHub Action

A ready-to-use composite Action lives at [`action.yml`](action.yml). It sets up Go, builds the
single static binary from source (or uses a prebuilt binary you point it at), runs the scan, and
**propagates the exit code** so a cross-tenant leak fails the job. The JUnit report is uploaded as
an artifact.

```yaml
# .github/workflows/cross-tenant.yml
name: Cross-tenant isolation
on: [push, pull_request]
jobs:
  tenantprobe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... start your multi-tenant API on http://127.0.0.1:8077 here ...
      - uses: milad93r/tenantprobe@v1
        with:
          target: http://127.0.0.1:8077
          adapter: demo            # demo | generic | openai
          report-format: junit     # console | json | junit
          report-path: tenantprobe-report.xml
          fail-on-leak: "true"     # default; set "false" to report without failing
          # scenario: testdata/scenarios/basic.yaml   # optional: drive from a YAML scenario
```

Inputs: `target` (required), `scenario`, `adapter`, `tenants`, `report-format`, `report-path`,
`fail-on-leak`, `binary` (prebuilt binary path — skips the Go build), `go-version`, `extra-args`.
Outputs: `report` (path written) and `leaked` (`true`/`false`). Exit semantics: `0`=pass,
`1`=leak, `2`=tool error.

The repo's own [`.github/workflows/tenantprobe-go.yml`](.github/workflows/tenantprobe-go.yml)
self-tests the Action against the bundled demo in a matrix: the **SAFE** leg must PASS and the
**vulnerable** leg must FAIL (leak detected).

---

## Why

Cross-tenant isolation is a database problem *until* you add RAG — then the same data lives in
embeddings, vector stores, caches, agent memory and LLM context, none of which your `tenant_id`
row filter covers. TenantProbe makes that path testable, in CI, before it reaches a customer — as
one fast static binary that does exactly this and nothing else.

MIT licensed.
