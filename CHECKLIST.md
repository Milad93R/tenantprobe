# TenantProbe — Checklist

## Phase 1: Validation gate (prove the concept, Python v0.1) ✅
- [x] Scaffold repo + Python project
- [x] Vulnerable multi-tenant RAG demo app (SAFE=1 toggles the fix)
- [x] Probe core: seed canary tenants → attack → detect
- [x] Detectors: canary_in_answer, cross_tenant_citation
- [x] CLI with CI exit codes
- [x] Test: vulnerable → FAIL (4 leaks), fixed → PASS (0 leaks)
- [x] README + example output

**Phase 1 Complete?** [x]
→ <promise>VALIDATION_GATE_PASSED</promise>

---

## Phase 2: Go single-binary rewrite (the shippable tool) ✅

The Python v0.1 stays as the black-box demo *target*. The scanner itself is
rewritten in Go: one static binary, zero third-party deps in the core (only
`gopkg.in/yaml.v3` for scenarios). Module `github.com/milad93r/tenantprobe`.

- [x] F1 — Go core port: canary tenants, HTTP attacker, 2 detectors, CI-exit CLI
- [x] F2 — Generic HTTP adapter (dotted-path field mapping, header/body tenant)
- [x] F3 — OpenAI-compatible chat adapter (per-tenant context seeding)
- [x] F4 — YAML scenario files (tenants / docs / attacks / assertions)
- [x] F5 — Detectors: fuzzy/substring canary + cross-tenant PII/secret regex
- [x] F6 — Reports: console / JSON / JUnit-XML via `-report` / `-out`
- [x] F7 — Composite GitHub Action + self-test workflow (SAFE passes, vulnerable fails)
- [x] F8 — README/docs refresh for the Go single-binary tool
- [x] Test: `go build ./...` + `go vet ./...` clean; unit tests pass
- [x] Test: Go binary vs demo — vulnerable → exit 1, SAFE → exit 0

**Phase 2 Complete?** [x]
→ <promise>GO_TOOL_READY</promise>

---

## Phase 3: Depth (the differentiator)
- [ ] Real pgvector demo app with the intentional tenant-filter bug
- [ ] Detectors: embedding-similarity match, cache & agent-memory leakage
- [ ] Prompt-injection attack suite (still scoped to cross-tenant, not generic)
- [ ] GDPR-style report template

## Phase 4: Launch
- [ ] Prebuilt release binaries (GoReleaser) + published Action tag `@v1`
- [ ] Blog post: "Your RAG app leaks across tenants — and your DB isolation won't catch it"
- [ ] Show HN + LinkedIn

**Complete?** [ ]
→ <promise>COMPLETE</promise>
