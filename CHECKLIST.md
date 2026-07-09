# TenantProbe — Checklist

## Phase 1: Validation gate (prove the concept) ✅
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

## Phase 2: Make it a real tool
- [ ] Adapter layer: generic HTTP / OpenAI-compatible / Python callback
- [ ] YAML scenario files (tenants, docs, attacks, assertions)
- [ ] Reports: JSON + JUnit-XML + Markdown
- [ ] GitHub Action (spin up demo, run probe, fail on leak)
- [ ] Unit tests (pytest) + CI

## Phase 3: Depth (the differentiator)
- [ ] Real pgvector demo app with the intentional tenant-filter bug
- [ ] Detectors: fuzzy/embedding-similarity match, PII/regex, citation-tenant-mismatch (done), cache & agent-memory leakage
- [ ] Prompt-injection attack suite
- [ ] GDPR-style report template

## Phase 4: Launch
- [ ] Polished README (arch diagram, GIF)
- [ ] Blog post: "Your RAG app leaks across tenants — and your DB isolation won't catch it"
- [ ] Show HN + LinkedIn

**Complete?** [ ]
→ <promise>COMPLETE</promise>
