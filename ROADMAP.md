# TenantProbe roadmap

## Shipped in the pre-v1 branch

- [x] Go CLI with bounded concurrency and stable exit codes.
- [x] Exact/fuzzy canary and cross-tenant citation detectors.
- [x] Victim-attributed PII and secret-pattern detectors.
- [x] Generic JSON HTTP mapping with nested request/response paths.
- [x] Per-tenant credentials sourced from environment variables.
- [x] Explicit ingestion and preseeded-fixture lifecycle modes.
- [x] YAML scenarios with strict field validation.
- [x] Console, JSON, and JUnit reports.
- [x] Composite GitHub Action and vulnerable/fixed self-test.
- [x] Deterministic victim-content influence heuristic.
- [x] PostgreSQL/pgvector Docker Compose demo with independent JWT principals.
- [x] End-to-end vulnerable/fixed acceptance script for that demo.
- [x] Threat model and documented authorization assumptions.
- [x] `SECURITY.md` and contribution guide.

## Required for v1

- [ ] CI green on the public repository.
- [x] GoReleaser workflow with checksums and Linux/macOS/Windows binaries.
- [ ] Tagged `v1.0.0` release and maintained `v1` Action tag.

## Later depth

- [ ] Cache-isolation sequences: victim warm-up → attacker query.
- [ ] Conversation/session-memory isolation sequences.
- [ ] Agent tool-call and credential provenance.
- [ ] Optional semantic influence detector with repeated controls, calibrated
      thresholds, and a published false-positive/false-negative benchmark.
- [ ] Compliance-oriented evidence report after the technical controls are real.
