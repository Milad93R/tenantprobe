# Threat model

## Security property

For every configured authenticated principal `A`, content owned exclusively by
principal `B` must not influence `A`'s answer or citations.

TenantProbe treats scenario tenant IDs as logical identities. A generic adapter
may map them to target-side organization UUIDs, but detector output is mapped
back to the logical identity so an owner's own citation is not misclassified.

## Attacker

The current attacker is an authenticated, unprivileged tenant who can send
queries through the same API as a normal customer. The attacker may use explicit
cross-boundary prompts but does not possess another tenant's credential.

## Trusted inputs

- The operator owns or is explicitly authorized to test the target.
- Per-tenant test credentials represent genuinely distinct authorization
  contexts.
- Seeded or preseeded fixture ownership in the scenario is ground truth.
- A target's citation owner field is meaningful when citation detection is used.

## Covered failure modes

- A vector/retrieval query omits or misapplies its tenant predicate.
- Retrieved text from one tenant appears in another tenant's answer.
- A response citation identifies another tenant's document.
- Seeded PII/secret-shaped values cross the response boundary.
- A summary drops the literal canary but preserves enough victim-owned
  vocabulary for deterministic provenance detection.

## Not covered yet

- Complete semantic paraphrases with no shared vocabulary.
- Cache keys, conversation memory, or state shared across multi-turn sessions.
- Agent tool-call authorization and side effects.
- Object-level authorization attacks that require guessing arbitrary resource
  identifiers rather than retrieving seeded content.
- Timing, embedding inversion, training-data extraction, or statistical privacy.
- Correctness of the target's claimed citation ownership.

## Operational safety

- Prefer a disposable staging environment and synthetic documents.
- `reset` and `seed` endpoints are opt-in; TenantProbe never guesses them.
- Use `preseeded: true` if ingestion is managed outside the scan.
- Keep credentials in environment variables via `headers_from_env`.
- Missing tenant credentials fail closed with exit code `2`.
- Do not point a scenario with destructive test endpoints at production.
