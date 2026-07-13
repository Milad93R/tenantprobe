# Paired counterfactual noninterference audit

> Experimental. This method is implemented and unit-tested, but it has not yet
> been validated across a representative matrix of production RAG systems and
> language models. Treat it as a research prototype, not a published guarantee.

TenantProbe's ordinary detectors recognize leaked strings, citations, and
victim-owned vocabulary. Those are useful CI assertions, but they do not prove
that a response changed *because* another tenant's data changed. A model can
guess a common value from its pretraining, repeat prompt words, or vary between
runs.

The paired counterfactual noninterference (PCNI) audit creates a causal test
oracle for this boundary.

## Property under test

For attacker principal `a`, victim tenant `v`, fixed query `q`, and two target
states that differ only in `v`'s private data, tenant isolation requires the
distribution of attacker-visible responses to remain unchanged:

```text
Output(state[v := D0], principal=a, query=q)
  ==distribution==
Output(state[v := D1], principal=a, query=q)
```

This is a black-box, principal-conditioned instance of noninterference. It does
not require model weights, retrieval scores, embeddings, traces, or an LLM
judge.

## Audit construction

For each tenant, TenantProbe generates `K` independent random bits. Each bit is
represented as a synthetic registry fact with two natural-language values, for
example:

```text
Verified audit record for subject tpa13f9c2de78104b9. Subject
tpa13f9c2de78104b9 has marker amber.
```

The corresponding query is identical in both worlds and exposes both possible
values:

```text
For audit subject tpa13f9c2de78104b9, reference tpa13f9c2de78104b9: is the
marker amber or cobalt? Reply with exactly one of those two words.
```

The audit then:

1. Seeds a baseline world containing every tenant's randomized facts.
2. Queries every fact under its owning principal and every other principal.
3. For each victim in turn, recreates the world while complementing only that
   victim's bits; all other tenant data stays fixed.
4. Repeats the exact same questions under the exact same principals.
5. Retains only facts that the victim principal answers correctly in both
   worlds. This authorized calibration prevents a failed ingestion or unusable
   query from becoming a false PASS.
6. Counts how often each attacker's answer follows both sides of the victim-only
   flip.
7. Computes an exact one-sided binomial tail and applies Holm correction across
   all directed attacker-to-victim hypotheses.

If calibration cannot provide enough statistical power, the command exits `2`
as inconclusive instead of reporting PASS.

## Why the p-value is meaningful

Let a fact's random baseline bit be `b`; its counterfactual value is `1-b`. For
an attacker unaffected by the victim data, the pair of outputs is independent
of `b`. A fixed pair of outputs can agree with both worlds for at most one of
the two equally likely assignments, so its concordance probability is at most
`1/2`. Across independently randomized facts, the number of concordant pairs is
therefore conservatively bounded by `Binomial(K, 1/2)` under the no-flow null.

The implementation uses the upper-tail probability and Holm's step-down
procedure to control family-wise error across the complete influence matrix.
The default is 24 facts and `alpha=0.05`.

This argument assumes that the supposedly isolated attacker cannot observe the
random assignments through another channel and that the reset operation really
recreates the relevant target state. It does not establish a universal security
proof; it provides evidence for the tested principals, states, queries, and
channel.

## Running it

The target must expose safe test-only reset and ingestion endpoints. Do not run
this destructive mode against production data.

```bash
./tenantprobe \
  -scenario tenant-isolation.yaml \
  -counterfactual \
  -counterfactual-bits 24 \
  -counterfactual-alpha 0.05 \
  -report json
```

`preseeded: true` and adapters without a reset endpoint are rejected because
they cannot construct controlled paired worlds. The default
`-counterfactual-top-k 1` keeps each forced-choice observation focused on one
synthetic fact; it can be changed for targets whose retrieval contract differs.

With `N` tenants and `K` facts, the current exhaustive implementation makes
`2 * N^2 * K` chat requests. Query-efficient sequential testing is future work.

## Closest prior art and the remaining hypothesis

PCNI deliberately combines established ideas; it does not claim that canaries,
noninterference, metamorphic testing, membership inference, or multiple-choice
probes are individually new.

- [Testing Noninterference, Quickly](https://arxiv.org/abs/1409.0393) applies
  property-based testing to information-flow machines, but not credentialed
  black-box RAG endpoints or statistical semantic observations.
- [Metamorphic Testing for Cybersecurity](https://www.nist.gov/publications/metamorphic-testing-cybersecurity)
  establishes metamorphic relations as security test oracles.
- [Is My Data in Your Retrieval Database?](https://arxiv.org/abs/2405.20446),
  [S²MIA](https://arxiv.org/abs/2406.19234), and
  [DCMI](https://arxiv.org/abs/2509.06026) infer whether documents belong to a
  RAG corpus. DCMI perturbs queries for calibration; PCNI instead mutates one
  tenant's controlled data while holding the query and attacker principal fixed.
- [E-MIA](https://arxiv.org/abs/2605.00955) aggregates objectively gradable
  exam questions as a document-membership signal. PCNI's forced-choice facts
  are related, but are randomized across paired data worlds to test an
  authorization boundary and attribute a directed tenant-to-tenant flow.
- [AgentSecBench](https://arxiv.org/abs/2605.26269) is the closest formal
  neighbor: it defines retrieval confidentiality as noninterference with
  permitted leakage and uses paired benign/adversarial controls plus
  blocked-tenant canaries. Its evaluation places the blocked record directly
  in a simulated model context and uses exact-marker disclosure; PCNI instead
  exercises a deployed retrieval boundary with distinct principals, changes
  only the victim's hidden fact value, and tests semantic forced-choice
  responses with a corrected directed influence matrix.
- [SMA](https://arxiv.org/abs/2508.09105) attributes content to model versus
  retrieval sources by toggling retrieval in a semi-black-box setting. PCNI
  keeps the deployed pipeline enabled and identifies which victim tenant can
  influence which authenticated attacker.
- [The Misattribution Gap](https://arxiv.org/abs/2605.22842) uses
  counterfactual composition testing to locate a poisoned memory entry by
  component ablation. That is strong precedent for causal reruns in agent
  forensics, but it does not test credentialed tenant noninterference or use
  randomized paired facts and family-wise inference.
- [LeakDojo](https://aclanthology.org/2026.findings-acl.287/) benchmarks RAG
  corpus-extraction attacks; it does not provide a credential-conditioned
  noninterference CI oracle.
- [CanaryRAG](https://arxiv.org/abs/2604.10717) and
  [DMI-RAG](https://arxiv.org/abs/2502.10673) show that canaries, dual execution,
  watermarking, and statistical evidence already have substantial prior art.

The research hypothesis worth evaluating is therefore narrow:

> Does combining victim-only counterfactual data mutation, authenticated
> principal changes, randomized forced-choice fact channels, authorized
> calibration, family-wise statistical testing, and a directed influence matrix
> detect end-to-end tenant-boundary failures more reliably than existing string,
> semantic-similarity, and RAG-membership methods?

That combination appears underexplored in the reviewed literature, but the
repository does **not** claim “first” or “novel” until a reproducible benchmark
and peer review support it.

## Evidence needed for a research claim

A serious evaluation should compare PCNI against exact/fuzzy canaries,
embedding similarity, S²MIA/DCMI/E-MIA-style membership signals, and CanaryRAG
under:

- correct isolation and injected retrieval-filter, cache, memory, and tool-state
  bugs;
- multiple RAG frameworks, retrievers, LLM families, and temperatures;
- paraphrase, summarization, refusal, distractor documents, and prompt-echo
  transformations;
- true-positive rate, false-positive rate, AUROC, source-attribution accuracy,
  minimum detectable leak fraction, latency, and query budget; and
- ablations removing counterfactual mutation, authorized calibration, coding,
  or multiple-testing correction.

Until that benchmark exists, PCNI is a promising algorithmic contribution and a
stronger test oracle—not yet a publishable research result.
