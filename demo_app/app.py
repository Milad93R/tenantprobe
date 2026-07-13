# demo_app/app.py — a deliberately VULNERABLE multi-tenant RAG API (and its one-line fix).
#
# This is the target TenantProbe attacks. By default retrieval searches EVERY tenant's
# documents (the classic RAG isolation bug). Set SAFE=1 to enable proper tenant scoping
# and watch TenantProbe go from FAIL -> PASS.
#
#   uvicorn demo_app.app:app            # vulnerable
#   SAFE=1 uvicorn demo_app.app:app     # fixed
import os
import re
from fastapi import FastAPI
from pydantic import BaseModel

SAFE = os.environ.get("SAFE", "0") == "1"
# SUMMARIZE=1 makes /chat return a paraphrased summary of the retrieved chunks
# instead of quoting them verbatim, and drops citations. This models a real RAG
# app whose LLM rewrites retrieved context in its own words: the leak becomes
# SILENT — the verbatim canary code never appears, so the string-matching
# detectors (canary_in_answer, cross_tenant_citation) go quiet. The behavioral
# content-influence sweep still catches it because tenant-specific vocabulary
# remains in another tenant's answer.
SUMMARIZE = os.environ.get("SUMMARIZE", "0") == "1"
app = FastAPI(title="TenantProbe demo — multi-tenant RAG")

# in-memory "vector store": each entry = {tenant_id, doc_id, text}
STORE: list[dict] = []


def _bag(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _score(query: str, doc: str) -> float:
    q, d = _bag(query), _bag(doc)
    if not q or not d:
        return 0.0
    return len(q & d) / len(q | d)  # Jaccard — enough to demo retrieval + the leak


class SeedItem(BaseModel):
    tenant_id: str
    doc_id: str
    text: str


class ChatReq(BaseModel):
    tenant_id: str
    query: str
    top_k: int = 3


@app.post("/seed")
def seed(item: SeedItem):
    STORE.append(item.model_dump())
    return {"ok": True, "count": len(STORE)}


@app.post("/reset")
def reset():
    STORE.clear()
    return {"ok": True}


@app.post("/chat")
def chat(req: ChatReq):
    # --- retrieval ---
    if SAFE:
        pool = [d for d in STORE if d["tenant_id"] == req.tenant_id]  # ✅ tenant-scoped
    else:
        pool = STORE                                                  # 🐞 BUG: all tenants
    ranked = sorted(pool, key=lambda d: _score(req.query, d["text"]), reverse=True)
    hits = [d for d in ranked if _score(req.query, d["text"]) > 0][: req.top_k]

    if not hits:
        return {"tenant_id": req.tenant_id, "answer": "I don't have information on that.", "citations": []}

    if SUMMARIZE:
        # Paraphrase: rewrite retrieved chunks in the "LLM's" own words and drop
        # citations. The verbatim canary CODE is redacted, so canary_in_answer /
        # cross_tenant_citation see nothing — but the victim's distinctive
        # project vocabulary still bleeds into the summary, which the behavioral
        # content-influence sweep detects.
        topics = []
        for h in hits:
            # keep tenant-distinctive content tokens, redact the high-entropy code
            words = re.findall(r"[a-zA-Z0-9]+", h["text"])
            kept = [w for w in words if not re.fullmatch(r"[0-9A-F]{8}", w)]
            topics.append(" ".join(kept))
        answer = "Based on the available records, the relevant material covers: " + "; ".join(topics) + "."
        return {"tenant_id": req.tenant_id, "answer": answer, "citations": []}

    # a fake grounded "LLM" answer that quotes retrieved chunks + their source
    answer = " ".join(h["text"] for h in hits)
    return {
        "tenant_id": req.tenant_id,
        "answer": answer,
        "citations": [{"doc_id": h["doc_id"], "tenant_id": h["tenant_id"]} for h in hits],
    }
