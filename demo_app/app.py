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

    # a fake grounded "LLM" answer that quotes retrieved chunks + their source
    answer = " ".join(h["text"] for h in hits) or "I don't have information on that."
    return {
        "tenant_id": req.tenant_id,
        "answer": answer,
        "citations": [{"doc_id": h["doc_id"], "tenant_id": h["tenant_id"]} for h in hits],
    }
