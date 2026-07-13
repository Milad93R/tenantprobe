"""Credentialed multi-tenant pgvector demo with one intentional isolation bug.

SAFE=0 omits the tenant predicate from vector retrieval. SAFE=1 applies it.
JWT claims, request tenant IDs, document ownership, and citations are all kept
separate so TenantProbe exercises an actual authorization boundary.
"""

from contextlib import asynccontextmanager
import hashlib
import math
import os
import re

from fastapi import Depends, FastAPI, Header, HTTPException, Response
import jwt
from pydantic import BaseModel
import psycopg


DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ.get("DEMO_JWT_SECRET", "tenantprobe-local-demo-secret-at-least-32-bytes")
ADMIN_TOKEN = os.environ.get("TEST_ADMIN_TOKEN", "tenantprobe-local-admin")
SAFE = os.environ.get("SAFE", "0") == "1"
DIMENSIONS = 32


def embedding(text: str) -> list[float]:
    """Stable local bag-of-words embedding; storage/search are real pgvector."""
    values = [0.0] * DIMENSIONS
    for token in re.findall(r"[a-z0-9]+", text.lower()):
        digest = hashlib.sha256(token.encode()).digest()
        index = int.from_bytes(digest[:2], "big") % DIMENSIONS
        values[index] += 1.0 if digest[2] & 1 else -1.0
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [value / norm for value in values]


def vector_literal(values: list[float]) -> str:
    return "[" + ",".join(f"{value:.8f}" for value in values) + "]"


def connection():
    return psycopg.connect(DATABASE_URL)


@asynccontextmanager
async def lifespan(_: FastAPI):
    with connection() as conn, conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS documents (
                tenant_id text NOT NULL,
                doc_id text NOT NULL,
                text text NOT NULL,
                embedding vector({DIMENSIONS}) NOT NULL,
                PRIMARY KEY (tenant_id, doc_id)
            )
            """
        )
        conn.commit()
    yield


app = FastAPI(title="TenantProbe pgvector integration target", lifespan=lifespan)


class DocumentIn(BaseModel):
    tenant_id: str
    doc_id: str
    text: str


class QueryIn(BaseModel):
    tenant_id: str
    query: str
    top_k: int = 3


def authenticated_org(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    try:
        claims = jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="invalid token") from exc
    org_id = claims.get("org_id")
    if not isinstance(org_id, str) or not org_id:
        raise HTTPException(status_code=401, detail="org_id claim required")
    return org_id


def require_same_tenant(request_tenant: str, authenticated_tenant: str) -> None:
    if request_tenant != authenticated_tenant:
        raise HTTPException(status_code=403, detail="tenant mismatch")


@app.get("/health")
def health():
    return {"ok": True, "safe": SAFE, "store": "pgvector"}


@app.post("/test/reset", status_code=204)
def reset(x_test_admin: str = Header(...)):
    if x_test_admin != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="test admin token required")
    with connection() as conn, conn.cursor() as cur:
        cur.execute("TRUNCATE documents")
        conn.commit()
    return Response(status_code=204)


@app.post("/test/documents", status_code=201)
def seed(item: DocumentIn, org_id: str = Depends(authenticated_org)):
    require_same_tenant(item.tenant_id, org_id)
    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO documents (tenant_id, doc_id, text, embedding)
            VALUES (%s, %s, %s, %s::vector)
            ON CONFLICT (tenant_id, doc_id)
            DO UPDATE SET text = EXCLUDED.text, embedding = EXCLUDED.embedding
            """,
            (item.tenant_id, item.doc_id, item.text, vector_literal(embedding(item.text))),
        )
        conn.commit()
    return {"ok": True}


@app.post("/v1/query")
def query(item: QueryIn, org_id: str = Depends(authenticated_org)):
    require_same_tenant(item.tenant_id, org_id)
    query_vector = vector_literal(embedding(item.query))
    limit = max(1, min(item.top_k, 10))

    with connection() as conn, conn.cursor() as cur:
        if SAFE:
            cur.execute(
                """
                SELECT tenant_id, doc_id, text, 1 - (embedding <=> %s::vector) AS score
                FROM documents
                WHERE tenant_id = %s
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (query_vector, org_id, query_vector, limit),
            )
        else:
            # Intentional bug: similarity search has no tenant predicate.
            cur.execute(
                """
                SELECT tenant_id, doc_id, text, 1 - (embedding <=> %s::vector) AS score
                FROM documents
                ORDER BY embedding <=> %s::vector
                LIMIT %s
                """,
                (query_vector, query_vector, limit),
            )
        rows = cur.fetchall()

    # Keep this demo deterministic: return retrieved chunks and their real owner.
    return {
        "answer": " ".join(row[2] for row in rows),
        "citations": [
            {"doc_id": row[1], "tenant_id": row[0], "score": float(row[3])}
            for row in rows
        ],
    }
