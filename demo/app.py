#!/usr/bin/env python3
import csv
import json
import os
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "dataset"
OUTPUT_CSV = BASE_DIR / "output.csv"
DEMO_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Ghost Data Still Exists - Demo", version="1.0.0")
templates = Jinja2Templates(directory=str(DEMO_DIR / "templates"))

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
EXPLAIN_LIMIT = int(os.environ.get("DEMO_EXPLAIN_LIMIT", "20"))
EXPLAIN_WINDOW = int(os.environ.get("DEMO_EXPLAIN_WINDOW_SECONDS", "3600"))

EXPLANATION_CACHE: dict[str, str] = {}
_EXPLAIN_HITS: dict[str, deque] = defaultdict(deque)


def load_output():
    if not OUTPUT_CSV.exists():
        return []
    rows = []
    with open(OUTPUT_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                r["_steps"] = json.loads(r["steps_json"]) if r.get("steps_json") else []
            except Exception:
                r["_steps"] = []
            rows.append(r)
    return rows


def load_requests():
    path = DATA_DIR / "deletion_requests.csv"
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


@app.get("/healthz")
async def healthz():
    return {"ok": True, "cases": len(load_output())}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return (forwarded.split(",")[0].strip() if forwarded else request.client.host) or "unknown"


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    hits = _EXPLAIN_HITS[ip]
    while hits and now - hits[0] > EXPLAIN_WINDOW:
        hits.popleft()
    if len(hits) >= EXPLAIN_LIMIT:
        return True
    hits.append(now)
    return False


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, q: str = "", status: str = ""):
    rows = load_output()
    reqs = {r["case_id"]: r for r in load_requests()}
    counts = Counter(r["deletion_status"] for r in rows)
    needle = q.strip().lower()
    if needle:
        rows = [
            r for r in rows
            if needle in r["case_id"].lower()
            or needle in str(reqs.get(r["case_id"], {}).get("email", "")).lower()
        ]
    if status in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
        rows = [r for r in rows if r["deletion_status"] == status]
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "rows": rows,
            "reqs": reqs,
            "counts": counts,
            "has_key": bool(GEMINI_API_KEY),
            "q": q,
            "status": status,
        },
    )


@app.get("/case/{case_id}", response_class=HTMLResponse)
async def case_detail(request: Request, case_id: str):
    rows = load_output()
    row = next((r for r in rows if r["case_id"] == case_id), None)
    if not row:
        raise HTTPException(404, "Case not found")
    reqs = {r["case_id"]: r for r in load_requests()}
    req = reqs.get(case_id)
    return templates.TemplateResponse("case.html", {"request": request, "row": row, "req": req, "has_key": bool(GEMINI_API_KEY)})


@app.post("/api/explain/{case_id}")
async def explain_case(case_id: str, request: Request):
    if not GEMINI_API_KEY:
        raise HTTPException(400, "GEMINI_API_KEY not configured")
    rows = load_output()
    row = next((r for r in rows if r["case_id"] == case_id), None)
    reqs = {r["case_id"]: r for r in load_requests()}
    req = reqs.get(case_id)
    if not row:
        raise HTTPException(404, "Case not found")
    if row["deletion_status"] != "NOT_APPLICABLE" and not row["_steps"]:
        raise HTTPException(422, "Case has no steps to explain")
    if case_id in EXPLANATION_CACHE:
        return JSONResponse({"explanation": EXPLANATION_CACHE[case_id], "cached": True})
    if _rate_limited(_client_ip(request)):
        raise HTTPException(429, "Explanation limit reached, try again later")
    prompt = f"""You are an expert on deletion audits (GDPR/erasure). Explain this case clearly.

Case: {case_id}
Request: {json.dumps(req) if req else None}
Result: status={row['deletion_status']}, steps={json.dumps(row['_steps'], indent=2)}

Explain: why this status, key findings, risks, remediation plan, verification. Be concise and accurate.
"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent",
                params={"key": GEMINI_API_KEY},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1200},
                },
            )
        if resp.status_code >= 400:
            raise HTTPException(502, f"Gemini request failed ({resp.status_code})")
        data = resp.json()
        text = (
            data.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
            .strip()
        )
        if not text:
            raise HTTPException(502, "Gemini returned an empty explanation")
        EXPLANATION_CACHE[case_id] = text
        return JSONResponse({"explanation": text, "cached": False})
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Gemini request failed")


@app.get("/api/stats")
async def stats():
    rows = load_output()
    return {"total": len(rows), "counts": dict(Counter(r["deletion_status"] for r in rows))}
