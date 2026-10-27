#!/usr/bin/env python3
import csv
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "dataset"
OUTPUT_CSV = BASE_DIR / "output.csv"
DEMO_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Ghost Data Still Exists - Demo", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(DEMO_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(DEMO_DIR / "templates"))

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    rows = load_output()
    reqs = {r["case_id"]: r for r in load_requests()}
    # counts
    from collections import Counter
    c = Counter(r["deletion_status"] for r in rows)
    return templates.TemplateResponse("index.html", {"request": request, "rows": rows, "reqs": reqs, "counts": c, "has_key": bool(GEMINI_API_KEY)})


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
async def explain_case(case_id: str):
    if not GEMINI_API_KEY:
        raise HTTPException(400, "GEMINI_API_KEY not configured")
    rows = load_output()
    row = next((r for r in rows if r["case_id"] == case_id), None)
    reqs = {r["case_id"]: r for r in load_requests()}
    req = reqs.get(case_id)
    if not row:
        raise HTTPException(404, "Case not found")
    prompt = f"""You are an expert on deletion audits (GDPR/erasure). Explain this case clearly.

Case: {case_id}
Request: {json.dumps(req) if req else None}
Result: status={row['deletion_status']}, steps={json.dumps(row['_steps'], indent=2)}

Explain: why this status, key findings, risks, remediation plan, verification. Be concise and accurate.
"""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
                params={"key": GEMINI_API_KEY},
                json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"temperature": 0.2, "maxOutputTokens": 1024}},
            )
            data = resp.json()
            text = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            return JSONResponse({"explanation": text})
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/api/run-solver")
async def run_solver():
    try:
        solver = BASE_DIR / "code" / "solver.py"
        if not solver.exists():
            raise HTTPException(500, "solver.py not found")
        result = subprocess.run([sys.executable, str(solver)], cwd=str(BASE_DIR), capture_output=True, text=True, timeout=300)
        return JSONResponse({"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    except subprocess.TimeoutExpired:
        raise HTTPException(500, "Solver timed out")
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/stats")
async def stats():
    rows = load_output()
    from collections import Counter
    c = Counter(r["deletion_status"] for r in rows)
    return {"total": len(rows), "counts": dict(c)}
