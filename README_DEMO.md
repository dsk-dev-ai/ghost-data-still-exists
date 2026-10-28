# Ghost Data Still Exists - Demo App

A web demo to visualize the deletion audit results with optional Gemini AI explanations.

**Live demo:** https://ghost-data-still-exists-demo.onrender.com — Gemini explanations are enabled.

## Deploy to Render

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/dsk-dev-ai/ghost-data-still-exists)

1. Open the Render blueprint link above (or create a Web Service from the repo)
2. Render reads [`render.yaml`](./render.yaml) automatically
3. Set `GEMINI_API_KEY` when prompted (get one from [Google AI Studio](https://aistudio.google.com/apikey))
4. Apply the blueprint

Do not commit the key. Render stores it as a secret environment variable.

Set `GEMINI_MODEL` to override the default `gemini-3.5-flash`. `GEMINI_FALLBACK_MODEL` (default `gemini-3.1-flash-lite`) is tried if the primary model is unavailable. Explanations are cached in memory per case and limited per client IP (`DEMO_EXPLAIN_LIMIT`, default 20 per hour).

## Local Development

```bash
pip install -r requirements_demo.txt
uvicorn demo.app:app --reload --port 8000
```

Open http://localhost:8000

## Features
- Browse all 518 audited cases
- View detailed findings, remediation, and verification steps
- AI explanation powered by Gemini 1.5 Flash
- Re-run solver from UI
