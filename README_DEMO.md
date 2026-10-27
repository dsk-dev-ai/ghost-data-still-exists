# Ghost Data Still Exists - Demo App

A web demo to visualize the deletion audit results with optional Gemini AI explanations.

## Deploy to Render

1. Fork/push this repo to GitHub
2. Go to [render.com](https://render.com) and create a new Web Service from the repo
3. Render will use `render.yaml` automatically
4. Add environment variable `GEMINI_API_KEY` (get from [Google AI Studio](https://aistudio.google.com/apikey))
5. Deploy

Set `GEMINI_MODEL` to override the default `gemini-2.5-flash`. Explanations are cached in memory per case and limited per client IP (`DEMO_EXPLAIN_LIMIT`, default 20 per hour).

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
