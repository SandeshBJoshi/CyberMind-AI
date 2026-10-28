# Deploy: backend on Render, frontend on Vercel

The backend (FastAPI) runs on Render and the frontend (React) on Vercel. Do the backend first.

## 1. Backend on Render
1. Push this repo to GitHub (done: `SandeshBJoshi/CyberMind-AI-Project`).
2. Render dashboard -> **New** -> **Blueprint** -> pick the repo. Render reads `render.yaml`.
3. When it asks for **CORS_ORIGINS**, type a placeholder for now (for example `https://example.com`). You will fix it in step 3 below.
4. Wait for the deploy. Open `https://<your-service>.onrender.com/health`. It should answer `{"status":"ok", ...}`.
5. Render generated the admin password. In the service's **Environment** tab, read `ADMIN_PASSWORD` (user `admin`).

## 2. Frontend on Vercel
1. Vercel dashboard -> **Add New** -> **Project** -> pick the repo.
2. Set **Root Directory** to `frontend`. Framework: Vite (auto-detected).
3. Add an environment variable: `VITE_API_BASE` = your Render URL (no trailing slash), for example `https://cybermind-api.onrender.com`.
4. Deploy. You get a URL like `https://cybermind-xxxx.vercel.app`.

## 3. Connect them
In Render -> the service -> **Environment** -> set `CORS_ORIGINS` to the exact Vercel URL (no trailing slash) and save. Render redeploys. Without this the browser blocks the API calls.

## Things to know
- **Free Render sleeps** after about 15 minutes idle; the first request takes 30 to 60 seconds to wake it.
- **The database is SQLite on Render's disk and is wiped on every redeploy or restart of a free service.** For lasting data, create a free Postgres on Render and set `DATABASE_URL` on the service.
- **The Analyst Assistant (LangChain, Chroma, PDF) is not installed on Render** (`requirements-deploy.txt` leaves it out), so that screen answers "not available". Everything else works.
- **The ML model file is not in Git.** On first start the backend builds a starting model from synthetic data; this takes a few seconds.
- **Shadow mode, poison tracing** are on by default; set `SHADOW_MODE=false` or `POISON_TRACING=false` to turn them off.
- Optional AI features need keys set as environment variables (`GROQ_API_KEY`, `GEMINI_API_KEY`). Never put keys in Git.
- The demo scripts that fake IP addresses need `ALLOW_CLIENT_IP_HEADER=true`, which the Render blueprint turns off on purpose. Run those demos locally.
