# Experiment copy (v2)

This folder is a copy of the project made on 2026-10-13 for trying new ideas and UI changes.
The original in `..\threat-detection-system` is untouched and can keep running.

- Git branch here: `experiments` (the stable version is tagged `v1-stable`).
- Ports: backend **8100**, frontend **5273** (so it can run beside the original on 8000 / 5173).
- It starts with an empty database and no uploaded documents. The `.env` (Groq key, admin password) was copied.

Run it (two terminals):

    cd E:\cybermind-ai-threat-detection\threat-detection-system-v2\backend
    python -m uvicorn app.main:app --port 8100

    cd E:\cybermind-ai-threat-detection\threat-detection-system-v2\frontend
    $env:VITE_API_BASE="http://127.0.0.1:8100"; npm run dev -- --port 5273

Open http://localhost:5273

Go back to the stable version: `git checkout v1-stable` (or use the original folder).
Pushing: `git push` from here does nothing by accident. To publish experiments use `git push -u origin experiments`.
