# CYBERMIND AI

Real-time account-takeover protection. It watches the login page and signed-in sessions, decides whether to **allow**, ask for **extra proof**, **contain in a sandbox** or **block**, and always shows the reasons in plain words.

Built as a team project at the Dept. of AIML, BEC Bagalkot.

**Stack:** Python, FastAPI, SQLAlchemy, scikit-learn (Isolation Forest), WebSockets, React, Vite, Three.js, LangGraph, ChromaDB.

## What it does

- **Login protection:** groups login attempts by client fingerprint instead of IP, so attacks that rotate through thousands of IPs are caught as one campaign. Uses decoy accounts and a breached-password check (hash only).
- **Session protection:** rules, a per-user behaviour baseline and an ML model flag IP or device changes, odd typing rhythm and API request bursts.
- **Phishing Poison Tracing:** plant a fake credential from a phishing email; if it is ever used at a login, the attacker's campaign is blocked.
- **Shadow Mode:** an uncertain stolen session is served from a sandbox where nothing real moves, while an admin releases or freezes it.
- **CyberMind Network:** a small separate hub where installs share blocked fingerprints as hashes. A hint only, never a block.
- **Attack Lab:** replays realistic attacks against the real detection code, plus an adaptive stress test that searches for ways to slip past.
- **Analyst Assistant:** chat over uploaded documents (RAG) and a structured report with CVE lookup.
- **Console:** live alerts, session list, review queue and a 3D view where each dot is a real session.

A language model never makes or changes a decision.

## Run it

You need Python 3.11+ and Node 18+.

```bash
# backend
cd backend
pip install -r requirements.txt
cp ../.env.example .env        # then set JWT_SECRET, ADMIN_PASSWORD (and an API key for the assistant, optional)
python -m uvicorn app.main:app --port 8000

# frontend (second terminal)
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and sign in as the admin from your `.env`.

## Try the demos

With the backend running, from the project folder:

```bash
python demo/shadow_demo.py        # a stolen session lands in the Shadow queue
python demo/attack_login.py       # a login attack gets blocked
python demo/session_hijack.py     # a hijacked session gets contained
```

For the poison demo, plant a credential in Email Analysis first, then `python demo/poison_trace.py --username <planted> --password <planted>`.

## Tests

```bash
cd backend
python -m unittest discover -s tests -t .
```

## More

- Full guide (architecture, API, every feature in detail): [docs/DETAILED_GUIDE.md](docs/DETAILED_GUIDE.md)
- What changed from the first version, and how it differs from other tools: [docs/CYBERMIND_AI_Project_Overview.pdf](docs/CYBERMIND_AI_Project_Overview.pdf)
- Network hub: [hub/README.md](hub/README.md)
- Current status: [PROJECT_STATUS.md](PROJECT_STATUS.md)

This is a research and demo project, not a production product.
