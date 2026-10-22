# 🛡️ CYBERMIND AI — Real-Time ML Behavioral Threat Detection & Automated Lockdown System

<p align="center">
  <img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" />
  <img src="https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react" />
  <img src="https://img.shields.io/badge/ML-Isolation%20Forest-orange?style=for-the-badge&logo=scikit-learn" />
  <img src="https://img.shields.io/badge/AI-LangGraph%20%2B%20Gemini-4285F4?style=for-the-badge&logo=google" />
  <img src="https://img.shields.io/badge/DB-SQLite%20%2F%20PostgreSQL-003B57?style=for-the-badge&logo=sqlite" />
  <img src="https://img.shields.io/badge/Vector%20DB-ChromaDB-purple?style=for-the-badge" />
</p>

---

## Table of Contents

1. [What Is This Project?](#what-is-this-project)
2. [System Architecture](#system-architecture)
3. [How It Works — Full Pipeline](#how-it-works--full-pipeline)
4. [Key Features](#key-features)
5. [Project Structure](#project-structure)
6. [Technology Stack and Why](#technology-stack-and-why)
7. [Backend Deep Dive](#backend-deep-dive)
8. [Frontend Deep Dive](#frontend-deep-dive)
9. [CyberMind Intel AI Module](#cybermind-intel-ai-module)
10. [Database Schema](#database-schema)
11. [Security Rules Engine](#security-rules-engine)
12. [ML Anomaly Engine](#ml-anomaly-engine)
13. [Decision Engine](#decision-engine)
14. [Real-Time WebSocket Feed](#real-time-websocket-feed)
15. [Environment Variables](#environment-variables)
16. [Setup and Running Locally](#setup-and-running-locally)
17. [Demo Walkthrough](#demo-walkthrough)
18. [API Reference](#api-reference)
19. [Configuration Tuning](#configuration-tuning)
20. [Optional PostgreSQL via Docker](#optional-postgresql-via-docker)

---

## What Is This Project?

**CYBERMIND AI** is a full-stack, real-time cybersecurity threat detection and automated response platform. It simulates and detects malicious user behavior across live sessions by combining:

- **Deterministic rule-based threat detection** (explicit security heuristics)
- **Unsupervised ML anomaly detection** (Isolation Forest on behavioral biometrics)
- **Automatic session lockdown** with admin-controlled unlock
- **A built-in LLM-powered cyber intelligence assistant** (CyberMind Intel) for RAG-based threat analysis

The system is designed as a realistic demonstration of how modern Security Operations Centers (SOCs) detect insider threats, credential abuse, and anomalous user behavior — powered by both classical rule engines and machine learning.

---

## System Architecture

```
+------------------------------------------------------------------+
|                        BROWSER CLIENTS                           |
|                                                                  |
|   +--------------------+        +--------------------------+    |
|   |  Admin Console     |        |  VaultApp User Portal    |    |
|   |  (React / Vite)    |        |  (React / Vite)          |    |
|   |  Port 5173         |        |  /#user-portal           |    |
|   +--------+-----------+        +----------+---------------+    |
|            |  REST + WebSocket             |  REST (polling)    |
+------------+-------------------------------+--------------------+
             |                               |
             v                               v
+------------------------------------------------------------------+
|                  FastAPI Backend  (Port 8000)                    |
|                                                                  |
|  +-------------+  +--------------+  +--------------------+     |
|  | Rule Engine |  |  ML Engine   |  |  Decision Engine   |     |
|  | (6 rules)   |  |  (IsoForest) |  |  (score -> status) |     |
|  +------+------+  +------+-------+  +----------+---------+     |
|         +------------------+-----------------------+            |
|                            |                                    |
|  +-------------------------v----------------------------------+  |
|  |           SQLAlchemy ORM  -->  SQLite / PostgreSQL        |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |    CyberMind Intel  (LangGraph RAG Agent)                  |  |
|  |    ChromaDB Vector Store  -->  Gemini / Groq LLM           |  |
|  +------------------------------------------------------------+  |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |    WebSocket Manager  (ws://localhost:8000/ws/live)        |  |
|  +------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

---

## How It Works — Full Pipeline

### Step 1 — Session Creation
A user visits the **VaultApp User Portal** (`/#user-portal`). Upon interaction, the portal calls `POST /api/sessions/start`, which creates a `SessionState` record in the database. The session is assigned a UUID and its IP address and device fingerprint are stored as reference baselines.

### Step 2 — Behavioral Telemetry Ingestion
As the user types or clicks within the VaultApp, behavioral metrics are captured:

| Metric | Description |
|--------|-------------|
| `keystroke_avg_interval_ms` | Average time between keystrokes |
| `keystroke_std_interval_ms` | Variability of keystroke timing |
| `typing_speed_cpm` | Characters per minute typed |
| `mouse_click_rate` | Mouse click frequency |
| `mouse_move_entropy` | Randomness of mouse movement paths |
| `session_duration_sec` | Duration since session started |

These are sent as a `POST /api/events/behavior` payload.

### Step 3 — Rule Engine Evaluation
The **Rule Engine** (`rule_engine.py`) evaluates the incoming event against 6 deterministic security rules:

1. **Excessive Failed Logins** — >= 5 failed logins in 10 minutes → weight 3.0
2. **Unusual Login Hour** — logins outside 05:00–23:00 UTC → weight 1.0
3. **IP / Device Change** — IP or device fingerprint differs from stored baseline → weight 1.5
4. **Request Burst** — >= 60 API calls in 1 minute → weight 2.5
5. **Excessive Resource Access** — >= 8 distinct resources in 2 minutes → weight 2.0
6. **Typing Speed Threshold** — typing > 100 CPM (demo trigger) → weight 6.0

Each triggered rule adds a fixed weight to the risk score.

### Step 4 — ML Anomaly Detection
Simultaneously, the **ML Engine** (`ml_engine.py`) vectorizes the 6 behavioral features and scores them against a trained **Isolation Forest** model (200 estimators, 8% contamination rate). The model:

- Was trained at startup on a synthetic baseline of "normal" behavioral distributions
- Returns `(is_anomaly: bool, raw_signal: float)` — anomaly adds +2.5 to the risk score
- Persists the trained model to `isolation_forest.joblib` so restarts do not require retraining

### Step 5 — Decision Engine
The **Decision Engine** (`decision_engine.py`) combines the rule score and ML signal into a final `internal_score`:

```
internal_score = rule_score + (2.5 if ml_is_anomaly else 0)

SAFE        if score < 3.0  (50% of lockdown threshold)
SUSPICIOUS  if score >= 3.0
LOCKDOWN    if score >= 6.0
```

> **Privacy note:** The numeric score is stored in the database for admin audit purposes only. The API never exposes it to non-admin clients — users only ever see SAFE, SUSPICIOUS, or LOCKDOWN.

### Step 6 — Automated Response
- **SAFE** → session status stays `active`
- **SUSPICIOUS** → session status set to `suspicious`, flagged for monitoring
- **LOCKDOWN** → session status atomically set to `locked` using a conditional DB update, a `LockdownRecord` is created, and a WebSocket `lockdown` event is broadcast to all connected admin consoles

### Step 7 — Real-Time Admin Notification
The **WebSocket Manager** (`ws://localhost:8000/ws/live`) pushes every security event to all connected admin dashboards in real-time. The admin sees:
- Live event stream with threat status and triggered rules
- Automatic lockdown alerts with session ID and reason
- Metric cards updating with event statistics

### Step 8 — Admin Unlock
An admin authenticates with JWT and calls `POST /api/lockdown/unlock/{session_id}`. The session status is reset to `active`, the `LockdownRecord` is closed with `unlocked_at` timestamp, and the VaultApp portal (which polls every 3 seconds) detects the unlock within moments.

---

## Key Features

| Feature | Description |
|---------|-------------|
| Real-Time Threat Detection | Sub-second behavioral analysis per event |
| Dual Detection Engine | Rule-based + Isolation Forest ML working in parallel |
| Automated Lockdown | Session locked atomically the moment threshold is crossed |
| WebSocket Live Feed | Admin console receives push updates instantly |
| CyberMind Intel | LLM-powered RAG assistant with PDF ingestion |
| Attacker Simulator | Built-in attack scenario console (API burst, credential stuffing, etc.) |
| Full Audit Trail | Every event, rule flag, ML result, and action stored in DB |
| JWT Admin Auth | Secure token-based admin authentication |
| Cinematic UI | 3D intro animation, particle background, glassmorphism design |
| Sessions Dashboard | Real-time session monitoring with unlock controls |
| Security Logs | Searchable, filterable event log with full metadata |
| Docker Support | Optional Postgres via docker-compose |

---

## Project Structure

```
threat-detection-system/
|
+-- backend/                          # FastAPI Python backend
|   +-- app/
|   |   +-- main.py                   # App entry point, lifespan, CORS, router registration
|   |   +-- config.py                 # Pydantic settings loaded from .env
|   |   +-- database.py               # SQLAlchemy engine & session factory
|   |   +-- models.py                 # ORM models: AdminUser, SessionState, SecurityEvent, LockdownRecord
|   |   +-- schemas.py                # Pydantic request/response schemas
|   |   +-- auth.py                   # JWT authentication utilities
|   |   +-- rule_engine.py            # 6 deterministic security rules
|   |   +-- ml_engine.py              # Isolation Forest training, inference, vectorization
|   |   +-- decision_engine.py        # Combines rule + ML scores -> SAFE/SUSPICIOUS/LOCKDOWN
|   |   +-- simulator.py              # Synthetic normal/attack training data generator
|   |   +-- seed_admin.py             # Creates default admin user on startup
|   |   +-- websocket_manager.py      # WebSocket connection pool & broadcast
|   |   +-- isolation_forest.joblib   # Persisted trained ML model
|   |   |
|   |   +-- routers/
|   |   |   +-- auth_routes.py        # POST /api/auth/login -> JWT token
|   |   |   +-- events_routes.py      # POST /api/events/behavior (main threat pipeline)
|   |   |   +-- lockdown_routes.py    # POST /api/lockdown/unlock/{session_id}
|   |   |   +-- logs_routes.py        # GET /api/logs (admin event log)
|   |   |   +-- simulate_routes.py    # POST /api/simulate/* (attack scenarios)
|   |   |   +-- user_routes.py        # POST /user/behavior, GET /user/status (portal API)
|   |   |   +-- cybermind_routes.py   # CyberMind Intel PDF ingestion & RAG query
|   |   |   +-- ws_routes.py          # WS /ws/live (WebSocket endpoint)
|   |   |
|   |   +-- cybermind/
|   |       +-- __init__.py
|   |       +-- pdf_loader.py         # PyMuPDF PDF text extraction
|   |       +-- vector_store.py       # ChromaDB service (add, search, clear)
|   |       +-- workflow.py           # LangGraph RAG agent (planner->retrieve->web->synthesize->validate)
|   |
|   +-- requirements.txt              # Python dependencies
|   +-- check_db.py                   # Database inspection utility
|   +-- .env                          # Local environment variables (not committed)
|
+-- frontend/                         # React + Vite admin console
|   +-- src/
|   |   +-- main.jsx                  # React entry point
|   |   +-- App.jsx                   # Root component: routing, WebSocket, auth state
|   |   +-- api.js                    # Axios/fetch API client layer
|   |   +-- ws.js                     # WebSocket connection factory
|   |   +-- index.css                 # Complete CSS design system (dark theme, animations)
|   |   |
|   |   +-- components/
|   |       +-- Sentinel3DIntro.jsx   # Cinematic 3D intro animation (CSS + canvas)
|   |       +-- ParticleBackground.jsx # Animated particle constellation background
|   |       +-- ShatteredGlassHero.jsx # Animated hero with shattered glass effect
|   |       +-- Login.jsx             # Admin JWT login form
|   |       +-- Navbar.jsx            # Navigation bar with view switching
|   |       +-- Dashboard.jsx         # Live event feed + metric cards
|   |       +-- MetricCard.jsx        # Reusable animated metric display
|   |       +-- StatusIndicator.jsx   # Animated threat status badge
|   |       +-- ActivityFeed.jsx      # Real-time event list component
|   |       +-- AttackerConsole.jsx   # Attack scenario simulator UI
|   |       +-- SessionsPanel.jsx     # Session monitor with unlock controls
|   |       +-- LogsViewer.jsx        # Searchable security event log
|   |       +-- LockdownScreen.jsx    # Full-screen lockdown overlay
|   |       +-- UserPortal.jsx        # VaultApp user portal (simulated target)
|   |       +-- CybermindAI.jsx       # CyberMind Intel AI chat interface
|   |
|   +-- index.html                    # HTML shell
|   +-- package.json                  # Node dependencies
|   +-- vite.config.js                # Vite build configuration
|
+-- docker-compose.yml                # Optional Postgres container
+-- .env.example                      # Environment variable template
+-- .gitignore
+-- PROJECT_STATUS.md                 # Developer handoff notes
+-- README.md                         # This file
```

---

## Technology Stack and Why

### Backend

| Technology | Version | Why It Was Chosen |
|------------|---------|-------------------|
| **FastAPI** | 0.115.0 | Async-first, automatic OpenAPI docs, excellent typing support via Pydantic. Ideal for high-throughput event ingestion. |
| **Uvicorn** | 0.30.6 | ASGI server required for FastAPI's async features and WebSocket support. |
| **SQLAlchemy** | 2.0.35 | Mature ORM with SQLite and PostgreSQL compatibility — allows zero-config local development while being production-ready. |
| **Pydantic** | 2.9.2 | Request validation, settings management, and schema definition with automatic error messages. |
| **python-jose** | 3.3.0 | JWT token creation and verification for admin authentication. |
| **passlib + bcrypt** | 1.7.4 / 4.0.1 | Industry-standard password hashing. bcrypt's computational cost protects against brute force. |
| **scikit-learn** | 1.5.2 | Provides `IsolationForest` — an unsupervised anomaly detection algorithm requiring no labeled data. |
| **NumPy** | 1.26.4 | Efficient numerical arrays for ML feature vectorization. |
| **joblib** | 1.4.2 | Serializes and loads the trained Isolation Forest model to disk, avoiding retraining on every restart. |
| **websockets** | >=14 | Enables the real-time push notification feed from server to all admin browsers. |
| **LangChain** | 1.3.14 | Orchestration framework for LLM interactions — provides a consistent interface across providers (Gemini, Groq). |
| **LangGraph** | 1.2.10 | Builds the stateful, cyclical RAG agent graph (planner -> retrieve -> web -> synthesize -> validate). |
| **ChromaDB** | latest | Embedded vector database for semantic document search. Requires zero external infrastructure. |
| **PyMuPDF** | latest | Fast PDF text extraction for ingesting cybersecurity intelligence reports. |
| **langchain-google-genai** | latest | Integrates Google's Gemini models (default: `gemini-1.5-flash`) as the CyberMind LLM. |
| **langchain-groq** | latest | Alternative LLM provider (Llama models via Groq) for CyberMind when GROQ_API_KEY is set. |
| **duckduckgo-search** | latest | Provides free, privacy-respecting web search for the CyberMind agent's web research step. |
| **python-dotenv** | 1.0.1 | Loads `.env` file configuration for clean environment variable management. |

### Frontend

| Technology | Version | Why It Was Chosen |
|------------|---------|-------------------|
| **React** | 18.3.1 | Component-based UI with hooks for managing real-time state from WebSocket events and API polling. |
| **Vite** | 5.4.6 | Extremely fast dev server with HMR. Significantly faster than Create React App for development iteration. |
| **Vanilla CSS** | — | Maximum control over the premium dark-mode, glassmorphism, and animation design system. No framework overhead. |
| **marked** | 18.0.13 | Renders the LLM's markdown-formatted threat intelligence briefings in the CyberMind chat UI. |

---

## Backend Deep Dive

### `main.py` — Application Entrypoint
Uses FastAPI's `lifespan` context manager to run startup tasks:
1. Create all database tables via `Base.metadata.create_all()`
2. Seed the default admin user (`seed_admin.py`)
3. Train/load the Isolation Forest model on synthetic normal baseline data

All routers are registered here with their prefixes.

### `config.py` — Configuration Management
Uses `pydantic_settings.BaseSettings` to load configuration from environment variables and `.env` file. All detection thresholds, JWT settings, LLM keys, and database URLs are configurable without code changes.

### `auth.py` — JWT Authentication
- `POST /api/auth/login` accepts username/password, verifies against bcrypt hash, returns a signed JWT
- `get_current_admin()` dependency verifies the JWT on every protected admin endpoint
- Tokens expire after `JWT_EXPIRE_MINUTES` (default: 60 minutes)

### `simulator.py` — Training Data Generator
Generates synthetic behavioral feature matrices for both "normal" user patterns and attack patterns. Used at startup to train the Isolation Forest on realistic baseline data, ensuring the ML model is ready immediately without needing real historical data.

---

## Frontend Deep Dive

### `App.jsx` — Root Application
- Manages global auth state, current view, and WebSocket connection
- WebSocket messages flow into state: `security_event` -> live event feed, `lockdown` -> session lock registry, `unlocked` -> lock removal
- Supports `#user-portal` hash routing to load the VaultApp in isolation (separate tab)
- Persists selected view in `localStorage` so page refreshes restore context

### `Sentinel3DIntro.jsx` — Cinematic Loading Screen
A fully custom CSS + canvas animated intro sequence styled as a security system initialization. Cross-fades into the main application when complete or skipped.

### `UserPortal.jsx` — VaultApp (Simulated Target)
- A realistic-looking banking/vault web application used as the demonstration target
- Captures keystroke timing, mouse movement, and click behavior passively
- Sends behavioral telemetry to `POST /user/behavior` every few seconds
- Polls `GET /user/status` every 3 seconds — instantly reflects admin lockdowns and unlocks
- Shows a full lockdown overlay when session is `LOCKDOWN`

### `AttackerConsole.jsx` — Attack Scenario Simulator
An admin tool for launching configured attack scenarios against monitored sessions:
- **T1110 — Credential Stuffing**: Sends multiple login failure events
- **T1499 — API Burst**: Fires 75 authenticated `api_call` events in rapid succession
- **T1078 — Typing Anomaly**: Sends high-speed typing behavior events
- **IP Change Attack**: Sends events from a spoofed IP address
- Each scenario shows live request count, status, and per-request results

### `CybermindAI.jsx` — Intelligence Chat Interface
- Allows admin to upload PDF cybersecurity reports and query them with natural language
- Displays structured threat intelligence briefings rendered from markdown
- Shows the agent's reasoning steps (plan, retrieve, web search, synthesize, validate)
- Displays groundedness score and hallucination detection results from the validation node

---

## CyberMind Intel AI Module

The `cybermind/` module implements a multi-step RAG (Retrieval-Augmented Generation) agent using **LangGraph**.

### Agent Architecture

```
         +---------+
         | planner | <-----------------------+
         +----+----+                         |
              |  next_step decision          |
    +---------+----------+                   |
    v                    v                   |
+----------+        +----------+             |
| retrieve |        |   web    |             |
| (Chroma) |        | (DuckDDG)|             |
+----+-----+        +----+-----+             |
     +-----------+--------+                  |
                 |  (loop back to planner) --+
                 |
            +----v-----+
            |synthesize|
            +----+-----+
                 |
            +----v-----+
            | validate |
            +----+-----+
                 |
                END
```

### Node Descriptions

| Node | Function |
|------|----------|
| **planner** | Decides which step to take next: `retrieve_docs`, `web_search`, or `synthesize`. If local documents exist, prioritizes retrieval first. |
| **retrieve** | Performs cosine similarity search against the ChromaDB vector store (top-5 chunks). Extracts document sources for citation. |
| **web** | Runs a DuckDuckGo search and returns the result snippet as web context. |
| **synthesize** | Sends all retrieved context (local + web) to the LLM with a strict structured prompt. Produces a 7-section Cyber Threat Intelligence Briefing. |
| **validate** | A second LLM call acts as a fact-checker: scores groundedness (1–5), detects hallucinations, and provides a reasoning verdict. |

### LLM Providers
- **Gemini** (default): `gemini-1.5-flash` via `langchain-google-genai`. Requires `GEMINI_API_KEY`.
- **Groq / Llama**: Any Groq-hosted model. Requires `GROQ_API_KEY`. Selected via the UI or `CYBERMIND_MODEL` env var.

### PDF Ingestion Pipeline
1. PDF uploaded via `POST /api/cybermind/ingest` (admin only, max 20 MB)
2. PyMuPDF extracts text page by page
3. LangChain's `RecursiveCharacterTextSplitter` chunks the text (preserving semantic boundaries)
4. Chunks embedded and stored in ChromaDB with source filename metadata
5. Subsequent queries automatically retrieve relevant chunks via semantic similarity

---

## Database Schema

### `admin_users`
| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment |
| username | String (unique) | Admin username |
| hashed_password | String | bcrypt hash |
| created_at | DateTime | Creation timestamp |

### `sessions`
| Column | Type | Description |
|--------|------|-------------|
| session_id | String PK | UUID |
| user_label | String | Display name (default: `demo_user`) |
| status | String | `active` or `suspicious` or `locked` |
| last_ip | String | Last known IP address |
| last_device | String | Last known device fingerprint |
| created_at | DateTime | Session start time |
| updated_at | DateTime | Last event timestamp |
| locked_at | DateTime | When session was locked |

### `security_events`
| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment |
| timestamp | DateTime (indexed) | Event time |
| session_id | String (indexed) | Associated session |
| event_type | String | `behavior`, `login_success`, `login_failed`, `api_call`, `resource_access`, `ip_change` |
| ip_address | String | Source IP |
| device_info | String | User agent / device fingerprint |
| details | JSON | Raw behavioral metadata |
| rule_flags | JSON | List of triggered rule names |
| ml_anomaly | Boolean | Whether ML flagged as anomalous |
| internal_score | Float | Combined risk score (admin audit only, never exposed to users) |
| status | String | `SAFE`, `SUSPICIOUS`, or `LOCKDOWN` |
| action_taken | String | `none`, `flagged_for_monitoring`, `session_locked`, or `blocked_session_locked` |

### `lockdown_records`
| Column | Type | Description |
|--------|------|-------------|
| id | Integer PK | Auto-increment |
| session_id | String (indexed) | Locked session |
| triggered_at | DateTime | Lockdown start time |
| reason | JSON | List of rule flags and/or `ml_anomaly` |
| unlocked_at | DateTime | When admin unlocked (null if still locked) |
| unlocked_by | String | Admin username who unlocked |

---

## Security Rules Engine

File: `backend/app/rule_engine.py`

Rules are evaluated against the last N minutes of `SecurityEvent` history for the given session. All rule weights contribute to the `internal_score`:

```python
RULE_WEIGHTS = {
    "excessive_failed_logins":         3.0,   # >=5 failures in 10 min
    "unusual_login_hour":              1.0,   # login outside 05:00-23:00 UTC
    "ip_or_device_change":             1.5,   # IP or device differs from stored baseline
    "request_burst":                   2.5,   # >=60 API calls in 1 min
    "excessive_resource_access":       2.0,   # >=8 distinct resources in 2 min
    "typing_speed_threshold_exceeded": 6.0,   # typing > 100 CPM (demo trigger)
}
```

**Why these rules?** These map directly to real-world MITRE ATT&CK techniques:
- `excessive_failed_logins` -> T1110 (Brute Force)
- `request_burst` -> T1499 (Endpoint Denial of Service)
- `ip_or_device_change` -> T1078 (Valid Accounts / Session Hijacking)
- `excessive_resource_access` -> T1083 (File and Directory Discovery)

---

## ML Anomaly Engine

File: `backend/app/ml_engine.py`

### Algorithm: Isolation Forest
**Why Isolation Forest?** It is an unsupervised algorithm — it learns what "normal" looks like from unlabeled data and identifies anomalies as samples that are isolated (short path length in random decision trees). No labeled attack data is required.

### Feature Vector (6 dimensions)
```
[keystroke_avg_interval_ms, keystroke_std_interval_ms, typing_speed_cpm,
 mouse_click_rate, mouse_move_entropy, session_duration_sec]
```

These features are behavioral biometrics — patterns that are hard to fake because they reflect natural human motor patterns. An attacker using automation (scripts, bots) will produce feature vectors that deviate from the trained normal distribution.

### Model Configuration
```python
IsolationForest(
    n_estimators=200,     # 200 trees for stable estimates
    contamination=0.08,   # Expects ~8% anomalous events in training data
    random_state=42,      # Deterministic results
)
```

### Training and Persistence
- On startup, the model is trained on synthetic normal behavioral data (mean/std tuned to realistic human typing patterns)
- The trained model is serialized to `isolation_forest.joblib` — fast loading on subsequent restarts
- A retrain function is available to update the model with new data

---

## Decision Engine

File: `backend/app/decision_engine.py`

```
ML_ANOMALY_WEIGHT = 2.5
SUSPICIOUS_THRESHOLD_RATIO = 0.5

internal_score = rule_score(rule_flags) + (2.5 if ml_is_anomaly else 0)

LOCKDOWN    if score >= LOCKDOWN_THRESHOLD       (default 6.0)
SUSPICIOUS  if score >= LOCKDOWN_THRESHOLD * 0.5 (default 3.0)
SAFE        otherwise
```

**Design rationale:** Neither the rule engine nor the ML model alone can lock a session. The combination ensures low false-positive rates while catching multi-vector attacks. A single anomaly (e.g., slightly fast typing) will not trigger lockdown — but typing fast *and* making excessive API calls *and* coming from a new IP will.

---

## Real-Time WebSocket Feed

### Server: `ws://localhost:8000/ws/live`

The `WebSocketManager` maintains a list of connected admin clients and broadcasts JSON messages to all of them simultaneously.

### Message Types

| Type | Payload Fields | Triggered When |
|------|---------------|----------------|
| `session_started` | `session_id`, `status` | New session created |
| `security_event` | `session_id`, `event_type`, `status`, `rule_flags`, `ml_anomaly`, `action_taken`, `timestamp` | Every processed behavior event |
| `lockdown` | `session_id`, `reason` | Session crosses lockdown threshold |
| `event_blocked` | `session_id` | Event received for already-locked session |
| `unlocked` | `session_id` | Admin unlocks a session |

### Client: `frontend/src/ws.js`
Establishes the WebSocket connection with automatic reconnection logic. Events flow into React state via `setEvents` and `setLockedSessions`.

---

## Environment Variables

Copy `.env.example` to `backend/.env` and fill in values:

```env
# Database (default: SQLite, no setup required)
DATABASE_URL=sqlite:///./security.db

# Auth
JWT_SECRET=change_this_to_a_long_random_secret
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60

# Admin credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_this_password

# Detection Thresholds
LOCKDOWN_THRESHOLD=6.0
FAILED_LOGIN_LIMIT=5
FAILED_LOGIN_WINDOW_MIN=10
REQUEST_BURST_LIMIT=60
REQUEST_BURST_WINDOW_MIN=1
RESOURCE_ACCESS_LIMIT=8
RESOURCE_ACCESS_WINDOW_MIN=2

# CyberMind Intel AI (optional — only needed for the AI chat feature)
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
CYBERMIND_MODEL=gemini-1.5-flash
CYBERMIND_CHROMA_DIR=./data/cybermind_chroma
CYBERMIND_MAX_UPLOAD_MB=20
```

---

## Setup and Running Locally

### Prerequisites
- Python 3.11+
- Node.js 18+
- npm

### Backend Setup

```powershell
# Navigate to the backend directory
cd threat-detection-system\backend

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Copy environment file and configure
copy ..\env.example .env
# Edit .env with your API keys and settings

# Start the backend server
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

The backend will:
- Auto-create the SQLite database and tables
- Seed the default admin user (`admin` / `admin123` unless overridden in `.env`)
- Train and persist the Isolation Forest model

### Frontend Setup

```powershell
# In a separate terminal
cd threat-detection-system\frontend

# Install dependencies
npm install

# Start the dev server
npm run dev -- --host 127.0.0.1
```

### Access the Application

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:5173/` | Admin console (login: admin / admin123) |
| `http://127.0.0.1:5173/#user-portal` | VaultApp user portal (no login required) |
| `http://127.0.0.1:8000/health` | Backend health check |
| `http://127.0.0.1:8000/docs` | Interactive API documentation (Swagger UI) |
| `ws://127.0.0.1:8000/ws/live` | Live WebSocket event feed |

---

## Demo Walkthrough

This walkthrough demonstrates the complete threat detection and lockdown cycle:

### 1. Open Two Browser Tabs
- **Tab A**: `http://127.0.0.1:5173/` — Log in as admin
- **Tab B**: `http://127.0.0.1:5173/#user-portal` — VaultApp portal

### 2. Create a Session
In **Tab B** (VaultApp), interact with the portal. It automatically creates a session and begins sending behavioral telemetry. You will see the session appear live in the **Dashboard** on Tab A.

### 3. Simulate an API Burst Attack
In **Tab A** (Admin Console):
1. Click **Attacker Terminal** in the navbar
2. Select the active session from the dropdown
3. Choose **T1499 — API Burst**
4. Click **Launch Attack**

Watch the Attacker Console show each of the 75 API requests firing in real time.

### 4. Observe the Lockdown
- **Tab A Dashboard** — Live event feed shows events turning LOCKDOWN (red)
- **Tab B VaultApp** — Full lockdown overlay appears within seconds
- **Sessions panel** — Session row shows LOCKDOWN with reason flags

### 5. Admin Unlock
In **Tab A**, navigate to **Sessions** and click **Unlock** next to the locked session. Within ~3 seconds, **Tab B** VaultApp returns to SAFE status.

### 6. Try CyberMind Intel
In **Tab A**, navigate to **CyberMind Intel**:
1. Upload a PDF cybersecurity report (e.g., any MITRE ATT&CK report)
2. Type a query: "What are the main attack techniques used by APT groups?"
3. The agent will retrieve relevant chunks, optionally run a web search, synthesize a structured briefing, and validate the response for hallucinations

---

## API Reference

### Authentication
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/auth/login` | POST | None | Get JWT token |

### Session and Events
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/sessions/start` | POST | None | Create a new monitored session |
| `/api/sessions` | GET | Admin | List all sessions with status |
| `/api/events/behavior` | POST | None | Ingest a behavioral event (main pipeline) |
| `/api/protected-action` | POST | None | Test protected resource access |

### Lockdown Management
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/lockdown/unlock/{session_id}` | POST | Admin | Unlock a locked session |

### Logs and Monitoring
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/logs` | GET | Admin | Paginated security event log |

### Attack Simulation
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/simulate/attack` | POST | Admin | Run a named attack scenario |

### User Portal (VaultApp)
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/user/behavior` | POST | None | VaultApp behavioral telemetry endpoint |
| `/user/status/{session_id}` | GET | None | Get session status for portal display |

### CyberMind Intel
| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/cybermind/status` | GET | Admin | Vector store status + ingested files |
| `/api/cybermind/ingest` | POST | Admin | Upload and index a PDF report |
| `/api/cybermind/query` | POST | Admin | Run RAG query against ingested docs |
| `/api/cybermind/clear` | POST | Admin | Clear the vector store |

### WebSocket
| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `/ws/live` | WS | Real-time security event broadcast |

---

## Configuration Tuning

All thresholds are adjustable via environment variables without code changes:

| Variable | Default | Effect |
|----------|---------|--------|
| `LOCKDOWN_THRESHOLD` | `6.0` | Minimum risk score to trigger lockdown |
| `FAILED_LOGIN_LIMIT` | `5` | Failed logins before rule fires |
| `FAILED_LOGIN_WINDOW_MIN` | `10` | Time window for login failure counting |
| `REQUEST_BURST_LIMIT` | `60` | API calls in window before rule fires |
| `REQUEST_BURST_WINDOW_MIN` | `1` | Time window for burst counting (minutes) |
| `RESOURCE_ACCESS_LIMIT` | `8` | Distinct resources before rule fires |
| `RESOURCE_ACCESS_WINDOW_MIN` | `2` | Time window for resource access counting |

Tip: Lower `LOCKDOWN_THRESHOLD` to `3.0` to make the system more aggressive. Raise `REQUEST_BURST_LIMIT` to `200` to require a heavier burst before detection.

---

## Optional PostgreSQL via Docker

For a production-like setup, use the included Docker Compose file:

```powershell
# Start Postgres container
docker compose up -d

# Update backend/.env:
# DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/threatdb
```

The `docker-compose.yml` starts a Postgres 16 container with a persistent volume, pre-configured with the `sentinel` user and `threatdb` database. The SQLAlchemy connection string just needs to be updated — all models and queries are fully compatible.

---

## Backend Tests

```powershell
cd backend
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

---

## Production Build (Frontend)

```powershell
cd frontend
npm run build
```

Output is placed in `frontend/dist/` and can be served by any static file host or Nginx.

---

## Security Considerations

- **Numeric risk scores are never exposed** to non-admin API consumers — only qualitative status labels (SAFE / SUSPICIOUS / LOCKDOWN)
- **Raw keystroke input is never captured** — only aggregate timing statistics (average interval, standard deviation)
- **Admin tokens expire** after `JWT_EXPIRE_MINUTES` (default 60 min)
- **CyberMind Intel is isolated** from the primary threat database — it uses its own ChromaDB instance
- **All lockdown state transitions use conditional DB updates** — preventing race conditions between concurrent requests
- **Change all default credentials** (`ADMIN_USERNAME`, `ADMIN_PASSWORD`, `JWT_SECRET`) before any non-demo deployment

---

## Built With

- **FastAPI** + **Uvicorn** — Async Python backend
- **SQLAlchemy** — Database ORM
- **scikit-learn** — Isolation Forest anomaly detection
- **LangChain** + **LangGraph** — LLM orchestration and RAG agent graph
- **ChromaDB** — Embedded vector database
- **Google Gemini** / **Groq** — LLM providers for CyberMind Intel
- **React 18** + **Vite 5** — Frontend framework and build tool
- **Vanilla CSS** — Custom dark-mode design system with glassmorphism and animations
- **marked** — Markdown rendering for LLM responses
- **Docker** / **PostgreSQL** — Optional production database

---

*CYBERMIND AI — Real-time threat detection powered by behavioral biometrics, rule-based heuristics, and unsupervised machine learning.*

---

## v2 — Hardening and Real Detection (what changed)

**Security hardening**
- Admin-only endpoints (`/api/sessions`, `/api/logs`, simulator, WebSocket feed) now require the admin JWT; JWTs carry a `jti` and are revoked on `/auth/logout`.
- Telemetry needs either the admin token or an HMAC-signed per-session `X-Session-Token` (issued at session start), so knowing a session id is not enough.
- `APP_ENV=production` refuses to start with a weak `JWT_SECRET` / `ADMIN_PASSWORD`; in development it only warns (see `/health`).
- CORS is an allowlist (`CORS_ORIGINS`); `X-Forwarded-For` is trusted only from `TRUSTED_PROXIES` (or `ALLOW_CLIENT_IP_HEADER=true` in dev for the VaultApp demo).
- Sliding-window rate limits on login, session creation and ingest. (In-memory: they reset on restart.)

**Detection**
- Login protection groups attempts into *campaigns* by client fingerprint (browser software + header order), not by IP, so IP rotation does not hide an attack. Decoy accounts give near-zero-false-alarm alerts. Breached-password check (local list; optional HIBP with `ENABLE_HIBP`).
- Per-user baselines (Welford running stats) feed a `baseline_deviation` rule; new device/IP for a known user is a signal.
- Every decision has a risk tier (`allow` / `step_up` / `block`) and human-readable reasons.
- IP change defaults to **step-up** instead of a hard lock (`IP_CHANGE_POLICY=lock` restores the old behaviour). Step-up has no real MFA: sensitive actions return HTTP 428 until an admin clears it.
- The ML model no longer retrains on synthetic data at every start; it trains from real events once there are enough (`/api/ml/retrain`), with a low contamination setting.

**Realistic Attack Lab** (Attacker Terminal → Realistic Attack Lab): replays scripted attacks mixed with normal users through the real detection code on a throw-away in-memory DB. It reports caught/missed, accounts compromised and normal users denied. Two scenarios are *expected to be missed* (diluted stealth, perfect session mimicry) to show the design's limits. It is a simulation, not live traffic.

**Client apps** report logins with `POST /api/auth-events/login-attempt` and header `X-App-Key` (`APP_API_KEYS`).

**Tests:** from `backend/`, run `python -m unittest discover -s tests -t .`

See `.env.example` for all new settings.

### VaultApp is now a real protected app
VaultApp (the demo bank, `#user-portal`) has real customer accounts: open an account, sign in, view balance and activity, and send transfers. Customers are stored in `bank_customers` (bcrypt-hashed passwords) and **never** appear in the admin console.
- Sign-in goes through the same login protection as the console: rate limits, campaign/decoy checks, breached-password check (a breached password signs in but requires step-up before moving money).
- Each sign-in starts a monitored session; the browser reports typing/mouse behaviour to CYBERMIND.
- The bank enforces CYBERMIND's decision: frozen session = HTTP 423 (freeze screen), step-up = HTTP 428 (customer re-enters their password via `/bank/step-up/verify`).
- A pending step-up is **sticky**: normal-looking traffic does not clear it, only verification does.

### Email (phishing) analysis
Console → **Email Analysis**. Upload an `.eml` or paste the full message source. 11 ready-made test emails (6 phishing, 5 legitimate) are in `backend/app/email_samples/`.
- **What it checks:** sender authentication (SPF / DKIM / DMARC), Reply-To and display-name mismatches, look-alike and brand-imitating domains, links whose visible text differs from the real destination, IP / shortener / punycode links, forms posting to other domains, dangerous attachments (double extensions, executables, macros, HTML), and urgency, credential and payment wording.
- **Verdict:** points add up to SAFE (under 3), SUSPICIOUS (3 to 6) or PHISHING (6 or more), with a plain-English reason and the exact evidence for every point. The verdict is rule-based; no AI model decides it.
- **Safety:** the email is only parsed. Links are never opened, attachments are only named and hashed, and only the analysis (not the email) is stored.
- **Reports:** download a PDF or Markdown report with the verdict, reasons, indicators to block, MITRE ATT&CK mapping and recommended actions.
- **Live alert:** a suspicious or phishing result raises the red banner in the console and counts on the Overview.
- **Known limits:** a well-written targeted email with clean headers and no links can look safe; the check for known-bad links needs an outside service and is not included.
- Code: `backend/app/email_parser.py`, `phish_rules.py`, `phish_engine.py`, `phish_report.py`, `routers/email_routes.py`, samples in `backend/app/email_samples/`. Tests: `backend/tests/test_email.py`.

#### AI analyst (optional second opinion)
With `GROQ_API_KEY` set, Email Analysis can also ask a Groq-hosted model (`openai/gpt-oss-20b` faster, `openai/gpt-oss-120b` stronger) to read the email and write its own assessment, in about a second. It is shown next to the rule-based result with "agrees / partly agrees / disagrees", and it is included in the PDF and Markdown reports.
- **The rules stay official.** Email text is untrusted (some phishing contains instructions aimed at AI models), so the model never sets the verdict. The email is passed as data inside tags with an instruction not to obey it, and the answer must be valid JSON that is checked and clamped.
- **Privacy:** when switched on, the email text and the scanner's findings are sent to Groq. Attachments are never sent. Switch it off in the screen and nothing leaves the server.
- No key, no network or a bad answer: the AI panel just says it is unavailable and the rest works.
- Code: `backend/app/phish_ai.py`. Tests (offline, with a fake model): `AiAnalystTests` and `AiApiTests` in `backend/tests/test_email.py`.

### Analyst Assistant report format
Ask a question about an uploaded report and the assistant answers in five sections:
1. **Summary of the report**, written from what your report says.
2. **Attacks performed**: each attack with a short evidence quote and its MITRE ATT&CK, CWE and CAPEC tags. A tag is marked *model-suggested* (dashed) unless the id really appears in your report.
3. **Suggested actions and techniques**: grouped as mitigation, detection, response and hardening, by priority. Each action says whether it is *from the report* or *best practice, not in the report*.
4. **CVEs and what defines them**: CVE ids are taken only from your report text (never from the AI), then looked up in the NIST **NVD** for CVSS score, severity, description and the **CWE** that defines the weakness. A CVE the NVD does not know shows as unverified.
5. **Agents involved**: planner, retriever, (web researcher), analyst, reference checker (NVD) and fact-checker, each with what it did and its time.

A fact-check (groundedness 1 to 5) judges only the claims taken from the report (summary, attacks, report-sourced actions); the model's threat-level rating, NVD data and best-practice extras are outside that check. The Markdown export has the same five sections. Needs internet for the model and the NVD; if the NVD is unreachable the CVEs simply show as unverified. Code: `backend/app/cybermind/` (`workflow.py`, `report.py`, `nvd.py`), screen: `frontend/src/components/IntelReport.jsx`, tests: `backend/tests/test_assistant_report.py`.

## Feature 1: Phishing Poison Tracing (experiments branch)
Connects the phishing module to the login guard. After analysing a suspicious or phishing email, an analyst can press **Plant credential** (Email Analysis). CYBERMIND creates a unique fake username and password tied to that email, shows the password once and stores only a hash. CYBERMIND never submits it anywhere; the analyst enters it manually on a clearly fictional page they control.
- If that credential is ever used at a CYBERMIND-protected login (VaultApp, the console, or an app using the login-protection API), the attempt is refused (like a decoy touch), an explained **`poison_credential_used`** signal blocks the attacker's whole fingerprint campaign, the console raises a banner, and **Detections → Poison traces** shows the timeline *email analysed → planted → used → campaign blocked* with the phishing-to-use time.
- Flag: `POISON_TRACING` (default on). Off means no minting and planted credentials are ignored at login, exactly the earlier behaviour.
- Honest limit: it only traces attackers who actually try the planted credential; a careful attacker may validate credentials elsewhere first.
- Self-test: `python demo/poison_trace.py --username <planted> --password <planted>`. Code: `backend/app/routers/poison_routes.py`, hook in `campaign_engine.py`, tests `backend/tests/test_poison.py`, UI `PoisonTraces.jsx`.

## Feature 2: Shadow Mode (experiments branch)
A fourth verdict between step-up and block. Blocking a suspected session tells the attacker they were caught, and wrongly blocking a real customer is costly. For sessions that are **suspicious but not certain**, CYBERMIND serves the session from a **sandbox**: balances look normal, transfers appear to succeed, nothing real moves, and every action is recorded as the **attacker-intent log** (recipients, amounts, order).
- **Who qualifies:** only when the evidence includes an *identity-change* signal (new device and network, or a large departure from the user's own baseline). Volume alone (request bursts, typing speed) never does. Decoy, poison and lockdown-level evidence are blocked as before and never enter shadow.
- **Safeguards:** every shadow session enters the review queue (**Active Sessions → Shadow queue**) with a deadline (`SHADOW_REVIEW_MINUTES`, default 30). *Release* restores the customer and shows them exactly which transfers did **not** execute (and learns the new device so they are not shadowed again); *Confirm attacker* freezes through the existing lockdown path; past the deadline it falls back to step-up. The shadow ledger is separate, so real balances and transactions never change.
- The attacker's browser is told nothing: the API masks the shadow state as an ordinary SAFE session. The console shows it (status SHADOW, a live banner) but it does not change the global status indicator.
- **Visible false-positive count:** the queue counts released sessions, and the Attack Lab has two scenarios: the thief on a new device with the owner's rhythm (*contained*) and the **real owner on a new laptop** (*false positive*, counted honestly).
- Flag: `SHADOW_MODE` (default on). Off restores the exact earlier step-up behaviour (the older IP-change test now asserts that with the flag off).
- Honest limit: a real customer wrongly shadowed briefly believes a transfer succeeded when it did not. The deadline, the clear release notice and the false-positive count exist to bound that harm.
- Demo: `python demo/shadow_demo.py`. Code: `backend/app/shadow.py`, `routers/shadow_routes.py`, tests `backend/tests/test_shadow.py`, UI `ShadowQueue.jsx`.

## UI track (experiments branch)
- **Direct navigation first.** Sidebar clicks, keys 1 to 7 and Ctrl+K now open a panel at once. The scenic camera flight is optional (**Scenic flight** toggle in the sidebar, remembered in the browser, off by default); the scroll-through journey and clickable stations still work.
- **Skippable intro.** *Skip intro* for this visit, **Always skip** to remember it (a *Replay intro* link then appears on the landing page), or add `?skip` to the address for a one-off.
- **Trust Field (3D).** The neural sphere now shows real data: one orbiting body per monitored session. *Active* = calm orbit (teal), *suspicious* = wobble (amber), *shadow* = ghost (violet), *locked* = leaves its orbit (red, larger). Blocked login campaigns appear as a swarm that converges into one shared ring. Hover a body for its name and state, click it to open that session in Active Sessions. The decorative satellites fade when real sessions exist. The global status now also follows real session state (not past events).
- Server times are now read as UTC, so "5h ago" no longer appears for things that just happened.

## Feature 3: CyberMind Network (experiments branch)
Independent CyberMind installs can warn each other about a blocked login campaign without sharing any customer data. A small **separate hub service** (`hub/`, its own database; see `hub/README.md`) exchanges only a **keyed hash** (HMAC) of the attacker's client fingerprint, reason codes and an expiry. The key (`NETWORK_HASH_KEY`) is shared by the members and never given to the hub, so the hub cannot reverse the hash.
- **Anti-poisoning:** the hub hands out an indicator only when at least `HUB_MIN_MEMBERS` (default 2) **distinct** members reported it; everything expires; an operator can **mute** an indicator and **remove** a member (their reports stop counting); members are rate-limited.
- **A hint, never a verdict:** a received indicator adds a few points (`NETWORK_SIGNAL_POINTS`, default 2) with a visible reason, `network_indicator` (naming how many installs agree). The sum is capped below the block line, so the network can tip a borderline pattern into *watching* but can never block anyone alone. Ordinary customers sharing a listed fingerprint are untouched.
- **Never slows logins:** receiving is a background refresh into a local cache and sharing is fire-and-forget; if the hub is down, logins are unaffected. The lab never uses or feeds the network.
- Flag: `NETWORK_ENABLED` (default off), plus `NETWORK_HUB_URL`, `NETWORK_MEMBER_ID`, `NETWORK_MEMBER_KEY`, `NETWORK_HASH_KEY`. `docker compose --profile network up` starts the hub. Console: Detections -> Campaigns shows the connection and received hints.
- Honest limits: a client fingerprint is not an identity, so it is only a hint; with two members a coordinated pair could still push one (raise `HUB_MIN_MEMBERS` in practice); anyone holding the hash key can test guesses against the hashes. It is a prototype of the idea behind shared threat intelligence (compare MISP, CrowdSec), not a hardened product. Verified in-process and with a real hub plus three separate backends over HTTP: two installs blocked the same fingerprint, the third received it and showed the `network_indicator` reason (borderline pattern went to *watching*, a different fingerprint got no hint, an honest login was allowed), an operator mute removed it, and with the hub stopped a login-attempt took about 0.02 s.
- Code: `backend/app/network.py`, `hub/app.py`, tests `backend/tests/test_network.py`.

## Feature 4: Adaptive Attack-Lab Evaluation (experiments branch)
The fixed Attack Lab scenarios ask "do we catch these attacks?". The **Adaptive stress test** (Attack Simulator -> Realistic attack lab, bottom card) asks "how much must an attacker change before one slips past?". A small genetic search tunes six attacker settings (number of tries, number of IPs, duration, browser fingerprint, share of breached passwords) against the real login guard in a throw-away database, rewarding harvested accounts and discounting slowness.
- **Robustness report:** how many variations were tried before one slipped through, the best evader and what it looked like, the attempts it needed per stolen account versus undefended, the rule that stopped most caught attacks but that the best evader stayed under, and false alarms on normal users.
- **Lab only:** separate in-memory database, no network traffic, never touches live data or the CyberMind Network. No switch is needed because it only runs when an admin presses the button (about a minute).
- First finding on the default settings: a slow, spread-out attack (a few hundred tries from about 10 IPs over 2 to 3 hours) peaks at score 5 against a block line of 6 and is never blocked. This is the same known limit as the "stealth, diluted" scenario, now found automatically.
- Honest limits: a six-knob parameter search, not a human adversary; login guard only (not sessions, phishing or the network); synthetic normal traffic; a clean result is evidence, not proof.
- Code: `backend/app/adaptive.py`, routes `/api/lab/adaptive/*`, UI `AdaptiveLab.jsx`, tests `backend/tests/test_adaptive.py`.
