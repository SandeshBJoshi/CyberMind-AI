# CYBERMIND AI Threat Detection System - Project Handoff

Last updated: 2026-09-22

## Current project location

The up-to-date project folder is:

`C:\Users\Asus\Downloads\threat-detection-system`

Open this folder as the workspace. The current project files are inside this folder, especially:

- `backend/` - FastAPI backend, security rules, ML engine, database models, WebSocket flow, and tests.
- `frontend/` - React/Vite admin console and VaultApp user portal.
- `database/` - database schema reference.
- `README.md` - general setup and CyberMind Intel documentation.

This workspace currently has no `.git` directory, so there is no branch or commit history available for comparison.

## What the project does

CYBERMIND AI is a real-time threat detection, behavioral monitoring, and automated lockdown application.

- FastAPI backend on port `8000`.
- React/Vite frontend on port `5173`.
- JWT-protected admin login.
- User sessions for the VaultApp portal.
- Behavioral telemetry processing.
- Deterministic security rules plus Isolation Forest ML detection.
- Security event persistence in the security database.
- Real-time admin notifications through `WS /ws/live`.
- Automatic session lockdown and admin unlock.
- Security logs and monitored sessions views.
- CyberMind Intel as an authenticated intelligence feature with an isolated Chroma vector store.

## Recent completed work

### API Request Attack activity

The existing `API Request Attack` / `T1499 API Burst` activity now:

- Sends real authenticated `POST /user/behavior` requests.
- Sends each request as an `api_call` event for the selected active session.
- Includes the configured endpoint, source IP, device information, and attack technique metadata.
- Displays every request in the Attacker Console with method, endpoint, timestamp, and response status.
- Shows live request count, completion count, and request rate.
- Defaults to 75 requests so a fresh session exceeds the default 60-request burst threshold.
- Uses the existing rule engine, security-event flow, WebSocket broadcast, and lockdown flow.

Relevant files:

- `frontend/src/api.js`
- `frontend/src/components/AttackerConsole.jsx`
- `frontend/src/index.css`

### Lockdown and unlock consistency

The project was fixed so concurrent telemetry cannot restore a locked session to active.

- Session status transitions use conditional database updates.
- An already committed lockdown is preserved when concurrent requests finish later.
- Open `LockdownRecord` rows are used to reconcile stale session status.
- Admin Sessions recognizes both internal `locked` and public `LOCKDOWN` labels.
- Admin unlock accepts a session with an open lockdown record even if its session status was stale.
- User Portal status also reports `LOCKDOWN` when an open lockdown record exists.

Relevant files:

- `backend/app/routers/events_routes.py`
- `backend/app/routers/user_routes.py`
- `backend/app/routers/lockdown_routes.py`
- `frontend/src/components/SessionsPanel.jsx`

### Refresh behavior

- The admin console persists the selected navigation view in `localStorage` using `sentinel_view`.
- Refreshing the admin page restores the last selected view instead of always returning to Dashboard.
- VaultApp fetches its authoritative status immediately on load.
- VaultApp keeps polling status every 3 seconds even while locked, so an admin unlock is reflected in the portal.
- Telemetry pauses during lockdown, but status polling continues.

Relevant files:

- `frontend/src/App.jsx`
- `frontend/src/components/UserPortal.jsx`

## Current runtime URLs

- Admin frontend: `http://127.0.0.1:5173/`
- User portal direct URL: `http://127.0.0.1:5173/#user-portal`
- Backend health check: `http://127.0.0.1:8000/health`
- Backend API documentation: `http://127.0.0.1:8000/docs`
- Live WebSocket: `ws://127.0.0.1:8000/ws/live`

The backend health check was verified as `ok`, and the frontend returned HTTP 200 during the latest run.

## How to run

From the project root, start the backend in one PowerShell terminal:

```powershell
cd C:\Users\Asus\Downloads\threat-detection-system\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

Start the frontend in a second PowerShell terminal:

```powershell
cd C:\Users\Asus\Downloads\threat-detection-system\frontend
npm run dev -- --host 127.0.0.1
```

## How to test the main lockdown flow

1. Open `http://127.0.0.1:5173/` and log in as the configured admin.
2. Open `http://127.0.0.1:5173/#user-portal` in a separate browser tab.
3. Create a VaultApp session and keep that tab visible.
4. In the admin tab, open **Attacker Terminal**.
5. Select the VaultApp session.
6. Open **T1499 API Burst** and fire the request burst.
7. Confirm the Attacker Console lists every API request and shows its live rate.
8. Confirm the User Portal changes to `LOCKED`.
9. In the admin console, open **Sessions**.
10. Confirm the same session shows `LOCKDOWN` and an **Unlock** button.
11. Click **Unlock**.
12. Confirm the Sessions row returns to `active` and the VaultApp status changes to `SAFE` within a few seconds.
13. Refresh both pages and confirm the admin view and VaultApp session state remain consistent.

## Validation completed

The following checks passed after the latest changes:

```powershell
cd backend
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Result: 2 existing backend tests passed.

```powershell
cd frontend
npm run build
```

Result: Vite production build passed.

Editor diagnostics passed for the files changed in the latest fixes.

## Important existing behavior

- The default request-burst limit is 60 events within 1 minute. This is configured in `backend/app/config.py`.
- The `request_burst` rule has weight `2.5`, so API burst alone may produce `SUSPICIOUS` depending on the total risk score. Other existing rules or ML anomaly signals can raise the session to full `LOCKDOWN`.
- Admin unlock requires the JWT admin session and uses `POST /api/lockdown/unlock`.
- The User Portal intentionally does not require admin login.
- Do not remove or bypass the existing ML engine, decision engine, WebSocket manager, or admin authentication when making further changes.

## Best next context for another agent

Start by reading this file, then inspect:

1. `frontend/src/App.jsx`
2. `frontend/src/components/UserPortal.jsx`
3. `frontend/src/components/AttackerConsole.jsx`
4. `frontend/src/components/SessionsPanel.jsx`
5. `frontend/src/api.js`
6. `backend/app/routers/events_routes.py`
7. `backend/app/routers/user_routes.py`
8. `backend/app/routers/lockdown_routes.py`
9. `backend/app/rule_engine.py`
10. `backend/app/decision_engine.py`
