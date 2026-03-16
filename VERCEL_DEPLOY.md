# Deploying This Project with Vercel

## Short answer

This repository is **not fully Vercel-compatible in its current form**.

You can host a web UI on Vercel, but the full system also needs:

- a **persistent TCP server** for agents
- a **persistent database**
- a host with a **stable public IP or hostname** for agent connections

## Why the current repo does not fit Vercel directly

These files show the main blockers:

- `frontend/app.py`
  - mixes the Flask UI with backend logic
  - writes to SQLite at startup
  - can start the master server thread locally
- `backend/network/tcp_server.py`
  - binds a raw TCP socket on port `5000`
  - runs forever waiting for agent connections
- `shared/persistence.py`
  - stores app state in a local SQLite file
- `client-agent/config.py`
  - expects agents to connect to a reachable `MASTER_IP:MASTER_PORT`

Vercel Functions are serverless and scale down when idle. They are not a good fit for a process that must keep a TCP listener alive, and Vercel does not support SQLite as durable server storage.

## Best practical architecture

### Recommended

- **Vercel**
  - host the admin web UI only
  - optionally host stateless HTTP endpoints
- **Railway / Render / Fly.io / VPS**
  - host the persistent Python backend master server
  - expose TCP port `5000`
- **Managed database**
  - use Postgres (for example Neon, Supabase, Railway Postgres)
  - replace SQLite usage in both Flask/SQLAlchemy and `shared/persistence.py`

## Fastest path to get the project online

If your goal is to make the current project work with the least refactoring, use:

- **Render / Railway / Fly.io / a VPS** for the full stack
- not Vercel for the whole system

That path matches the current architecture much better because your app depends on long-running TCP networking.

## If you still want to use Vercel

You will need to split the system into two parts.

### Part 1: Vercel app

Deploy only the admin website and stateless HTTP layer to Vercel.

Requirements:

- remove local SQLite dependency
- move state to managed Postgres
- keep HTTP routes stateless
- do **not** run `start_master()` on Vercel

Suggested environment values for the Vercel side:

- `START_MASTER_WITH_UI=0`
- `SECRET_KEY=<strong-random-value>`
- `SQLALCHEMY_DATABASE_URI=<managed postgres url>`

### Part 2: Persistent backend host

Deploy the master TCP server somewhere else.

Requirements:

- public hostname or static IP
- TCP port `5000` open
- same shared database as the web app

Suggested environment values for the backend side:

- `MASTER_PORT=5000`
- `APP_DB_PATH` should be replaced by managed DB logic instead of SQLite

### Part 3: Client agents

Point the agents at the real backend and web config URL.

Example values:

- `MASTER_IP=<public backend hostname>`
- `MASTER_PORT=5000`
- `FRONTEND_CONFIG_URL=https://<your-vercel-project>.vercel.app`

## Minimum code refactor needed before Vercel

1. Move all TCP server responsibilities out of `frontend/app.py`.
2. Replace SQLite usage in:
   - `frontend/app.py`
   - `frontend/models.py`
   - `shared/persistence.py`
3. Make the web app talk to shared persistent storage only.
4. Keep agent socket handling on a non-Vercel host.
5. Update `client-agent/config.py` to use deployed hostnames instead of LAN IPs.

## Suggested next move

If you want the system working soon, deploy the current stack on **Render/Railway/VPS**.

If you specifically need **Vercel**, the next development task should be:

**split the Flask admin UI from the long-running TCP master backend**

That will make a Vercel deployment possible for the UI layer while keeping the agent network reliable.
