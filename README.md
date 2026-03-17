# CodeSweep

## Project Description
### Problem Statement
Managing unauthorized, unsafe, or outdated code files across many lab machines is difficult when done manually. Administrators need a centralized and auditable way to detect, quarantine, review, and remove code files from distributed endpoints.

### Objectives
- Provide centralized scan-task dispatch to distributed lab agents.
- Detect code files across multiple languages using pattern-based analysis.
- Quarantine suspected files before permanent deletion.
- Add a human verification step (approve/reject) before deletion.
- Maintain audit and deletion logs for traceability.

### Target Users
- University/school lab administrators
- IT operations teams managing shared lab environments
- Security/compliance teams needing controlled cleanup workflows

### Overview
CodeSweep is an agent-based file governance system with:
- A backend TCP master server for agent orchestration
- A Flask admin frontend for task submission and verification
- Lightweight client agents that scan, detect, quarantine, and report
- Shared persistence for agent status, pending files, and audit trails (PostgreSQL recommended; SQLite supported for local fallback)

## System Architecture / Design
### Components
- `frontend` (Flask Admin UI + REST endpoints)
- `backend` (master TCP server + connection handlers + orchestrator)
- `client-agent` (scanner, detector, quarantine manager, TCP client)
- `shared` (DB persistence and shared schemas/constants)

### High-Level Workflow
1. Admin selects target languages, scan path, and optional date filter in dashboard.
2. Frontend creates a `scan_task` and dispatches it to online agents.
3. Agent scans files, detects language/confidence, and quarantines matched files.
4. Agent sends scan results to master; results are stored as pending verification.
5. Admin reviews pending files in verification page and approves/rejects.
6. Approved deletion commands are sent/queued to agents.
7. Agents delete quarantined files and send deletion reports.
8. System records audit logs and updates pending/deleted state.

### Architecture Diagram
```mermaid
flowchart LR
    A[Admin Browser] --> B[Frontend Flask App]
    B --> C[(PostgreSQL / SQLite)]
    B --> D[Backend TCP Master]
    D <--> E[Client Agent 1]
    D <--> F[Client Agent 2]
    D <--> G[Client Agent N]
    E --> H[Scanner + Detector + Quarantine]
    F --> H
    G --> H
```

## Technologies Used
- Programming Languages: Python, HTML, CSS, JavaScript
- Backend Frameworks/Libraries: Flask, Flask-SQLAlchemy, WTForms
- Database: PostgreSQL (recommended), SQLite (local fallback)
- Networking: TCP sockets (custom protocol)
- Frontend UI: Bootstrap 5, Font Awesome
- Deployment/Tooling: Docker, Docker Compose
- Version Control: Git

## Installation Instructions
### Requirements
- Python 3.9+
- pip
- Docker + Docker Compose (optional, recommended)

### Option A: Run with Docker Compose
From `project/`:
```bash
docker compose up --build
```

Default ports:
- Backend TCP master: `5000`
- Frontend web UI: `5001` (mapped to container `5000`)

### Option B: Run Locally (without Docker)
Open separate terminals:

1. Backend
```bash
cd project/backend
pip install -r requirements.txt
python main.py
```

2. Frontend
```bash
cd project/frontend
pip install -r requirements.txt
python app.py
```

3. Client Agent (one or more)
```bash
cd project/client-agent
pip install -r requirements.txt
python agent.py
```

Environment variables commonly used:
- `MASTER_IP` / `BACKEND_HOST`
- `MASTER_PORT` / `BACKEND_PORT`
- `SCAN_DIRS` (comma-separated directories)
- `QUARANTINE_DIR`
- `LOG_DIR`
- `APP_DATABASE_URL` (recommended shared DB URL for frontend + backend persistence)
  - Example PostgreSQL: `postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME`
- `APP_DB_PATH` (optional SQLite fallback path)

## Usage Instructions
1. Open dashboard at `http://localhost:5001/`.
2. In **File Scan Task**:
   - Select one or more target languages.
   - Enter absolute folder path to scan.
   - Optionally set modified date range.
3. Submit scan task.
4. Open **Verification** page to review pending files.
5. Approve or reject deletions.
6. Monitor logs and audit trail via UI endpoints.

### Example Scan Input (API)
```json
{
  "target_languages": ["python", "java", "javascript"],
  "scan_path": "/home/lab/shared",
  "date_filter": {
    "start": "2026-03-01T00:00:00",
    "end": "2026-03-17T23:59:59"
  }
}
```

### Example Response
```json
{
  "message": "Instruction dispatched to 3 agent(s)",
  "task_id": "17032026-1",
  "target_languages": ["python", "java", "javascript"],
  "scan_path": "/home/lab/shared",
  "date_filter": {
    "start": "2026-03-01T00:00:00",
    "end": "2026-03-17T23:59:59"
  },
  "failed_agents": []
}
```

## Dataset
No external ML dataset is required for core operation.

- Detection is rule/pattern-based (regex + keyword/signature heuristics).
- Input data consists of files scanned on managed machines.

If you add benchmark datasets later, document:
- Source URL
- License
- Usage limitations

## Project Structure
```text
project/
├── backend/            # TCP master server, network handlers, orchestrator
├── client-agent/       # File scanner, detector, quarantine, TCP client
├── frontend/           # Flask web UI + admin API
├── shared/             # Shared DB persistence, constants, schemas
├── website/            # Static informational website
├── docker-compose.yml  # Multi-service orchestration
└── README.md           # This file
```

## Screenshots / Demo
Add screenshots and demo links here:
- Dashboard: `docs/screenshots/dashboard.png`
- submit-task-success: `docs/screenshots/dashboard.png`
- agent-layout: `docs/screenshots/verification.png`
- verification: `docs/screenshots/agent-layout.png`


## Contributors
- **Ms. J. Varsha**  
  Reg No: 2021/CSC/080  
  Email: varshajeyaraj@gmail.com  
  Led the overall system design and development. Implemented core backend components including task processing, agent coordination logic, database integration, and system orchestration.

- **Mr. K.A.T. Saranga**  
  Reg No: 2021/CSC/027  
  Email: tharakasaranga755@gmail.com  
  Designed and implemented the administrative web interface using HTML, CSS, JavaScript, Jinja2 templates, and Bootstrap for responsive UI. Also helped with validating regex.

- **Mr. K.G.H.M.Wijesekara**  
  Reg No: 2021/CSC/030  
  Email: hasitha.m.wijesekara@gmail.com  
  Developed frontend components and user interface features for the administrative dashboard, ensuring usability and integration with backend APIs. Also helped with validating regex.

- **Ms. S. Kujinsika**  
  Reg No: 2021/CSC/034  
  Email: kujinsikasivaneswaran@gmail.com  
  Conducted manual integration and system testing, validation of agent communication and file operations, and assisted in identifying and resolving integration issues.

- **Ms. P. Mathuja**  
  Reg No: 2021/CSC/088  
  Email: mathujaparameshwaran@gmail.com  
  Developed the master server backend logic, implemented task distribution mechanisms, and configured containerised deployment using Docker and Docker Compose.

## Contact Information
- Team Lead: Ms. J. Varsha
- Email: varshajeyaraj@gmail.com
- Institution: Department of Computer Science (replace with official institution name if needed)

## Licence
This project is released under the **MIT License**.

Add a `LICENSE` file at the repository root with MIT terms if not already present.
