# Sentinel NIDS

Sentinel NIDS is a local-first network monitoring and PCAP triage dashboard. It supports offline PCAP/PCAPNG analysis, persisted heuristic alerts, alert and incident workflows, rule configuration, reports, and optional live capture when a capture provider is installed and permitted.

Live capture status is based on the actual Scapy capture worker. If Npcap/libpcap or required privileges are unavailable, the application reports that condition; it does not simulate live traffic. Stored PCAPs can be replayed through the offline detection path and are labeled as replay data.

## Architecture

```text
Browser (React / Vite)
        | JSON API + bearer token
        v
FastAPI routers -- authentication / role checks
        |                 |
        v                 v
SQLite + PCAP archive   Detection and replay services
        ^                 |
        +------ alerts, flows, assets, incidents ------+
```

The SQLite database and archived uploads are stored under `backend/data` by default (or `NIDS_DATA_DIR` when configured). PCAP files are not stored in the frontend's served directory.

## Requirements

- Python 3.10+
- Node.js 18+
- Optional live capture: Npcap on Windows (or libpcap on supported platforms), a visible interface, and appropriate capture permissions

## Run on Windows

From the repository root, reuse the existing `.venv` if present:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. On first use, create the initial administrator through the setup screen; there is no default password. API documentation is available at <http://127.0.0.1:8000/docs>.

Set `NIDS_JWT_SECRET` to a persistent secret for sessions that must remain valid across backend restarts. Without it, a random process-local signing secret is used. Set `NIDS_FRONTEND_ORIGIN` to the exact browser origin when the UI is served elsewhere. `NIDS_DATA_DIR` changes the location of the SQLite database and capture archive.

## Core workflows

- Upload a PCAP/PCAPNG from the PCAP Analyzer. The API checks capture magic bytes, applies a 50 MB limit and per-client upload rate limit, archives the capture outside the frontend, and deduplicates identical content by SHA256.
- Inspect alerts, update their lifecycle, add notes, and manage incidents from their respective pages.
- Configure built-in rules and create custom JSON/YAML rule definitions as an administrator.
- Export alert, incident, and asset reports as PDF, CSV, or HTML with an optional date range.
- Select a stored PCAP from analysis history and start replay at a configurable speed. Replay data is labeled and does not imply live capture.
- Start live monitoring only when the host exposes a valid capture provider and the process has permission. Otherwise, the monitor reports the capture failure reason.

## Tests

Run backend tests with the existing environment:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

Build the frontend:

```powershell
Set-Location frontend
npm run build
```

The backend tests use isolated temporary databases and synthetic/documentation-range packets; they do not capture network traffic. See [docs/VERIFICATION.md](docs/VERIFICATION.md) for the latest recorded checks.

## Known limitations

- Detection is heuristic and currently covers a limited set of packet indicators; it is not a full signature engine or a substitute for a production NIDS.
- Live capture requires a valid provider and host permissions and has not been validated on this host.
- Replay is PCAP-driven and visibly labeled, but does not model every live-capture condition.
- Strict parser process isolation/memory limits, persistent distributed upload rate limiting, advanced detection rules, encrypted third-party threat-intelligence integration, guided capture diagnostics, and bundled demo PCAP generation are not yet implemented.
- Advanced per-page filtering/pagination, complete asset enrichment, notifications, syslog/CEF export, and container/CI packaging remain future work.

Do not treat heuristic alerts as proof of compromise. Validate findings against packet context and local policy.
