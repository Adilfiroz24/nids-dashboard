# Interaction Audit

## Scope
This audit covers the core dashboard interactions available in the current NIDS Monitor workspace. The project remains local-only and does not use simulated traffic for security claims; only real local data and verified backend responses are used.

## Interaction matrix

| Component | Expected behaviour | Backend endpoint | Actual result | Test status |
| --- | --- | --- | --- | --- |
| Sidebar navigation | Switches between Overview, Real-Time Monitor, Network Traffic, PCAP Analyzer, Security Alerts, Incident Management, Network Assets, Threat Intelligence, Detection Rules, Reports, System Health, Audit Logs, and Settings | Frontend state changes only | Changes page state and renders the selected module | Implemented and Tested |
| PCAP upload | Opens native file selector and submits selected file to the backend | POST /api/pcap | Validates extension and file size, then parses packets and stores alerts | Implemented and Tested |
| Refresh | Reloads data from the backend and updates KPI cards | GET /api/overview, /api/stats, /api/alerts, /api/traffic/flows | Updates current view from live database content | Implemented and Tested |
| Clear alerts | Deletes stored alert history | DELETE /api/alerts | Confirms before deletion and removes records from SQLite | Implemented and Tested |
| Alert detail | Opens selected alert details | GET /api/alerts | Renders evidence and metadata from the chosen record | Implemented and Tested |
| Alert filtering | Restricts alert list by search or status | GET /api/alerts | Filters by status and text in the backend query | Implemented and Tested |
| Incident creation | Creates incident from an alert | POST /api/incidents | Persists incident and links the source alert | Implemented and Tested |
| Settings save | Saves system preferences | POST /api/settings | Persists keys to SQLite settings table | Implemented and Tested |
| Live monitor start/stop | Starts or stops monitoring session | POST /api/monitor/start, POST /api/monitor/stop | Returns honest status when capture is unavailable or when Npcap permissions are missing | Implemented but Not Fully Tested |
| Rule toggling | Enables/disables detection rule | PATCH /api/rules/{id} | Persists rule state | Implemented and Tested |
| Export/report preview | Returns a report payload for the selected report type | GET /api/reports | Lists the selected records and summary data | Implemented and Tested |
| System health | Displays backend and dependency status | GET /api/system/health | Reports actual platform state and local configuration | Implemented and Tested |

## Notable restrictions
- Live packet capture on Windows requires valid Npcap or admin-capable packet capture support. If not available, the backend reports that live capture is not configured instead of faking a running session.
- Threat intelligence providers are intentionally left Not Configured unless API credentials are supplied via environment variables.
