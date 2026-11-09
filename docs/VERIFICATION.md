# Verification Record

Latest recorded validation for the current implementation:

## Backend

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
```

Result: **17 passed**, with one deprecation warning from the installed Starlette/AnyIO dependency.

Coverage includes authentication and role enforcement, settings audit behavior, honest failed-capture reporting, detection thresholds, PCAP upload/hash deduplication/flow/replay integration, legacy migration idempotence and data preservation, rule editing/history/custom-rule validation, and report exports.

## Frontend

```powershell
Set-Location frontend
npm run build
```

Result: **Vite production build succeeded**.

## Capture and data integrity notes

- The existing `.venv` and `data/alerts.sqlite3` are preserved.
- Startup applies additive, idempotent SQLite schema creation/column migrations; no destructive database reset is part of startup.
- The host does not expose a usable packet-capture provider, so successful live capture has not been verified. A failed start must remain a permission/provider failure, not a successful monitoring session.
- PCAP upload rejects files without PCAP/PCAPNG magic bytes and stores accepted files under the data directory, outside the frontend.
- Tests use temporary SQLite databases and synthetic traffic; they do not represent a live network capture or verify an installed Npcap driver.

## Not validated or incomplete

External threat-intelligence providers, GeoIP/ASN enrichment, advanced detection signatures, strict parser memory/process isolation, Npcap guided setup checks, container builds, and notification integrations are not complete and therefore are not claimed as verified.
