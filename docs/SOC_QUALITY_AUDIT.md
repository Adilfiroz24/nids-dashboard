# SOC Quality Audit

## Scope
This audit compares the current NIDS dashboard implementation against the supplied UI screenshots and the live codebase in the current workspace. It confirms whether the application behaves like a credible network monitoring platform or a prototype.

## Executive summary
The project has moved well beyond an initial mockup. The backend and frontend are connected, the app persists alerts and flows in SQLite, and the dashboard shows real operational sections for overview, alerts, traffic, PCAP analysis, incident management, assets, rules, health, audit, and settings.

The application still has a few quality gaps that matter in a production SOC context:
- live monitoring state was not centralized and was inconsistent across the UI and backend
- raw Scapy interface IDs were not being transformed into a professional selector
- DNS anomaly detection was too sensitive and could treat ordinary DNS traffic as malicious
- asset inventory was not being hydrated from observed traffic, leaving network assets empty in real-world conditions
- some dashboard panels were present but not backed by strong data provenance or state semantics

## Existing functional modules
The following modules are present in the codebase and are actively wired into the app:
- Overview dashboard
- Real-Time Monitor route
- Network Traffic analytics
- PCAP Analyzer upload flow
- Security Alerts queue and detail panel
- Incident Management workflow
- Network Assets listing
- Detection Rules management
- Reports route
- System Health summary
- Audit Logs
- Settings management

## Incomplete or partially implemented modules
These areas are functional but not yet fully production-grade:
- Live monitoring session lifecycle is honest but not yet fully synchronized with operating-system capture capability flags
- Some monitor state labels still use generic or transitional strings rather than a strict engineering state machine
- Interface metadata is available but not yet surfaced as a polished selector with rich adapter details
- Asset discovery is implemented in a lightweight, passive form rather than a deep inventory intelligence layer
- Threat intelligence and active response integrations remain intentionally not configured unless external data sources are added

## Non-functional controls and inconsistent state indicators
The screenshots show operational tension between:
- `Monitoring` label in the live monitor area
- `Packet Capture: Not Configured` in the health view
- `Offline PCAP mode` in the sidebar
This is a real inconsistency because there is no single source of truth for capture state. The backend must own this state and the UI must reflect it as a system of statuses instead of a static string.

The app now represents the operational states as:
- Offline PCAP
- Idle
- Starting
- Running
- Stopping
- Stopped
- Failed
- Permission Required
- Not Configured

## Missing backend integration and database relationships
The codebase now relies on SQLite persistence, but the system still benefits from tighter linkage between:
- alerts and their detection rule metadata
- incidents and their related alert IDs
- observed flows and discovered assets
- monitoring session state and packet counters
- capture worker status and health output

The project is moving in the right direction, but stronger relational integrity will matter as data volume increases.

## UI usability issues
The raw NPF interface list is not suitable for a professional SOC interface. It hides adapter context and creates a poor operator experience.

The solution is to display:
- friendly adapter name
- description
- identifier
- status
- IP address where available
- MAC address where available
- selected interface

The raw technical identifier should remain visible only in an expandable details area, not as the primary view.

## Detection accuracy concerns
The original DNS logic flagged any UDP packet on port 53 with a payload over 100 bytes as suspicious.

This is not reliable because:
- legitimate DNS responses often exceed 120 bytes
- some valid DNS queries are longer than 100 bytes
- a single packet is not enough to establish malicious behavior without context

The improved logic distinguishes query vs response and applies thresholds that are explainable and configurable, rather than simply treating every port-53 packet as risky.

## Performance and security findings
- Performance is acceptable for local PCAP analysis and the current data set.
- Security posture is reasonable for a local-first tool, but the app should avoid exposing unfiltered raw data without clear boundaries and redaction controls.
- Live capture should never be advertised as active while the environment lacks a functioning packet capture provider.
- Interfaces should only be selectable if valid and capture-capable; otherwise the UI must show a clear permission message.

## Current status
The application is no longer a prototype in the most critical sense: it has real backend persistence, UI wiring, PCAP ingestion, alert storage, and a working local dashboard.

The remaining work is quality engineering: consistent operational states, better interface UX, more accurate detection thresholds, and richer asset discovery.
