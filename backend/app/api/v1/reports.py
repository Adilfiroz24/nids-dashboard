from __future__ import annotations

import csv
import html
import io
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.core.auth import get_current_user
from app.db.session import connect, fetch_rules

router = APIRouter(tags=["reports"], dependencies=[Depends(get_current_user)])

REPORT_TABLES = {
    "alerts": ("alerts", "timestamp"),
    "incidents": ("incidents", "created_at"),
    "assets": ("assets", "last_seen"),
}


def _parse_range(start: str | None, end: str | None) -> tuple[str | None, str | None]:
    def parse(value: str | None, label: str) -> datetime | None:
        if value is None:
            return None
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"{label} must be an ISO-8601 datetime") from exc
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)

    start_date = parse(start, "start")
    end_date = parse(end, "end")
    if start_date and end_date and start_date > end_date:
        raise HTTPException(status_code=400, detail="start must be earlier than or equal to end")
    return (
        start_date.isoformat() if start_date else None,
        end_date.isoformat() if end_date else None,
    )


def _report_records(report_type: str, start: str | None, end: str | None) -> list[dict[str, Any]]:
    table, timestamp_column = REPORT_TABLES[report_type]
    clauses: list[str] = []
    params: list[str] = []
    if start:
        clauses.append(f"{timestamp_column} >= ?")
        params.append(start)
    if end:
        clauses.append(f"{timestamp_column} <= ?")
        params.append(end)
    where_clause = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as db:
        rows = db.execute(
            f"SELECT * FROM {table}{where_clause} ORDER BY id DESC LIMIT 10000",
            params,
        ).fetchall()
    return [dict(row) for row in rows]


@router.get("/reports/summary")
def report_summary(start: str | None = None, end: str | None = None) -> dict[str, Any]:
    start, end = _parse_range(start, end)
    clauses: list[str] = []
    params: list[str] = []
    if start:
        clauses.append("timestamp >= ?")
        params.append(start)
    if end:
        clauses.append("timestamp <= ?")
        params.append(end)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as db:
        total = db.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]
        by_severity = {
            row[0]: row[1]
            for row in db.execute(f"SELECT severity, COUNT(*) FROM alerts{where} GROUP BY severity", params)
        }
        latest = db.execute(
            f"SELECT timestamp, title, severity FROM alerts{where} ORDER BY id DESC LIMIT 1",
            params,
        ).fetchone()
    return {
        "total_alerts": total,
        "severity_breakdown": by_severity,
        "latest_event": {
            "timestamp": latest[0],
            "title": latest[1],
            "severity": latest[2],
        }
        if latest
        else None,
    }


@router.get("/reports")
def generate_report(
    report_type: str = Query("summary"),
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    start, end = _parse_range(start, end)
    if report_type == "alerts":
        return {"report_type": "alerts", "records": _report_records("alerts", start, end)}
    if report_type == "incidents":
        return {"report_type": "incidents", "records": _report_records("incidents", start, end)}
    if report_type == "rules":
        return {"report_type": "rules", "records": fetch_rules()}
    if report_type == "assets":
        return {"report_type": "assets", "records": _report_records("assets", start, end)}
    return {"report_type": report_type, "records": report_summary(start, end)}


@router.get("/reports/export")
def export_report(
    report_type: str = Query("alerts", pattern="^(alerts|incidents|assets)$"),
    format: str = Query("csv", pattern="^(csv|html|pdf)$"),
    start: str | None = None,
    end: str | None = None,
) -> Response:
    start, end = _parse_range(start, end)
    rows = _report_records(report_type, start, end)

    if format == "csv":
        stream = io.StringIO(newline="")
        fieldnames = list(rows[0].keys()) if rows else ["message"]
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        if rows:
            writer.writerows(rows)
        else:
            writer.writerow({"message": "No records matched the selected period"})
        return Response(stream.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="nids-{report_type}.csv"'})

    if format == "html":
        headers = "".join(f"<th>{html.escape(str(key))}</th>" for key in (rows[0].keys() if rows else ["message"]))
        body_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row.values()) + "</tr>"
            for row in rows
        ) or "<tr><td>No records matched the selected period</td></tr>"
        document = f"<!doctype html><meta charset='utf-8'><title>NIDS {report_type.title()} Report</title><h1>NIDS {report_type.title()} Report</h1><p>Records: {len(rows)}</p><table border='1'><thead><tr>{headers}</tr></thead><tbody>{body_rows}</tbody></table>"
        return Response(document, media_type="text/html; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="nids-{report_type}.html"'})

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50
    pdf.setTitle(f"NIDS {report_type.title()} report")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, f"NIDS {report_type.title()} Report")
    y -= 24
    pdf.setFont("Helvetica", 9)
    pdf.drawString(40, y, f"Records: {len(rows)} | Range: {start or 'all time'} to {end or 'now'}")
    y -= 22
    for row in rows:
        line = " | ".join(f"{key}: {value}" for key, value in row.items())
        while line:
            pdf.drawString(40, y, line[:120])
            line = line[120:]
            y -= 13
            if y < 45:
                pdf.showPage()
                pdf.setFont("Helvetica", 9)
                y = height - 45
        y -= 6
        if y < 45:
            pdf.showPage()
            pdf.setFont("Helvetica", 9)
            y = height - 45
    pdf.save()
    return Response(buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="nids-{report_type}.pdf"'})
