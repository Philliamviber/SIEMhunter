"""
GET /v1/events — paginated, filtered security events.

Filters (all optional, all parameterized):
  - start / end: ISO-8601 datetime bounds on TimeGenerated
  - hostname: HostName exact match
  - event_id: EventID (uint)
  - subject_user_name: SubjectUserName exact match
  - src_ip_addr: SrcIpAddr exact match
  - provenance_tag: ProvenanceTag exact match

Pagination:
  - limit (1–1000, default 100)
  - offset (>=0, default 0)

NOTE: security_events has NO anomaly_score column. AnomalyScore lives on
detection_hits. Event rows therefore do NOT include an AnomalyScore field.

Data source: siemhunter.security_events (local ClickHouse only).
Authentication: required (bearer token).
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from ..auth import verify_token
from ..clickhouse_client import get_client

log = structlog.get_logger(__name__)
router = APIRouter()

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 1000


# ── Response models ───────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    # Time and identity anchors
    TimeGenerated: str
    HostName: str
    EventID: int

    # Event metadata
    EventRecordID: str
    ChannelName: str
    ProviderName: str

    # Actor (subject)
    SubjectUserName: str
    SubjectUserSid: str
    SubjectDomainName: str

    # Target (user)
    TargetUserName: str
    TargetUserSid: str
    TargetDomainName: str

    # Authentication
    LogonType: int
    ServiceName: str

    # Process
    ProcessImagePath: str
    CommandLine: str
    ParentProcessImagePath: str
    ParentCommandLine: str
    GrantedAccess: str

    # File
    ObjectName: str
    FileMD5: str
    FileSHA256: str

    # Registry
    RegistryKey: str

    # Network
    SrcIpAddr: str
    SrcPort: int
    DstIpAddr: str
    DstPort: int
    NetworkProtocol: str

    # SIEMhunter pipeline fields
    ProvenanceTag: str
    IngestTimestamp: str

    # Unmapped catch-all (JSON string)
    UnmappedFields: str


class EventsResponse(BaseModel):
    events: list[SecurityEvent]
    total_count: int
    limit: int
    offset: int


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_iso(val) -> str:
    if val is None:
        return ""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.isoformat()
    return str(val)


def _parse_dt(value: Optional[str], param_name: str) -> Optional[datetime]:
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": f"Invalid datetime for {param_name}: {value!r}",
                "code": "INVALID_PARAM",
            },
        )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/events", response_model=EventsResponse)
async def list_events(
    start: Optional[str] = Query(default=None),
    end: Optional[str] = Query(default=None),
    hostname: Optional[str] = Query(default=None),
    event_id: Optional[int] = Query(default=None, ge=0),
    subject_user_name: Optional[str] = Query(default=None),
    src_ip_addr: Optional[str] = Query(default=None),
    provenance_tag: Optional[str] = Query(default=None),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(verify_token),
) -> EventsResponse:
    """Return paginated security events with optional filters."""

    start_dt = _parse_dt(start, "start")
    end_dt = _parse_dt(end, "end")

    where_clauses: list[str] = []
    params: dict = {}

    if start_dt is not None:
        where_clauses.append("TimeGenerated >= {start_dt:DateTime64(3)}")
        params["start_dt"] = start_dt

    if end_dt is not None:
        where_clauses.append("TimeGenerated <= {end_dt:DateTime64(3)}")
        params["end_dt"] = end_dt

    if hostname is not None:
        where_clauses.append("HostName = {hostname:String}")
        params["hostname"] = hostname

    if event_id is not None:
        where_clauses.append("EventID = {event_id:UInt32}")
        params["event_id"] = event_id

    if subject_user_name is not None:
        where_clauses.append("SubjectUserName = {subject_user_name:String}")
        params["subject_user_name"] = subject_user_name

    if src_ip_addr is not None:
        where_clauses.append("SrcIpAddr = {src_ip_addr:String}")
        params["src_ip_addr"] = src_ip_addr

    if provenance_tag is not None:
        where_clauses.append("ProvenanceTag = {provenance_tag:String}")
        params["provenance_tag"] = provenance_tag

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    try:
        client = get_client()

        # Total count
        count_rows = client.query(
            f"SELECT count() FROM siemhunter.security_events {where_sql}",
            parameters=params,
        ).result_rows
        total_count = int(count_rows[0][0]) if count_rows else 0

        # Paginated rows — select every column from schema.sql in declared order
        params_page = dict(params)
        params_page["_limit"] = limit
        params_page["_offset"] = offset

        evt_rows = client.query(
            f"""
            SELECT
                TimeGenerated, HostName, EventID,
                EventRecordID, ChannelName, ProviderName,
                SubjectUserName, SubjectUserSid, SubjectDomainName,
                TargetUserName, TargetUserSid, TargetDomainName,
                LogonType, ServiceName,
                ProcessImagePath, CommandLine, ParentProcessImagePath,
                ParentCommandLine, GrantedAccess,
                ObjectName, FileMD5, FileSHA256,
                RegistryKey,
                SrcIpAddr, SrcPort, DstIpAddr, DstPort, NetworkProtocol,
                ProvenanceTag, IngestTimestamp,
                UnmappedFields
            FROM siemhunter.security_events
            {where_sql}
            ORDER BY TimeGenerated DESC
            LIMIT {{_limit:UInt32}}
            OFFSET {{_offset:UInt32}}
            """,
            parameters=params_page,
        ).result_rows

        events = [
            SecurityEvent(
                TimeGenerated=_to_iso(r[0]),
                HostName=str(r[1]),
                EventID=int(r[2]),
                EventRecordID=str(r[3]),
                ChannelName=str(r[4]),
                ProviderName=str(r[5]),
                SubjectUserName=str(r[6]),
                SubjectUserSid=str(r[7]),
                SubjectDomainName=str(r[8]),
                TargetUserName=str(r[9]),
                TargetUserSid=str(r[10]),
                TargetDomainName=str(r[11]),
                LogonType=int(r[12]),
                ServiceName=str(r[13]),
                ProcessImagePath=str(r[14]),
                CommandLine=str(r[15]),
                ParentProcessImagePath=str(r[16]),
                ParentCommandLine=str(r[17]),
                GrantedAccess=str(r[18]),
                ObjectName=str(r[19]),
                FileMD5=str(r[20]),
                FileSHA256=str(r[21]),
                RegistryKey=str(r[22]),
                SrcIpAddr=str(r[23]),
                SrcPort=int(r[24]),
                DstIpAddr=str(r[25]),
                DstPort=int(r[26]),
                NetworkProtocol=str(r[27]),
                ProvenanceTag=str(r[28]),
                IngestTimestamp=_to_iso(r[29]),
                UnmappedFields=str(r[30]),
            )
            for r in evt_rows
        ]

    except HTTPException:
        raise
    except Exception as exc:
        log.error("events_query_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ClickHouse query failed", "code": "QUERY_ERROR"},
        )

    return EventsResponse(
        events=events,
        total_count=total_count,
        limit=limit,
        offset=offset,
    )
