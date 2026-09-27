"""
DFIR Workbench V2 - Timeline Engine
Builds chronological forensic timelines with strict provenance,
never asserts unbacked process terminations, and flags inferred events.
"""

from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime

from backend.models.timeline import TimelineEvent
from backend.models.artifact import Artifact
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("forensic")


class TimelineEngine:
    """Consolidates process creation/exit, network activity, detections, and artifact events

    into a strictly verified forensic timeline.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    def generate_timeline(self, arg1: str, arg2: Optional[str] = None) -> List[TimelineEvent]:
        evidence_id = arg2 if arg2 is not None else arg1
        events: List[TimelineEvent] = []
        ev = self.db.get_evidence(evidence_id)
        cid = ev.case_id if ev else (arg1 if arg2 is not None else "")

        # Clear existing timeline events for this evidence to prevent duplicates
        self.db.clear_events(evidence_id)

        # 1. Process timestamps
        processes = self.db.list_processes(evidence_id)
        for p in processes:
            proc_source = "windows.pslist.PsList" if p.in_pslist else "windows.psscan.PsScan"
            # Process Creation
            if p.create_time and p.create_time.strip() and p.create_time.lower() != "n/a":
                events.append(TimelineEvent(
                    id=str(uuid.uuid4()),
                    evidence_id=evidence_id,
                    case_id=cid,
                    timestamp=p.create_time.strip(),
                    event_type="Process Create",
                    description=f"Process created: {p.name} (PID: {p.pid}, PPID: {p.ppid})",
                    pid=p.pid,
                    process_name=p.name,
                    source_plugin=proc_source,
                    severity="High" if p.risk_score >= 70 else ("Medium" if p.risk_score >= 40 else "Low"),
                    details=f"Command line: {p.command_line or 'N/A'}",
                    confidence="High",
                    inferred=False
                ))

            # Process Termination - ONLY if exit_time is explicitly present and non-empty
            if p.exit_time and p.exit_time.strip() and p.exit_time.lower() not in ("n/a", "none", ""):
                events.append(TimelineEvent(
                    id=str(uuid.uuid4()),
                    evidence_id=evidence_id,
                    case_id=cid,
                    timestamp=p.exit_time.strip(),
                    event_type="Process Exit",
                    description=f"Process terminated: {p.name} (PID: {p.pid})",
                    pid=p.pid,
                    process_name=p.name,
                    source_plugin=proc_source,
                    severity="Low",
                    details=f"Exit time recorded by operating system EPROCESS block",
                    confidence="High",
                    inferred=False
                ))

        # 2. Network timestamps
        connections = self.db.list_connections(evidence_id)
        for c in connections:
            if c.created_time and c.created_time.strip() and c.created_time.lower() != "n/a":
                is_ext = c.scope == "External" or not str(c.remote_addr).startswith(("10.", "192.168.", "172.16.", "127.", "0.", "::", "*"))
                events.append(TimelineEvent(
                    id=str(uuid.uuid4()),
                    evidence_id=evidence_id,
                    case_id=cid,
                    timestamp=c.created_time.strip(),
                    event_type="Network Socket",
                    description=f"Socket {c.protocol} {c.local_addr}:{c.local_port} -> {c.remote_addr}:{c.remote_port} ({c.state})",
                    pid=c.pid,
                    process_name=c.process_name,
                    source_plugin="windows.netscan.NetScan",
                    severity="Medium" if is_ext else "Low",
                    details=f"Owner: {c.owner or 'N/A'}. Scope: {'External' if is_ext else 'Internal'}",
                    confidence="High",
                    inferred=False
                ))

        # 3. Detections as timeline events
        detections = self.db.list_detections(evidence_id=evidence_id)
        for d in detections:
            events.append(TimelineEvent(
                id=str(uuid.uuid4()),
                evidence_id=evidence_id,
                case_id=cid,
                timestamp=d.created_at,
                event_type="Detection",
                description=f"Detection [{d.rule_id}]: {d.rule_name} on {d.affected_entity}",
                pid=0,
                process_name=d.affected_entity,
                source_plugin="DetectionEngine",
                severity=d.severity,
                details=d.explanation,
                confidence=d.confidence,
                inferred=True
            ))

        # Sort chronologically
        events.sort(key=lambda x: x.timestamp or "")

        # Save to DB in bulk
        if events:
            self.db.create_events_bulk(events)

        logger.info(f"Timeline populated with {len(events)} events for evidence {evidence_id}")
        return events

    def list_events(self, evidence_id: Optional[str] = None, case_id: Optional[str] = None) -> List[TimelineEvent]:
        return self.db.list_events(evidence_id=evidence_id, case_id=case_id)

    def get_events(self, evidence_id: Optional[str] = None, filter_type: str = "ALL", search_query: str = "") -> List[TimelineEvent]:
        events = self.db.list_events(evidence_id=evidence_id)
        if filter_type and filter_type.upper() != "ALL":
            events = [
                e for e in events
                if (e.event_type and e.event_type.lower() == filter_type.lower())
                or (e.severity and e.severity.lower() == filter_type.lower())
            ]
        if search_query:
            sq = search_query.lower()
            events = [
                e for e in events
                if sq in (e.description or "").lower() or sq in (e.process_name or "").lower()
            ]
        return events
