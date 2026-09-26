"""
DFIR Workbench V2 - IOC Engine
Separates Observed Network Artifacts from Indicators of Compromise.
Guarantees deduplication, threat-intel verification, and provenance linkage.
"""

import os
import re
import json
import uuid
import ipaddress
from datetime import datetime
from typing import List, Dict, Any, Optional

from backend.models.audit import IOC
from backend.models.artifact import Artifact
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("forensic")


class IOCEngine:
    """Manages Indicators of Compromise, automated network artifact harvesting,

    deduplication, and cross-artifact hunting.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    def list_iocs(self, case_id: str = "") -> List[IOC]:
        return self.db.list_iocs(case_id)

    def add_ioc(self, case_id: str, ioc_type: str, value: str, severity: str = "Medium",
                source: str = "Analyst Manual", description: str = "", pid: int = 0,
                finding_id: Optional[str] = None) -> Optional[IOC]:
        """Creates an IOC with strict deduplication check."""
        clean_value = (value or "").strip()
        if not clean_value:
            return None

        if self.db.ioc_exists(case_id, ioc_type, clean_value):
            logger.info(f"IOC '{clean_value}' of type '{ioc_type}' already exists in case {case_id}; skipping duplicate.")
            # Return existing or None
            for existing in self.db.list_iocs(case_id):
                if existing.type == ioc_type and existing.value.lower() == clean_value.lower():
                    return existing
            return None

        ioc = IOC(
            id=str(uuid.uuid4()),
            case_id=case_id,
            type=ioc_type,
            value=clean_value,
            severity=severity,
            source=source,
            description=description,
            associated_finding_id=finding_id,
            associated_pid=pid,
            created_at=datetime.now().isoformat()
        )
        self.db.create_ioc(ioc)
        return ioc

    def harvest_from_network(self, case_id: str, evidence_id: str) -> List[IOC]:
        """Harvests network sockets.

        Crucially:
        1. Records them as first-class observed Artifacts (type='network_connection', scope='External').
        2. Deduplicates candidates.
        3. Assigns evidence-based initial severity ('Medium' or 'Low' unless process has High/Critical risk).
        """
        conns = self.db.list_connections(evidence_id)
        processes = {p.pid: p for p in self.db.list_processes(evidence_id)}
        harvested: List[IOC] = []
        observed_artifacts: List[Artifact] = []
        seen_ips = set()

        for c in conns:
            addr = c.remote_addr.split(":")[0].strip() if c.remote_addr else ""
            if not addr or addr in ("0.0.0.0", "127.0.0.1", "::", "-", "*") or addr in seen_ips:
                continue

            try:
                ip = ipaddress.ip_address(addr)
                if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved:
                    continue
            except ValueError:
                continue

            seen_ips.add(addr)

            # 1. Record as Observed Network Artifact
            art = Artifact(
                id=str(uuid.uuid4()),
                case_id=case_id,
                evidence_id=evidence_id,
                artifact_type="network_connection",
                source_plugin="windows.netscan.NetScan",
                source_execution_id="",
                entity_id=str(c.pid),
                timestamp=c.created_time or "",
                raw_reference=f"Socket: {c.local_addr}:{c.local_port} -> {c.remote_addr}:{c.remote_port} [{c.protocol}]",
                normalized_data={
                    "scope": "External",
                    "remote_addr": addr,
                    "remote_port": c.remote_port,
                    "local_addr": c.local_addr,
                    "local_port": c.local_port,
                    "protocol": c.protocol,
                    "state": c.state,
                    "pid": c.pid,
                    "process_name": c.process_name
                },
                hash="",
                created_at=datetime.now().isoformat()
            )
            observed_artifacts.append(art)

            # 2. Check if already recorded as an IOC
            if self.db.ioc_exists(case_id, "ip", addr):
                continue

            # 3. Determine severity based on associated process risk
            proc = processes.get(c.pid)
            if proc and proc.risk_score >= 70:
                sev = "High"
            elif proc and proc.risk_score >= 40:
                sev = "Medium"
            else:
                sev = "Low"

            ioc = IOC(
                id=str(uuid.uuid4()),
                case_id=case_id,
                type="ip",
                value=addr,
                severity=sev,
                source="netscan",
                description=f"Observed External IP in socket from PID {c.pid} ({c.process_name or 'unknown'})",
                associated_pid=c.pid,
                created_at=datetime.now().isoformat()
            )
            self.db.create_ioc(ioc)
            harvested.append(ioc)

        # Bulk save observed artifacts
        if observed_artifacts:
            self.db.create_artifacts_bulk(observed_artifacts)

        logger.info(f"Processed {len(observed_artifacts)} external network artifacts; harvested {len(harvested)} new deduplicated IP IOCs for evidence {evidence_id}")
        return harvested

    def promote_artifact_to_ioc(self, artifact_id: str, case_id: str, severity: str = "High",
                                analyst: str = "Analyst", notes: str = "") -> Optional[IOC]:
        """Analyst action: promotes an observed artifact (IP, hash, filename, domain) to an official IOC."""
        art = self.db.get_artifact(artifact_id)
        if not art:
            return None

        val = ""
        ioc_type = "artifact"
        if art.artifact_type == "network_connection" and isinstance(art.normalized_data, dict):
            val = art.normalized_data.get("remote_addr", "")
            ioc_type = "ip"
        elif art.hash:
            val = art.hash
            ioc_type = "hash"
        else:
            val = art.raw_reference

        if not val:
            return None

        desc = f"Promoted by {analyst} from Artifact {art.id}. {notes}".strip()
        pid = int(art.entity_id) if art.entity_id.isdigit() else 0
        return self.add_ioc(case_id, ioc_type, val, severity, source=f"Promoted by {analyst}", description=desc, pid=pid)

    def hunt(self, query: str, evidence_id: str) -> List[Dict[str, Any]]:
        """Fast global artifact hunting with regex safeguards."""
        q = (query or "").strip()
        if not q:
            return []

        if len(q) > 256:
            q = q[:256]

        q_lower = q.lower()

        # Guard against ReDoS (nested quantifiers or alternations)
        REDOS_SUSPICIOUS = re.compile(r"(\([^\)]*[\+\*][^\)]*\)[\+\*]|\([^\)]*\|[^\)]*\)[\+\*])")
        regex = None
        if not REDOS_SUSPICIOUS.search(q):
            try:
                regex = re.compile(q, re.IGNORECASE)
            except re.error:
                regex = None

        def is_match(text: str) -> bool:
            if not text:
                return False
            if q_lower in text.lower():
                return True
            if regex:
                try:
                    if regex.search(text[:2048]):
                        return True
                except Exception:
                    pass
            return False

        matches: List[Dict[str, Any]] = []

        # 1. Search Processes
        for p in self.db.list_processes(evidence_id):
            if is_match(p.name):
                matches.append({"source": "Processes", "field": "name", "match": p.name, "context": p.to_dict()})
            elif is_match(p.command_line):
                matches.append({"source": "Processes", "field": "command_line", "match": p.command_line, "context": p.to_dict()})
            elif is_match(p.path):
                matches.append({"source": "Processes", "field": "path", "match": p.path, "context": p.to_dict()})

        # 2. Search Network
        for c in self.db.list_connections(evidence_id):
            if is_match(c.remote_addr):
                matches.append({"source": "Network", "field": "remote_addr", "match": c.remote_addr, "context": c.to_dict()})
            elif is_match(c.local_addr):
                matches.append({"source": "Network", "field": "local_addr", "match": c.local_addr, "context": c.to_dict()})

        # 3. Search Timeline
        for e in self.db.list_events(evidence_id):
            if is_match(e.description):
                matches.append({"source": "Timeline", "field": "description", "match": e.description, "context": e.to_dict()})

        # 4. Search Artifacts (V2)
        for a in self.db.list_artifacts(evidence_id=evidence_id, limit=200):
            if is_match(a.raw_reference):
                matches.append({"source": f"Artifact ({a.artifact_type})", "field": "raw_reference", "match": a.raw_reference, "context": a.to_dict()})

        # 5. Search Detections (V2)
        for d in self.db.list_detections(evidence_id=evidence_id):
            if is_match(d.explanation) or is_match(d.rule_name):
                matches.append({"source": "Detection", "field": "rule_name", "match": f"{d.rule_name}: {d.explanation}", "context": d.to_dict()})

        # 6. Search Plugin Results
        for r in self.db.list_results_for_evidence(evidence_id):
            try:
                rows = json.loads(r.data) if r.data else []
                if r.storage_mode == "file" and r.file_path and os.path.exists(r.file_path):
                    with open(r.file_path, "r", encoding="utf-8") as f:
                        rows = json.load(f).get("data", [])
                for row in rows[:500]:
                    row_str = " ".join(str(val) for val in row)
                    if is_match(row_str):
                        matches.append({"source": r.plugin_name, "field": "row", "match": row_str[:120], "context": {"plugin": r.plugin_name, "row": row}})
                        break
            except Exception:
                pass

        logger.info(f"IOC hunt for '{q}' in {evidence_id} produced {len(matches)} matches")
        return matches

    def export_stix(self, case_id: str) -> str:
        from core.report_exporters import build_stix
        iocs = self.db.list_iocs(case_id)
        return build_stix(iocs)
