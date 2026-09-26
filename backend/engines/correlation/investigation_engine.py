"""
DFIR Workbench V2 - Investigation & Correlation Engine
Parses raw plugin outputs, normalizes them into first-class Artifacts with provenance,
correlates processes, network sockets, memory anomalies, and DLLs, and evaluates risk.
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional

from backend.models import Process, NetworkConnection, DLL, MemoryRegion, Artifact, Detection
from backend.infrastructure.database.manager import DatabaseManager
from backend.engines.risk.risk_engine import RiskEngine
from core.logger import get_logger

logger = get_logger("forensic")


class CorrelatedProcess:
    def __init__(self, pid: int, name: str, ppid: int = 0):
        self.pid = pid
        self.name = name
        self.ppid = ppid
        self.path = ""
        self.command_line = ""
        self.create_time = ""
        self.exit_time = ""
        self.session_id = 0
        self.user_info = ""
        self.in_pslist = False
        self.in_psscan = False
        self.in_pstree = False
        self.risk_score = 0
        self.risk_level = "Normal"
        self.confidence = "Medium"
        self.severity = "Normal"
        self.verdict = "unreviewed"
        self.risk_indicators: List[Dict[str, Any]] = []
        self.risk_explanation = ""
        self.network_connections: List[Dict[str, Any]] = []
        self.dlls: List[Dict[str, Any]] = []
        self.memory_regions: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "path": self.path,
            "command_line": self.command_line,
            "create_time": self.create_time,
            "exit_time": self.exit_time,
            "session_id": self.session_id,
            "user_info": self.user_info,
            "in_pslist": self.in_pslist,
            "in_psscan": self.in_psscan,
            "in_pstree": self.in_pstree,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "severity": self.severity,
            "verdict": self.verdict,
            "risk_indicators": self.risk_indicators,
            "risk_explanation": self.risk_explanation,
            "network_connections": self.network_connections,
            "dlls": self.dlls,
            "memory_regions": self.memory_regions
        }


class InvestigationEngine:
    """Correlates multiple Volatility 3 plugin outputs into a cohesive process graph,

    normalized artifacts, and detections.
    """

    def __init__(self, db: DatabaseManager, risk_engine: Optional[RiskEngine] = None):
        self.db = db
        self.risk_engine = risk_engine or RiskEngine()

    def correlate_evidence(self, evidence_id: str) -> Dict[int, CorrelatedProcess]:
        logger.info(f"Starting cross-plugin correlation for evidence {evidence_id}")
        ev = self.db.get_evidence(evidence_id)
        case_id = ev.case_id if ev else ""

        results = self.db.list_results_for_evidence(evidence_id)

        plugin_data_map: Dict[str, List[Dict[str, Any]]] = {}
        for r in results:
            try:
                headers = json.loads(r.headers) if isinstance(r.headers, str) else r.headers
                data_rows = json.loads(r.data) if (r.data and isinstance(r.data, str)) else (r.data or [])
                if r.storage_mode == "file" and r.file_path:
                    import os
                    if os.path.exists(r.file_path):
                        with open(r.file_path, "r", encoding="utf-8") as f:
                            file_payload = json.load(f)
                            headers = file_payload.get("headers", headers)
                            data_rows = file_payload.get("data", data_rows)

                dict_rows = [dict(zip(headers, row)) for row in data_rows if len(row) == len(headers)]
                plugin_data_map[r.plugin_name.lower()] = dict_rows
            except Exception as e:
                logger.error(f"Failed to decode result for {r.plugin_name}: {e}")

        correlated: Dict[int, CorrelatedProcess] = {}
        new_artifacts: List[Artifact] = []

        def get_or_create(pid: int, name: str = "", ppid: int = 0) -> CorrelatedProcess:
            if pid not in correlated:
                correlated[pid] = CorrelatedProcess(pid, name, ppid)
            else:
                if name and not correlated[pid].name:
                    correlated[pid].name = name
                if ppid and not correlated[pid].ppid:
                    correlated[pid].ppid = ppid
            return correlated[pid]

        # 1. PsList
        for key in plugin_data_map:
            if "pslist" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        ppid = int(row.get("PPID", 0))
                        name = row.get("ImageFileName", "")
                        p = get_or_create(pid, name, ppid)
                        p.in_pslist = True
                        p.create_time = str(row.get("CreateTime", ""))
                        p.exit_time = str(row.get("ExitTime", ""))
                        p.session_id = int(row.get("SessionId", 0) or 0)

                        new_artifacts.append(Artifact(
                            id=str(uuid.uuid4()),
                            case_id=case_id,
                            evidence_id=evidence_id,
                            artifact_type="process",
                            source_plugin="windows.pslist.PsList",
                            source_execution_id="",
                            entity_id=str(pid),
                            timestamp=p.create_time,
                            raw_reference=f"PID {pid} ({name}) PPID {ppid}",
                            normalized_data=row,
                            created_at=datetime.now().isoformat()
                        ))
                    except Exception as e:
                        logger.debug(f"pslist row error: {e}")

        # 2. PsScan
        for key in plugin_data_map:
            if "psscan" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        ppid = int(row.get("PPID", 0))
                        name = row.get("ImageFileName", "")
                        p = get_or_create(pid, name, ppid)
                        p.in_psscan = True
                        if not p.create_time:
                            p.create_time = str(row.get("CreateTime", ""))

                        new_artifacts.append(Artifact(
                            id=str(uuid.uuid4()),
                            case_id=case_id,
                            evidence_id=evidence_id,
                            artifact_type="process_scan",
                            source_plugin="windows.psscan.PsScan",
                            source_execution_id="",
                            entity_id=str(pid),
                            timestamp=p.create_time,
                            raw_reference=f"PsScan PID {pid} ({name})",
                            normalized_data=row,
                            created_at=datetime.now().isoformat()
                        ))
                    except Exception as e:
                        logger.debug(f"psscan row error: {e}")

        # 3. PsTree
        for key in plugin_data_map:
            if "pstree" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        ppid = int(row.get("PPID", 0))
                        name = row.get("ImageFileName", "")
                        p = get_or_create(pid, name, ppid)
                        p.in_pstree = True
                    except Exception as e:
                        logger.debug(f"pstree row error: {e}")

        # 4. CmdLine
        for key in plugin_data_map:
            if "cmdline" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        cmd = row.get("Args", "") or row.get("CommandLine", "")
                        if pid in correlated:
                            correlated[pid].command_line = str(cmd)

                        new_artifacts.append(Artifact(
                            id=str(uuid.uuid4()),
                            case_id=case_id,
                            evidence_id=evidence_id,
                            artifact_type="command_line",
                            source_plugin="windows.cmdline.CmdLine",
                            source_execution_id="",
                            entity_id=str(pid),
                            timestamp="",
                            raw_reference=f"PID {pid} Cmd: {str(cmd)[:100]}",
                            normalized_data=row,
                            created_at=datetime.now().isoformat()
                        ))
                    except Exception as e:
                        logger.debug(f"cmdline row error: {e}")

        # 5. NetScan
        all_network_conns: List[Dict[str, Any]] = []
        db_connections: List[NetworkConnection] = []
        self.db.clear_connections_for_evidence(evidence_id)
        for key in plugin_data_map:
            if "netscan" in key or "netstat" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0) or row.get("Owner", 0) or 0)
                        rem = str(row.get("ForeignAddr", row.get("ForeignAddress", "")))
                        is_ext = not rem.startswith(("10.", "192.168.", "172.16.", "127.", "0.", "::", "*")) and rem not in ("0.0.0.0", "127.0.0.1", "")
                        conn_info = {
                            "pid": pid,
                            "protocol": str(row.get("Proto", "TCP")),
                            "local_addr": str(row.get("LocalAddr", row.get("LocalAddress", ""))),
                            "local_port": int(row.get("LocalPort", 0) or 0),
                            "remote_addr": rem,
                            "remote_port": int(row.get("ForeignPort", 0) or 0),
                            "state": str(row.get("State", "")),
                            "owner": str(row.get("Owner", "")),
                            "scope": "External" if is_ext else "Internal"
                        }
                        all_network_conns.append(conn_info)
                        if pid in correlated:
                            correlated[pid].network_connections.append(conn_info)

                        nc = NetworkConnection(
                            evidence_id=evidence_id,
                            pid=pid,
                            process_name=correlated[pid].name if pid in correlated else "",
                            local_addr=conn_info["local_addr"],
                            local_port=conn_info["local_port"],
                            remote_addr=conn_info["remote_addr"],
                            remote_port=conn_info["remote_port"],
                            protocol=conn_info["protocol"],
                            state=conn_info["state"],
                            owner=conn_info["owner"],
                            scope=conn_info["scope"]
                        )
                        db_connections.append(nc)

                        new_artifacts.append(Artifact(
                            id=str(uuid.uuid4()),
                            case_id=case_id,
                            evidence_id=evidence_id,
                            artifact_type="network_connection",
                            source_plugin="windows.netscan.NetScan",
                            source_execution_id="",
                            entity_id=str(pid),
                            timestamp=str(row.get("Created", "")),
                            raw_reference=f"Socket {conn_info['protocol']} {conn_info['local_addr']}:{conn_info['local_port']} -> {conn_info['remote_addr']}:{conn_info['remote_port']}",
                            normalized_data=conn_info,
                            created_at=datetime.now().isoformat()
                        ))
                    except Exception as e:
                        logger.debug(f"netscan row error: {e}")

        if db_connections:
            self.db.create_connections_bulk(db_connections)

        # 6. DllList
        for key in plugin_data_map:
            if "dlllist" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        dll_info = {
                            "name": str(row.get("Path", "")).split("\\")[-1],
                            "path": str(row.get("Path", "")),
                            "base": str(row.get("Base", ""))
                        }
                        if pid in correlated:
                            correlated[pid].dlls.append(dll_info)
                            if not correlated[pid].path and dll_info["path"].endswith(".exe"):
                                correlated[pid].path = dll_info["path"]
                    except Exception as e:
                        logger.debug(f"dlllist row error: {e}")

        # 7. Malfind
        all_mem_anomalies: List[Dict[str, Any]] = []
        for key in plugin_data_map:
            if "malfind" in key:
                for row in plugin_data_map[key]:
                    try:
                        pid = int(row.get("PID", 0))
                        mem_info = {
                            "pid": pid,
                            "process_name": str(row.get("Process", "")),
                            "start_address": str(row.get("StartVPN", row.get("Start", ""))),
                            "end_address": str(row.get("EndVPN", row.get("End", ""))),
                            "tag": str(row.get("Tag", "")),
                            "protection": str(row.get("Protection", ""))
                        }
                        all_mem_anomalies.append(mem_info)
                        if pid in correlated:
                            correlated[pid].memory_regions.append(mem_info)

                        new_artifacts.append(Artifact(
                            id=str(uuid.uuid4()),
                            case_id=case_id,
                            evidence_id=evidence_id,
                            artifact_type="memory_region",
                            source_plugin="windows.malfind.Malfind",
                            source_execution_id="",
                            entity_id=str(pid),
                            timestamp="",
                            raw_reference=f"Malfind PID {pid} [{mem_info['protection']}] at {mem_info['start_address']}",
                            normalized_data=mem_info,
                            created_at=datetime.now().isoformat()
                        ))
                    except Exception as e:
                        logger.debug(f"malfind row error: {e}")

        # 8. Evaluate Risk for all processes
        process_dicts = [p.to_dict() for p in correlated.values()]
        risk_results = self.risk_engine.evaluate_all(
            all_processes=process_dicts,
            network_connections=all_network_conns,
            memory_anomalies=all_mem_anomalies,
            case_id=case_id,
            evidence_id=evidence_id
        )

        proc_models = []
        all_detections: List[Detection] = []
        for pid, p in correlated.items():
            if pid in risk_results:
                r = risk_results[pid]
                p.risk_score = r["risk_score"]
                p.risk_level = r["risk_level"]
                p.confidence = r["confidence"]
                p.severity = r["severity"]
                p.risk_indicators = r["indicators"]
                p.risk_explanation = r["explanation"]
                for d_dict in r.get("detections", []):
                    all_detections.append(Detection.from_dict(d_dict))

            proc_model = Process(
                evidence_id=evidence_id,
                pid=p.pid,
                ppid=p.ppid,
                name=p.name,
                path=p.path,
                command_line=p.command_line,
                create_time=p.create_time,
                exit_time=p.exit_time,
                session_id=p.session_id,
                user_info=p.user_info,
                in_pslist=p.in_pslist,
                in_psscan=p.in_psscan,
                in_pstree=p.in_pstree,
                risk_score=p.risk_score,
                risk_level=p.risk_level,
                confidence=p.confidence,
                severity=p.severity,
                verdict=p.verdict,
                risk_details=json.dumps(p.risk_indicators),
                metadata=json.dumps({"explanation": p.risk_explanation})
            )
            proc_models.append(proc_model)

        if proc_models:
            self.db.upsert_processes_bulk(proc_models)

        if new_artifacts:
            self.db.create_artifacts_bulk(new_artifacts)

        if all_detections:
            self.db.create_detections_bulk(all_detections)

        logger.info(f"Cross-plugin correlation complete for evidence {evidence_id}: {len(correlated)} processes, {len(new_artifacts)} artifacts, {len(all_detections)} detections.")
        return correlated
