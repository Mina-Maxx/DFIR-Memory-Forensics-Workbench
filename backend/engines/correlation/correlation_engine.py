"""
DFIR Workbench V2 - Correlation Engine
Correlates processes, network sockets, memory regions, DLLs, and command lines.
Provides explainable process profiles: 'Why is this process suspicious?'
"""

from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime

from backend.infrastructure.database.manager import DatabaseManager
from backend.engines.risk.risk_engine import RiskEngine
from backend.models.process import Process
from backend.models.artifact import Artifact
from backend.models.detection import Detection
from core.logger import get_logger

logger = get_logger("forensic")


class CorrelationEngine:
    """Consolidates disparate Volatility plugin artifacts into a cohesive,

    explainable forensic process tree and correlation graph.
    """

    def __init__(self, db: DatabaseManager, risk_engine: Optional[RiskEngine] = None):
        self.db = db
        self.risk_engine = risk_engine or RiskEngine()

    def correlate_evidence(self, case_id: str, evidence_id: str) -> Dict[str, Any]:
        """Runs comprehensive cross-artifact correlation for a given evidence image."""
        processes = self.db.list_processes(evidence_id)
        conns = self.db.list_connections(evidence_id)
        regions = self.db.list_memory_regions(evidence_id)
        
        proc_dicts = [p.to_dict() for p in processes]
        conn_dicts = [c.to_dict() for c in conns]
        mem_dicts = [r.to_dict() for r in regions]

        updated_processes: List[Process] = []
        new_detections: List[Detection] = []

        # Clear existing risk assessments and detections for this evidence run to avoid duplication
        self.db.clear_risk_assessments(evidence_id)

        for p in processes:
            eval_result = self.risk_engine.evaluate_process(
                process=p.to_dict(),
                all_processes=proc_dicts,
                network_connections=conn_dicts,
                memory_anomalies=mem_dicts,
                case_id=case_id,
                evidence_id=evidence_id
            )

            p.risk_score = eval_result["risk_score"]
            p.risk_level = eval_result["risk_level"]
            p.confidence = eval_result["confidence"]
            p.severity = eval_result["severity"]
            p.risk_details = eval_result["explanation"]

            updated_processes.append(p)

            # Collect detections
            for d_dict in eval_result["detections"]:
                new_detections.append(Detection.from_dict(d_dict))

        # Bulk update processes
        if updated_processes:
            self.db.upsert_processes_bulk(updated_processes)

        # Bulk save detections
        if new_detections:
            self.db.create_detections_bulk(new_detections)

        logger.info(f"Correlated {len(updated_processes)} processes and generated {len(new_detections)} detections for evidence {evidence_id}")
        return {
            "processes_count": len(updated_processes),
            "detections_count": len(new_detections)
        }

    def explain_process(self, evidence_id: str, pid: int) -> Dict[str, Any]:
        """Builds a comprehensive, explainable forensic profile for a specific PID:

        - Identity & Integrity (pslist vs psscan DKOM, timestamps, path, user)
        - Risk Breakdown (score, level, confidence, contributing rules with weights & evidence)
        - Parent-Child Ancestry Tree
        - Sockets (Internal vs External)
        - Memory Injections (Malfind RWX regions)
        - Loaded Modules (DLLs)
        - Associated Detections, Findings, and Analyst Notes
        """
        proc = self.db.get_process_by_pid(evidence_id, pid)
        if not proc:
            return {"error": f"Process with PID {pid} not found in evidence {evidence_id}"}

        all_procs = self.db.list_processes(evidence_id)
        proc_map = {p.pid: p for p in all_procs}

        # 1. Build Ancestry
        ancestry = []
        curr = proc
        visited = set()
        while curr and curr.ppid and curr.ppid not in visited:
            visited.add(curr.ppid)
            parent = proc_map.get(curr.ppid)
            if parent:
                ancestry.append({
                    "pid": parent.pid,
                    "ppid": parent.ppid,
                    "name": parent.name,
                    "path": parent.path,
                    "risk_score": parent.risk_score,
                    "risk_level": parent.risk_level
                })
                curr = parent
            else:
                ancestry.append({
                    "pid": curr.ppid,
                    "name": "Unknown / Terminated Parent",
                    "missing": True
                })
                break

        # 2. Children
        children = [
            {"pid": c.pid, "name": c.name, "risk_score": c.risk_score, "risk_level": c.risk_level, "create_time": c.create_time}
            for c in all_procs if c.ppid == pid
        ]

        # 3. Sockets
        sockets = [c.to_dict() for c in self.db.list_connections(evidence_id) if c.pid == pid]

        # 4. DLLs
        dlls = [d.to_dict() for d in self.db.list_dlls(evidence_id, pid)]

        # 5. Memory regions
        mem_regions = [m.to_dict() for m in self.db.list_memory_regions(evidence_id, pid)]

        # 6. Detections
        detections = [
            d.to_dict() for d in self.db.list_detections(evidence_id=evidence_id)
            if f"PID {pid}" in d.affected_entity
        ]

        # 7. Re-evaluate for live indicators
        eval_result = self.risk_engine.evaluate_process(
            process=proc.to_dict(),
            all_processes=[p.to_dict() for p in all_procs],
            network_connections=sockets,
            memory_anomalies=mem_regions,
            evidence_id=evidence_id
        )

        return {
            "process": proc.to_dict(),
            "risk_assessment": {
                "score": proc.risk_score,
                "level": proc.risk_level,
                "confidence": proc.confidence,
                "severity": proc.severity,
                "verdict": proc.verdict,
                "explanation": eval_result["explanation"],
                "contributing_factors": eval_result["indicators"]
            },
            "ancestry": ancestry,
            "children": children,
            "sockets": sockets,
            "dlls": dlls,
            "memory_regions": mem_regions,
            "detections": detections
        }
