"""
DFIR Workbench V2 - Correlation Service
Coordinates correlation engine, explainable process profiles, and cross-artifact synthesis.
"""

from typing import Dict, Any, List, Optional
from backend.infrastructure.database.manager import DatabaseManager
from backend.engines.correlation.correlation_engine import CorrelationEngine
from backend.engines.correlation.investigation_engine import InvestigationEngine
from backend.engines.risk.risk_engine import RiskEngine
from core.logger import get_logger

logger = get_logger("forensic")


class CorrelationService:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.risk_engine = RiskEngine()
        self.correlation_engine = CorrelationEngine(self.db, self.risk_engine)
        self.investigation_engine = InvestigationEngine(self.db, self.risk_engine)

    def run_correlation(self, case_id: str, evidence_id: str) -> Dict[str, Any]:
        """Runs full investigation ingestion and cross-plugin correlation."""
        # 1. Correlate raw outputs and populate DB
        inv_result = self.investigation_engine.correlate_evidence(evidence_id)
        # 2. Correlate processes and generate detections
        corr_result = self.correlation_engine.correlate_evidence(case_id, evidence_id)
        return {
            "processes_count": len(inv_result),
            "detections_count": corr_result.get("detections_count", 0),
            "status": "success"
        }

    def explain_process(self, evidence_id: str, pid: int) -> Dict[str, Any]:
        """Returns deep forensic explanation for a specific PID."""
        return self.correlation_engine.explain_process(evidence_id, pid)

    def update_process_verdict(self, process_id: str, verdict: str) -> bool:
        """Allows an analyst to set verdict on a process (e.g., confirmed, false_positive)."""
        return self.db.update_process_verdict(process_id, verdict)
