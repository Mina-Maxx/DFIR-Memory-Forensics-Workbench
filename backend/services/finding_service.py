"""
DFIR Workbench V2 - Finding Service
Manages full analyst finding lifecycle:
detected -> triaged -> investigating -> confirmed / false_positive / inconclusive -> closed.
Handles artifact linkage, analyst notes, and MITRE ATT&CK association.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import json
import uuid

from backend.models.finding import Finding, FindingArtifact, FINDING_STATUSES
from backend.models.audit import AnalystNote
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("app")

ALLOWED_TRANSITIONS = {
    "detected": ["triaged", "false_positive", "investigating", "confirmed"],
    "triaged": ["investigating", "false_positive", "inconclusive", "closed", "confirmed"],
    "investigating": ["confirmed", "false_positive", "inconclusive", "triaged", "closed"],
    "confirmed": ["closed", "investigating"],
    "false_positive": ["triaged", "investigating"],
    "inconclusive": ["investigating", "closed"],
    "closed": ["investigating", "triaged"]
}


class FindingService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def create_finding(
        self,
        case_id: str,
        title: str,
        severity: str = "Medium",
        confidence: str = "Medium",
        status: str = "detected",
        source_type: str = "analyst_investigation",
        affected_entity: str = "",
        associated_pid: int = 0,
        associated_process_name: str = "",
        summary: str = "",
        technical_description: str = "",
        supporting_evidence: str = "[]",
        analyst_assessment: str = "",
        limitations: str = "",
        mitre_attack: str = "[]",
        threat_intel: str = "",
        investigator: str = "Analyst"
    ) -> Finding:
        finding = Finding(
            case_id=case_id,
            title=title,
            severity=severity,
            confidence=confidence,
            status=status if status in FINDING_STATUSES else "detected",
            source_type=source_type,
            affected_entity=affected_entity,
            associated_pid=associated_pid,
            associated_process_name=associated_process_name,
            description=summary or technical_description or title,
            summary=summary,
            technical_description=technical_description,
            supporting_evidence=supporting_evidence,
            analyst_assessment=analyst_assessment,
            limitations=limitations,
            mitre_attack=mitre_attack,
            threat_intel=threat_intel,
            investigator=investigator
        )
        self.db.create_finding(finding)
        logger.info(f"Created finding '{title}' ({finding.id}) in case {case_id} [Status: {finding.status}]")
        return finding

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        return self.db.get_finding(finding_id)

    def list_findings(self, case_id: str, status: Optional[str] = None) -> List[Finding]:
        return self.db.list_findings(case_id, status=status)

    def transition_status(self, finding_id: str, new_status: str, analyst: str = "Analyst", reason: str = "") -> Optional[Finding]:
        if new_status not in FINDING_STATUSES:
            raise ValueError(f"Invalid finding status: {new_status}. Allowed statuses: {FINDING_STATUSES}")

        finding = self.db.get_finding(finding_id)
        if not finding:
            return None

        old_status = finding.status or "detected"
        allowed = ALLOWED_TRANSITIONS.get(old_status, [])
        if new_status != old_status and new_status not in allowed:
            raise ValueError(
                f"Invalid lifecycle transition from '{old_status}' to '{new_status}'. "
                f"Allowed transitions for '{old_status}' are: {allowed}"
            )

        finding.status = new_status
        finding.updated_at = datetime.now().isoformat()
        self.db.update_finding(finding)

        # Log transition in analyst notes
        self.db.add_analyst_note(AnalystNote(
            case_id=finding.case_id,
            entity_id=finding.id,
            entity_type="finding",
            author=analyst,
            text=f"Status transitioned from '{old_status}' to '{new_status}'. Reason: {reason or 'Lifecycle update'}."
        ))

        logger.info(f"Finding {finding_id} status transitioned: {old_status} -> {new_status} by {analyst}")
        return finding

    def update_finding(self, finding_id: str, updates: Dict[str, Any], analyst: str = "Analyst") -> Optional[Finding]:
        finding = self.db.get_finding(finding_id)
        if not finding:
            return None

        # Prevent arbitrary bypass of lifecycle state machine through generic update
        for k, v in updates.items():
            if hasattr(finding, k) and k not in ("id", "case_id", "created_at", "status", "verdict"):
                setattr(finding, k, v)
        finding.updated_at = datetime.now().isoformat()
        finding.investigator = analyst
        self.db.update_finding(finding)
        return finding

    def delete_finding(self, finding_id: str) -> bool:
        return self.db.delete_finding(finding_id)

    def attach_artifact(self, finding_id: str, artifact_id: str, role: str = "supports", explanation: str = "") -> FindingArtifact:
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding not found: {finding_id}")

        artifact = self.db.get_artifact(artifact_id)
        if not artifact:
            raise ValueError(f"Artifact not found: {artifact_id}")

        if finding.case_id and artifact.case_id and finding.case_id != artifact.case_id:
            raise ValueError(
                f"Cross-case artifact attachment prohibited: Finding belongs to case '{finding.case_id}', "
                f"but Artifact belongs to case '{artifact.case_id}'"
            )

        link = FindingArtifact(
            finding_id=finding_id,
            artifact_id=artifact_id,
            case_id=finding.case_id,
            role=role,
            explanation=explanation,
            relationship=role
        )
        self.db.add_finding_artifact(link)
        logger.info(f"Attached artifact {artifact_id} to finding {finding_id} in case {finding.case_id} (Role: {role})")
        return link

    def add_note(self, finding_id: str, author: str, content: str) -> AnalystNote:
        finding = self.db.get_finding(finding_id)
        note = AnalystNote(
            case_id=finding.case_id if finding else "",
            entity_id=finding_id,
            entity_type="finding",
            author=author,
            text=content
        )
        self.db.add_analyst_note(note)
        return note

    def get_finding_details(self, finding_id: str) -> Dict[str, Any]:
        finding = self.db.get_finding(finding_id)
        if not finding:
            return {"error": "Finding not found"}

        artifacts = []
        links = self.db.get_finding_artifacts(finding_id)
        for link in links:
            art = self.db.get_artifact(link.artifact_id)
            if art:
                artifacts.append({
                    "artifact": art.to_dict(),
                    "link": link.to_dict()
                })

        notes = [n.to_dict() for n in self.db.list_analyst_notes(finding.case_id, finding_id=finding_id)]

        return {
            "finding": finding.to_dict(),
            "artifacts": artifacts,
            "notes": notes
        }
