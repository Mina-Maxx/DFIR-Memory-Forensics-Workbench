"""
DFIR Workbench V2 - Case Management Service
Handles case creation, workspace directories, status lifecycle, and chain of custody tracking.
"""

import os
from typing import List, Optional
from datetime import datetime
from backend.models.case import Case
from backend.models.audit import CustodyEvent
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("app")


class CaseService:
    def __init__(self, db: DatabaseManager, workspace_root: str):
        self.db = db
        self.workspace_root = workspace_root

    def create_case(self, case_id: str, name: str, investigator: str, description: str = "") -> Case:
        ws_path = os.path.join(self.workspace_root, case_id)
        os.makedirs(ws_path, exist_ok=True)
        os.makedirs(os.path.join(ws_path, "dumps"), exist_ok=True)
        os.makedirs(os.path.join(ws_path, "exports"), exist_ok=True)
        os.makedirs(os.path.join(ws_path, "raw"), exist_ok=True)

        case = Case(
            id=case_id,
            name=name,
            investigator=investigator,
            description=description,
            status="Open",
            workspace_path=ws_path,
            chain_of_custody=f"Case initialized by {investigator} at {datetime.now().isoformat()}."
        )
        self.db.create_case(case)
        logger.info(f"Created case {case_id} at {ws_path}")
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        return self.db.get_case(case_id)

    def list_cases(self) -> List[Case]:
        return self.db.list_cases()

    def update_case(self, case_id: str, name: Optional[str] = None, investigator: Optional[str] = None,
                    description: Optional[str] = None, status: Optional[str] = None) -> Optional[Case]:
        case = self.db.get_case(case_id)
        if not case:
            return None
        if name is not None:
            case.name = name
        if investigator is not None:
            case.investigator = investigator
        if description is not None:
            case.description = description
        if status is not None:
            case.status = status
        case.updated_at = datetime.now().isoformat()
        self.db.update_case(case)
        return case

    def delete_case(self, case_id: str, delete_files: bool = True) -> bool:
        case = self.db.get_case(case_id)
        if not case:
            return False
        ok = self.db.delete_case(case_id)
        if delete_files and case.workspace_path and os.path.exists(case.workspace_path):
            import shutil
            try:
                shutil.rmtree(case.workspace_path, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to delete case workspace directory: {e}")
        return ok

    def log_custody_action(self, case_id: str, action: str, actor: str,
                           evidence_id: Optional[str] = None, notes: str = "",
                           hash_after: str = "") -> CustodyEvent:
        event = CustodyEvent(
            case_id=case_id,
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            notes=notes,
            hash_after=hash_after
        )
        self.db.add_custody_event(event)
        return event
