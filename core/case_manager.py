import os
import shutil
from typing import Optional, List
from pathlib import Path
from core.models import Case
from core.database import DatabaseManager
from core.logger import get_logger

logger = get_logger("app")

class CaseManager:
    """Manages forensic cases and workspaces with path traversal prevention."""

    def __init__(self, db: DatabaseManager, workspace_root: str):
        self.db = db
        self.workspace_root = os.path.abspath(workspace_root)
        os.makedirs(self.workspace_root, exist_ok=True)

    def _validate_case_path(self, case_id: str) -> Path:
        safe_id = "".join([c for c in case_id if c.isalnum() or c in ("-", "_")]).strip()
        if not safe_id or safe_id != case_id or ".." in case_id or "/" in case_id or "\\" in case_id:
            raise ValueError(f"Invalid case identifier: {case_id}")
        target_path = (Path(self.workspace_root) / safe_id).resolve()
        if not str(target_path).startswith(str(Path(self.workspace_root).resolve())):
            raise ValueError("Directory traversal attempt detected.")
        return target_path

    def create_case(self, case_id: str, name: str, investigator: str, description: str) -> Case:
        case_dir = self._validate_case_path(case_id)
        os.makedirs(case_dir, exist_ok=True)
        for sub in ("dumps", "exports", "notes", "cache"):
            os.makedirs(case_dir / sub, exist_ok=True)

        from datetime import datetime
        now = datetime.now().isoformat()
        audit_entry = f"[{now}] Case created by {investigator or 'Unknown'}"
        case = Case(
            id=case_id,
            name=name,
            investigator=investigator,
            description=description,
            status="Open",
            workspace_path=str(case_dir),
            chain_of_custody=audit_entry
        )
        self.db.create_case(case)
        logger.info(f"Created case {case_id} at {case_dir}")
        return case

    def load_case(self, case_id: str) -> Optional[Case]:
        return self.db.get_case(case_id)

    def list_cases(self) -> List[Case]:
        return self.db.list_cases()

    def update_case(self, case: Case) -> bool:
        return self.db.update_case(case)

    def delete_case(self, case_id: str, delete_files: bool = False) -> bool:
        case = self.db.get_case(case_id)
        if not case:
            return False
        if delete_files and os.path.exists(case.workspace_path):
            try:
                shutil.rmtree(case.workspace_path)
            except Exception as e:
                logger.error(f"Failed to delete workspace folder for case {case_id}: {e}")
        return self.db.delete_case(case_id)
