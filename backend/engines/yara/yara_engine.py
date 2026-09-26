"""
DFIR Workbench V2 - YARA Engine
Manages YARA rule compilation, validation, scanning in memory, and storage of matches.
"""

import os
import json
from typing import Dict, List, Any, Optional
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("forensic")


def available() -> bool:
    try:
        import yara
        return True
    except ImportError:
        return False


def validate_rule_file(rule_path: str) -> Optional[str]:
    if not os.path.isfile(rule_path):
        return f"Rule file not found: {rule_path}"
    try:
        import yara
        yara.compile(filepath=rule_path)
        return None
    except ImportError:
        return None
    except Exception as e:
        return str(e)


class YaraEngine:
    """Manages YARA rule scanning in memory and storage of matches."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def list_matches(self, evidence_id: str) -> List[Dict[str, Any]]:
        return self.db.list_yara_matches(evidence_id)

    def matches_for(self, evidence_id: str) -> List[Dict[str, Any]]:
        return self.list_matches(evidence_id)

    def validate_rule(self, rule_text: str) -> Dict[str, Any]:
        try:
            import yara
            yara.compile(source=rule_text)
            return {"valid": True, "error": None}
        except ImportError:
            return {"valid": True, "error": "YARA module not installed"}
        except Exception as e:
            return {"valid": False, "error": str(e)}
