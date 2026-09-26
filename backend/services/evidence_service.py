"""
DFIR Workbench V2 - Evidence Service
Manages digital evidence ingestion, SHA-256 primary hashing, MD5, and integrity verification.
"""

import os
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime

from backend.models.evidence import Evidence
from backend.models.audit import CustodyEvent
from backend.infrastructure.database.manager import DatabaseManager
from core.logger import get_logger

logger = get_logger("app")


def compute_hashes(filepath: str) -> Dict[str, str]:
    """Computes SHA-256 (primary) and MD5 (secondary) hashes for forensic integrity."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):  # 1MB chunks
            sha256.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest()
    }


class EvidenceService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def ingest_evidence(self, case_id: str, filepath: str, filename: Optional[str] = None) -> Evidence:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Evidence file not found: {filepath}")

        fname = filename or os.path.basename(filepath)
        size = os.path.getsize(filepath)
        logger.info(f"Computing cryptographic hashes for {fname} ({size} bytes)...")
        hashes = compute_hashes(filepath)

        evidence = Evidence(
            case_id=case_id,
            filename=fname,
            filepath=filepath,
            file_size=size,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            status="Ready",
            verification_status="Verified",
            last_verified=datetime.now().isoformat()
        )
        self.db.create_evidence(evidence)
        logger.info(f"Evidence ingested: {fname} (SHA256: {hashes['sha256']})")
        return evidence

    def verify_evidence_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Recalculates evidence file hashes and compares against the recorded chain of custody."""
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            return {"verified": False, "error": "Evidence record not found"}

        if not os.path.exists(evidence.filepath):
            evidence.verification_status = "Missing File"
            self.db.update_evidence(evidence)
            return {"verified": False, "error": f"File missing at {evidence.filepath}"}

        curr_hashes = compute_hashes(evidence.filepath)
        match = (curr_hashes["sha256"].lower() == (evidence.sha256 or "").lower())
        
        evidence.verification_status = "Verified" if match else "Hash Mismatch"
        evidence.last_verified = datetime.now().isoformat()
        self.db.update_evidence(evidence)

        # Log verification event in chain of custody
        self.db.add_custody_event(CustodyEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            action="INTEGRITY_VERIFIED",
            actor="System",
            hash_after=curr_hashes["sha256"],
            notes=f"Integrity check: {'PASSED' if match else 'FAILED (HASH MISMATCH)'}"
        ))

        return {
            "verified": match,
            "recorded_sha256": evidence.sha256,
            "calculated_sha256": curr_hashes["sha256"],
            "verification_status": evidence.verification_status,
            "last_verified": evidence.last_verified
        }

    def list_evidence(self, case_id: str) -> List[Evidence]:
        return self.db.list_evidence_for_case(case_id)

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self.db.get_evidence(evidence_id)

    def delete_evidence(self, evidence_id: str) -> bool:
        return self.db.delete_evidence(evidence_id)
