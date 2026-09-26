import os
import hashlib
import json
from datetime import datetime
from typing import Optional, List, Callable, Dict, Any, Tuple

from core.models import Evidence, DumpArtifact
from core.database import DatabaseManager
from forensics.vol_adapter import VolAdapter
from core.logger import get_logger

logger = get_logger("forensic")

class EvidenceManager:
    """Manages memory image evidence, hashing, validation, and metadata."""

    def __init__(self, db: DatabaseManager, vol_adapter: Optional[VolAdapter] = None):
        self.db = db
        self.vol = vol_adapter or VolAdapter(getattr(db, "workspace_path", "."))

    def compute_hashes_sync(self, filepath: str, progress_callback: Optional[Callable[[int], None]] = None) -> Tuple[str, str]:
        """Compute SHA256 and MD5 with streaming chunks and progress callback."""
        total_size = os.path.getsize(filepath)
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        read_bytes = 0
        chunk_size = 4 * 1024 * 1024  # 4MB chunks

        with open(filepath, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
                md5.update(chunk)
                read_bytes += len(chunk)
                if progress_callback and total_size > 0:
                    pct = int((read_bytes / total_size) * 100)
                    progress_callback(pct)

        return sha256.hexdigest(), md5.hexdigest()

    def import_evidence(self, case_id: str, filepath: str, sha256_or_cb: Any = None, md5: Optional[str] = None) -> Evidence:
        """Imports memory dump into case and calculates hashes (or uses precomputed hashes)."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Evidence file does not exist: {filepath}")

        abs_path = os.path.abspath(filepath)
        file_size = os.path.getsize(abs_path)
        filename = os.path.basename(abs_path)

        if isinstance(sha256_or_cb, str) and sha256_or_cb:
            sha256_val = sha256_or_cb
            md5_val = md5 or ""
        else:
            cb = sha256_or_cb if callable(sha256_or_cb) else None
            logger.info(f"Computing cryptographic hashes for {filename} ({file_size} bytes)...")
            sha256_val, md5_val = self.compute_hashes_sync(abs_path, cb)
            logger.info(f"Hashes computed: SHA256={sha256_val[:16]}... MD5={md5_val}")

        os_type = "Windows" if any(filename.lower().endswith(ext) for ext in (".dmp", ".raw", ".vmem", ".mem", ".bin", ".img")) else "Unknown"

        evidence = Evidence(
            case_id=case_id,
            filename=filename,
            filepath=abs_path,
            file_size=file_size,
            sha256=sha256_val,
            md5=md5_val,
            os_type=os_type,
            architecture="x64",
            status="Ready"
        )
        self.db.create_evidence(evidence)

        # Audit chain of custody
        case = self.db.get_case(case_id)
        if case:
            now = datetime.now().isoformat()
            audit_line = f"\n[{now}] Evidence imported: {filename} (SHA256: {sha256_val})"
            case.chain_of_custody += audit_line
            self.db.update_case(case)

        return evidence

    def verify_integrity(self, evidence_id: str) -> Dict[str, Any]:
        evidence = self.db.get_evidence(evidence_id)
        if not evidence:
            return {"success": False, "error": "Evidence not found"}
        if not os.path.isfile(evidence.filepath):
            return {"success": False, "error": f"Evidence file not found on disk: {evidence.filepath}"}

        calc_sha256, calc_md5 = self.compute_hashes_sync(evidence.filepath)
        match = (calc_sha256.lower() == evidence.sha256.lower())
        return {
            "success": True,
            "intact": match,
            "expected_sha256": evidence.sha256,
            "calculated_sha256": calc_sha256,
            "calculated_md5": calc_md5
        }

    def record_dump_artifact(self, case_id: str, evidence_id: str, dump_type: str,
                             source_plugin: str, output_path: str, pid: Optional[int] = None,
                             address: str = "") -> DumpArtifact:
        if not os.path.isfile(output_path):
            raise FileNotFoundError(f"Target dump does not exist: {output_path}")

        sha256_val, _ = self.compute_hashes_sync(output_path)
        art = DumpArtifact(
            case_id=case_id,
            evidence_id=evidence_id,
            dump_type=dump_type,
            source_plugin=source_plugin,
            output_path=os.path.abspath(output_path),
            sha256=sha256_val,
            pid=pid,
            address=address
        )
        self.db.create_dump_artifact(art)
        return art

    def list_evidence(self, case_id: str = "") -> List[Evidence]:
        if case_id:
            return self.db.list_evidence_for_case(case_id)
        c = self.db._get_conn().cursor()
        c.execute("SELECT * FROM evidence ORDER BY created_at DESC")
        return [Evidence.from_dict(dict(r)) for r in c.fetchall()]

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self.db.get_evidence(evidence_id)

    def delete_evidence(self, evidence_id: str) -> bool:
        return self.db.delete_evidence(evidence_id)
