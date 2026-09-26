"""
DFIR Workbench V2 - Thread-Safe Database Manager with Automatic Schema Migrations
"""

import sqlite3
import os
import json
import threading
from typing import Optional, List, Dict, Any
from datetime import datetime

from backend.models import (
    Case, Evidence, PluginExecution, PluginResult, Process,
    NetworkConnection, DLL, MemoryRegion, Finding, FindingArtifact,
    IOC, TimelineEvent, Bookmark, AnalystNote, CustodyEvent,
    RiskAssessment, DumpArtifact, Artifact, Detection, DetectionRule
)
from backend.infrastructure.database.schema import SCHEMA_DDL
from core.logger import get_logger

logger = get_logger("app")


class DatabaseManager:
    """Thread-safe SQLite Database Manager for DFIR investigations with WAL mode,

    automatic column migrations, and complete V2 CRUD capabilities.
    """

    def __init__(self, db_path: str, workspace_path: str = "."):
        self.db_path = db_path
        self.workspace_path = workspace_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA foreign_keys=ON")
            except Exception:
                pass
            self._local.conn = conn
        return self._local.conn

    def _init_db(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        conn = self._get_conn()
        
        # Execute schema DDL scripts (creates any missing tables/indexes)
        conn.executescript(SCHEMA_DDL)
        conn.commit()

        # Run automated column migrations for existing databases
        self._migrate_schema()
        logger.info(f"V2 Database initialized and verified: {self.db_path}")

    def _migrate_schema(self):
        """Ensures that newly introduced V2 columns exist in existing tables."""
        conn = self._get_conn()
        cursor = conn.cursor()

        required_columns = {
            "evidence": {
                "verification_status": "TEXT DEFAULT 'Verified'",
                "last_verified": "TEXT"
            },
            "plugin_executions": {
                "raw_output_path": "TEXT",
                "stdout_hash": "TEXT",
                "stderr_hash": "TEXT",
                "result_hash": "TEXT",
                "python_version": "TEXT",
                "platform": "TEXT",
                "plugin_version": "TEXT",
                "symbol_table": "TEXT",
                "configuration": "TEXT",
                "working_directory": "TEXT",
                "execution_host": "TEXT"
            },
            "processes": {
                "confidence": "TEXT DEFAULT 'Medium'",
                "severity": "TEXT DEFAULT 'Normal'",
                "verdict": "TEXT DEFAULT 'unreviewed'"
            },
            "network_connections": {
                "scope": "TEXT DEFAULT 'Internal'",
                "is_ioc": "BOOLEAN DEFAULT 0",
                "threat_intel": "TEXT DEFAULT 'Unknown'"
            },
            "findings": {
                "status": "TEXT DEFAULT 'detected'",
                "affected_entity": "TEXT",
                "summary": "TEXT",
                "technical_description": "TEXT",
                "supporting_evidence": "TEXT",
                "limitations": "TEXT",
                "confidence": "TEXT DEFAULT 'Medium'",
                "threat_intel": "TEXT",
                "investigator": "TEXT",
                "updated_at": "TEXT"
            },
            "timeline_events": {
                "plugin_execution_id": "TEXT",
                "source_artifact_id": "TEXT",
                "confidence": "TEXT DEFAULT 'High'",
                "inferred": "BOOLEAN DEFAULT 0"
            },
            "finding_artifacts": {
                "case_id": "TEXT",
                "role": "TEXT DEFAULT 'supports'",
                "explanation": "TEXT"
            }
        }

        for table, cols in required_columns.items():
            cursor.execute(f"PRAGMA table_info({table})")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            for col_name, col_def in cols.items():
                if col_name not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                        logger.debug(f"Migrated table '{table}': added column '{col_name}'")
                    except Exception as e:
                        logger.warning(f"Column migration warning ({table}.{col_name}): {e}")

        conn.commit()

    # =========================================================================
    # Cases
    # =========================================================================
    def create_case(self, case: Case):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO cases (id, name, investigator, description, status, created_at, updated_at, workspace_path, chain_of_custody)
            VALUES (:id, :name, :investigator, :description, :status, :created_at, :updated_at, :workspace_path, :chain_of_custody)
        """, case.to_dict())
        self._get_conn().commit()

        # Add initial chain of custody event
        self.add_custody_event(CustodyEvent(
            case_id=case.id,
            action="CASE_CREATED",
            actor=case.investigator or "System",
            notes=f"Case '{case.name}' initialized."
        ))

    def get_case(self, case_id: str) -> Optional[Case]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
        row = c.fetchone()
        return Case.from_dict(dict(row)) if row else None

    def list_cases(self) -> List[Case]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM cases ORDER BY created_at DESC")
        return [Case.from_dict(dict(row)) for row in c.fetchall()]

    def update_case(self, case: Case) -> bool:
        c = self._get_conn().cursor()
        c.execute("""
            UPDATE cases SET name=:name, investigator=:investigator, description=:description,
            status=:status, workspace_path=:workspace_path, chain_of_custody=:chain_of_custody,
            updated_at=:updated_at WHERE id=:id
        """, case.to_dict())
        self._get_conn().commit()
        return c.rowcount > 0

    def delete_case(self, case_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM evidence WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM artifacts WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM detections WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM finding_artifacts WHERE finding_id IN (SELECT id FROM findings WHERE case_id = ?)", (case_id,))
        c.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM custody_events WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM analyst_notes WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM iocs WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM timeline_events WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM plugin_executions WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM dump_artifacts WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM bookmarks WHERE case_id = ?", (case_id,))
        c.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    # =========================================================================
    # Evidence & Verification
    # =========================================================================
    def create_evidence(self, evidence: Evidence):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO evidence (
                id, case_id, filename, filepath, file_size, sha256, md5, os_type,
                architecture, kernel_info, vol_compatibility, symbol_status,
                import_timestamp, acquisition_timestamp, status, verification_status,
                last_verified, metadata, created_at
            ) VALUES (
                :id, :case_id, :filename, :filepath, :file_size, :sha256, :md5, :os_type,
                :architecture, :kernel_info, :vol_compatibility, :symbol_status,
                :import_timestamp, :acquisition_timestamp, :status, :verification_status,
                :last_verified, :metadata, :import_timestamp
            )
        """, evidence.to_dict())
        self._get_conn().commit()

        # Add chain of custody event
        self.add_custody_event(CustodyEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            action="EVIDENCE_IMPORTED",
            actor="System",
            hash_after=evidence.sha256 or "",
            notes=f"Evidence file '{evidence.filename}' ({evidence.file_size} bytes) ingested."
        ))

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        row = c.fetchone()
        return Evidence.from_dict(dict(row)) if row else None

    def list_evidence_for_case(self, case_id: str) -> List[Evidence]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY import_timestamp DESC", (case_id,))
        return [Evidence.from_dict(dict(row)) for row in c.fetchall()]

    def update_evidence(self, evidence: Evidence) -> bool:
        c = self._get_conn().cursor()
        c.execute("""
            UPDATE evidence SET os_type=:os_type, architecture=:architecture, kernel_info=:kernel_info,
            vol_compatibility=:vol_compatibility, symbol_status=:symbol_status, status=:status,
            verification_status=:verification_status, last_verified=:last_verified,
            metadata=:metadata WHERE id=:id
        """, evidence.to_dict())
        self._get_conn().commit()
        return c.rowcount > 0

    def delete_evidence(self, evidence_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM processes WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM network_connections WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM dlls WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM memory_regions WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM artifacts WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM detections WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM timeline_events WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM plugin_results WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM plugin_executions WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM dump_artifacts WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM yara_matches WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM risk_assessments WHERE evidence_id = ?", (evidence_id,))
        c.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    # =========================================================================
    # Chain of Custody & Audit
    # =========================================================================
    def add_custody_event(self, event: CustodyEvent):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO custody_events (
                id, case_id, evidence_id, timestamp, action, actor,
                source, destination, hash_before, hash_after, notes, metadata
            ) VALUES (
                :id, :case_id, :evidence_id, :timestamp, :action, :actor,
                :source, :destination, :hash_before, :hash_after, :notes, :metadata
            )
        """, event.to_dict())
        self._get_conn().commit()

    def list_custody_events(self, case_id: str, evidence_id: Optional[str] = None) -> List[CustodyEvent]:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT * FROM custody_events WHERE case_id = ? AND evidence_id = ? ORDER BY timestamp ASC", (case_id, evidence_id))
        else:
            c.execute("SELECT * FROM custody_events WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
        return [CustodyEvent.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # Analyst Notes & Bookmarks
    # =========================================================================
    def add_analyst_note(self, note: AnalystNote):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO analyst_notes (
                id, case_id, entity_id, entity_type, text, author, timestamp, created_at
            ) VALUES (
                :id, :case_id, :entity_id, :entity_type, :text, :author, :timestamp, :created_at
            )
        """, note.to_dict())
        self._get_conn().commit()

    def list_analyst_notes(self, case_id: str, finding_id: Optional[str] = None) -> List[AnalystNote]:
        c = self._get_conn().cursor()
        if finding_id:
            c.execute("SELECT * FROM analyst_notes WHERE case_id = ? AND entity_id = ? AND entity_type = 'finding' ORDER BY created_at DESC", (case_id, finding_id))
        else:
            c.execute("SELECT * FROM analyst_notes WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        return [AnalystNote.from_dict(dict(row)) for row in c.fetchall()]

    def delete_analyst_note(self, note_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM analyst_notes WHERE id = ?", (note_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    def create_bookmark(self, b: Bookmark):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO bookmarks (id, case_id, item_type, item_id, notes, created_at)
            VALUES (:id, :case_id, :item_type, :item_id, :notes, :created_at)
        """, b.to_dict())
        self._get_conn().commit()

    def list_bookmarks(self, case_id: str) -> List[Bookmark]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM bookmarks WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        return [Bookmark.from_dict(dict(row)) for row in c.fetchall()]

    def delete_bookmark(self, bookmark_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM bookmarks WHERE id = ?", (bookmark_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    # =========================================================================
    # Plugin Executions & Results (Reproducibility)
    # =========================================================================
    def create_execution(self, execution: PluginExecution):
        c = self._get_conn().cursor()
        d = execution.to_dict()
        if "vol_version" not in d:
            d["vol_version"] = d.get("volatility_version", "3.x")
        c.execute("""
            INSERT INTO plugin_executions (
                id, evidence_id, case_id, plugin_name, arguments, command, status,
                current_activity, stdout_tail, stderr, error_message, raw_output_path,
                stdout_hash, stderr_hash, result_hash, vol_version, python_version,
                platform, plugin_version, symbol_table, configuration, working_directory,
                execution_host, start_time, end_time, runtime_seconds, result_count, created_at
            ) VALUES (
                :id, :evidence_id, :case_id, :plugin_name, :arguments, :command, :status,
                :current_activity, :stdout_tail, :stderr, :error_message, :raw_output_path,
                :stdout_hash, :stderr_hash, :result_hash, :vol_version, :python_version,
                :platform, :plugin_version, :symbol_table, :configuration, :working_directory,
                :execution_host, :start_time, :end_time, :runtime_seconds, :result_count, :created_at
            )
        """, d)
        self._get_conn().commit()

    def get_execution(self, execution_id: str) -> Optional[PluginExecution]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM plugin_executions WHERE id = ?", (execution_id,))
        row = c.fetchone()
        return PluginExecution.from_dict(dict(row)) if row else None

    def list_executions(self, evidence_id: Optional[str] = None) -> List[PluginExecution]:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT * FROM plugin_executions WHERE evidence_id = ? ORDER BY created_at DESC", (evidence_id,))
        else:
            c.execute("SELECT * FROM plugin_executions ORDER BY created_at DESC")
        return [PluginExecution.from_dict(dict(row)) for row in c.fetchall()]

    def update_execution_status(self, execution_id: str, status: str, error_message: str = "",
                                runtime_seconds: float = 0.0, result_count: int = 0,
                                stdout_hash: str = "", stderr_hash: str = "", result_hash: str = "",
                                raw_output_path: str = ""):
        c = self._get_conn().cursor()
        now = datetime.now().isoformat()
        c.execute("""
            UPDATE plugin_executions SET
                status = ?, error_message = ?, runtime_seconds = ?,
                result_count = ?, end_time = ?, stdout_hash = COALESCE(NULLIF(?, ''), stdout_hash),
                stderr_hash = COALESCE(NULLIF(?, ''), stderr_hash),
                result_hash = COALESCE(NULLIF(?, ''), result_hash),
                raw_output_path = COALESCE(NULLIF(?, ''), raw_output_path)
            WHERE id = ?
        """, (status, error_message, runtime_seconds, result_count, now,
              stdout_hash, stderr_hash, result_hash, raw_output_path, execution_id))
        self._get_conn().commit()

    def update_execution_activity(self, execution_id: str, activity: str, stdout_tail: str = ""):
        c = self._get_conn().cursor()
        c.execute("UPDATE plugin_executions SET current_activity = ?, stdout_tail = ? WHERE id = ?",
                  (activity, stdout_tail, execution_id))
        self._get_conn().commit()

    def store_result(self, result: PluginResult, raw_data: Optional[List] = None):
        if raw_data and len(raw_data) > 5000:
            cache_dir = os.path.join(self.workspace_path, "cache")
            os.makedirs(cache_dir, exist_ok=True)
            fpath = os.path.join(cache_dir, f"result_{result.execution_id}.json")
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump({"headers": json.loads(result.headers) if isinstance(result.headers, str) else result.headers, "data": raw_data}, f)
            result.storage_mode = "file"
            result.file_path = fpath
            result.data = ""
        c = self._get_conn().cursor()
        c.execute("""
            INSERT OR REPLACE INTO plugin_results (
                id, execution_id, evidence_id, plugin_name, headers, data,
                storage_mode, file_path, row_count, created_at
            ) VALUES (
                :id, :execution_id, :evidence_id, :plugin_name, :headers, :data,
                :storage_mode, :file_path, :row_count, :created_at
            )
        """, result.to_dict())
        self._get_conn().commit()

    def get_result(self, execution_id: str) -> Optional[PluginResult]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM plugin_results WHERE execution_id = ?", (execution_id,))
        row = c.fetchone()
        return PluginResult.from_dict(dict(row)) if row else None

    def list_results_for_evidence(self, evidence_id: str) -> List[PluginResult]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM plugin_results WHERE evidence_id = ?", (evidence_id,))
        return [PluginResult.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # First-Class Artifacts (Provenance & Normalization)
    # =========================================================================
    def create_artifact(self, artifact: Artifact):
        self.create_artifacts_bulk([artifact])

    def create_artifacts_bulk(self, artifacts: List[Artifact]):
        if not artifacts:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT OR REPLACE INTO artifacts (
                id, case_id, evidence_id, artifact_type, source_plugin,
                source_execution_id, entity_id, timestamp, raw_reference,
                normalized_data, hash, created_at
            ) VALUES (
                :id, :case_id, :evidence_id, :artifact_type, :source_plugin,
                :source_execution_id, :entity_id, :timestamp, :raw_reference,
                :normalized_data, :hash, :created_at
            )
        """, [a.to_dict() for a in artifacts])
        conn.commit()

    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,))
        row = c.fetchone()
        return Artifact.from_dict(dict(row)) if row else None

    def list_artifacts(self, case_id: Optional[str] = None, evidence_id: Optional[str] = None,
                       artifact_type: Optional[str] = None, entity_id: Optional[str] = None,
                       limit: int = 500) -> List[Artifact]:
        c = self._get_conn().cursor()
        query = "SELECT * FROM artifacts WHERE 1=1"
        params: List[Any] = []
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if evidence_id:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if artifact_type:
            query += " AND artifact_type = ?"
            params.append(artifact_type)
        if entity_id:
            query += " AND entity_id = ?"
            params.append(entity_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        c.execute(query, tuple(params))
        return [Artifact.from_dict(dict(row)) for row in c.fetchall()]

    def count_artifacts(self, evidence_id: Optional[str] = None) -> int:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT COUNT(*) FROM artifacts WHERE evidence_id = ?", (evidence_id,))
        else:
            c.execute("SELECT COUNT(*) FROM artifacts")
        return c.fetchone()[0]

    # =========================================================================
    # Detections & Rules (Automated Detections)
    # =========================================================================
    def create_detection(self, detection: Detection):
        self.create_detections_bulk([detection])

    def create_detections_bulk(self, detections: List[Detection]):
        if not detections:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO detections (
                id, case_id, evidence_id, rule_id, name, category,
                severity, confidence, entity_id, entity_type,
                reason, contributing_factors, supporting_artifacts,
                mitre_technique_id, mitre_technique_name, mitre_tactic,
                created_at
            ) VALUES (
                :id, :case_id, :evidence_id, :rule_id, :name, :category,
                :severity, :confidence, :entity_id, :entity_type,
                :reason, :contributing_factors, :supporting_artifacts,
                :mitre_technique_id, :mitre_technique_name, :mitre_tactic,
                :created_at
            )
        """, [d.to_dict() for d in detections])
        conn.commit()

    def list_detections(self, case_id: Optional[str] = None, evidence_id: Optional[str] = None,
                        affected_entity: Optional[str] = None) -> List[Detection]:
        c = self._get_conn().cursor()
        query = "SELECT * FROM detections WHERE 1=1"
        params: List[Any] = []
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        if evidence_id:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        if affected_entity:
            query += " AND entity_id = ?"
            params.append(affected_entity)
        query += " ORDER BY created_at DESC"
        c.execute(query, tuple(params))
        return [Detection.from_dict(dict(row)) for row in c.fetchall()]

    def get_detection(self, detection_id: str) -> Optional[Detection]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM detections WHERE id = ?", (detection_id,))
        row = c.fetchone()
        return Detection.from_dict(dict(row)) if row else None

    def upsert_detection_rule(self, rule: DetectionRule):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT OR REPLACE INTO detection_rules (
                id, name, description, category, severity, confidence,
                mitre_tactic, mitre_technique_id, mitre_technique_name,
                weight, conditions, references_json, mitre_attack, enabled, version, author, created_at
            ) VALUES (
                :id, :name, :description, :category, :severity, :confidence,
                :mitre_tactic, :mitre_technique_id, :mitre_technique_name,
                :weight, :conditions, :references_json, :mitre_attack, :enabled, :version, :author, :created_at
            )
        """, rule.to_dict())
        self._get_conn().commit()

    def list_detection_rules(self) -> List[DetectionRule]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM detection_rules ORDER BY category, name")
        return [DetectionRule.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # First-Class Findings & Finding Lifecycle
    # =========================================================================
    def create_finding(self, f: Finding):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO findings (
                id, case_id, title, severity, status, affected_entity,
                summary, technical_description, supporting_evidence,
                limitations, confidence, threat_intel, investigator,
                associated_pid, associated_process_name, analyst_assessment,
                created_at, updated_at
            ) VALUES (
                :id, :case_id, :title, :severity, :status, :affected_entity,
                :summary, :technical_description, :supporting_evidence,
                :limitations, :confidence, :threat_intel, :investigator,
                :associated_pid, :associated_process_name, :analyst_assessment,
                :created_at, :updated_at
            )
        """, f.to_dict())
        self._get_conn().commit()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = c.fetchone()
        return Finding.from_dict(dict(row)) if row else None

    def update_finding(self, f: Finding) -> bool:
        c = self._get_conn().cursor()
        c.execute("""
            UPDATE findings SET
                title=:title, severity=:severity, status=:status,
                affected_entity=:affected_entity, summary=:summary,
                technical_description=:technical_description,
                supporting_evidence=:supporting_evidence, limitations=:limitations,
                confidence=:confidence, threat_intel=:threat_intel,
                investigator=:investigator, associated_pid=:associated_pid,
                associated_process_name=:associated_process_name,
                analyst_assessment=:analyst_assessment, updated_at=:updated_at
            WHERE id=:id
        """, f.to_dict())
        self._get_conn().commit()
        return c.rowcount > 0

    def list_findings(self, case_id: str, status: Optional[str] = None) -> List[Finding]:
        c = self._get_conn().cursor()
        if status:
            c.execute("SELECT * FROM findings WHERE case_id = ? AND status = ? ORDER BY created_at DESC", (case_id, status))
        else:
            c.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        return [Finding.from_dict(dict(row)) for row in c.fetchall()]

    def delete_finding(self, finding_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM finding_artifacts WHERE finding_id = ?", (finding_id,))
        c.execute("DELETE FROM analyst_notes WHERE entity_id = ? AND entity_type = 'finding'", (finding_id,))
        c.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    def add_finding_artifact(self, link: FindingArtifact):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT OR REPLACE INTO finding_artifacts (
                id, finding_id, artifact_id, case_id, role, relationship, explanation, created_at
            ) VALUES (
                :id, :finding_id, :artifact_id, :case_id, :role, :relationship, :explanation, :created_at
            )
        """, link.to_dict())
        self._get_conn().commit()

    def get_finding_artifacts(self, finding_id: str) -> List[FindingArtifact]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM finding_artifacts WHERE finding_id = ? ORDER BY created_at ASC", (finding_id,))
        return [FindingArtifact.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # Processes & Correlation
    # =========================================================================
    def upsert_process(self, p: Process):
        self.upsert_processes_bulk([p])

    def upsert_processes_bulk(self, processes: List[Process]):
        if not processes:
            return
        conn = self._get_conn()
        c = conn.cursor()
        for p in processes:
            c.execute("SELECT id, name, create_time, in_pslist, in_psscan, in_pstree, verdict FROM processes WHERE evidence_id = ? AND pid = ?", (p.evidence_id, p.pid))
            rows = c.fetchall()
            target_id = None
            for row in rows:
                same_name = (row["name"] or "").strip().lower() == (p.name or "").strip().lower()
                same_time = bool(row["create_time"] and p.create_time and row["create_time"] == p.create_time)
                time_unknown = not row["create_time"] or not p.create_time
                if same_name or same_time or (time_unknown and (not row["name"] or not p.name or same_name)):
                    target_id = row["id"]
                    if row["in_pslist"]:
                        p.in_pslist = True
                    if row["in_psscan"]:
                        p.in_psscan = True
                    if row["in_pstree"]:
                        p.in_pstree = True
                    if row["verdict"] and not p.verdict:
                        p.verdict = row["verdict"]
                    break
            if target_id:
                p.id = target_id
                c.execute("""
                    UPDATE processes SET
                        ppid=:ppid, name=:name, path=:path, command_line=:command_line,
                        create_time=:create_time, exit_time=:exit_time, session_id=:session_id,
                        user_info=:user_info, in_pslist=:in_pslist, in_psscan=:in_psscan,
                        in_pstree=:in_pstree, risk_score=:risk_score, risk_level=:risk_level,
                        confidence=:confidence, severity=:severity, verdict=:verdict,
                        risk_details=:risk_details, metadata=:metadata
                    WHERE id=:id
                """, p.to_dict())
            else:
                c.execute("""
                    INSERT OR REPLACE INTO processes (
                        id, evidence_id, pid, ppid, name, path, command_line,
                        create_time, exit_time, session_id, user_info, in_pslist,
                        in_psscan, in_pstree, risk_score, risk_level, confidence,
                        severity, verdict, risk_details, metadata
                    ) VALUES (
                        :id, :evidence_id, :pid, :ppid, :name, :path, :command_line,
                        :create_time, :exit_time, :session_id, :user_info, :in_pslist,
                        :in_psscan, :in_pstree, :risk_score, :risk_level, :confidence,
                        :severity, :verdict, :risk_details, :metadata
                    )
                """, p.to_dict())
        conn.commit()

    def list_processes(self, evidence_id: Optional[str] = None) -> List[Process]:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT * FROM processes WHERE evidence_id = ? ORDER BY risk_score DESC, pid ASC", (evidence_id,))
        else:
            c.execute("SELECT * FROM processes ORDER BY risk_score DESC, pid ASC")
        return [Process.from_dict(dict(row)) for row in c.fetchall()]

    def get_process(self, p_id: str) -> Optional[Process]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM processes WHERE id = ?", (p_id,))
        row = c.fetchone()
        return Process.from_dict(dict(row)) if row else None

    def get_process_by_pid(self, evidence_id: str, pid: int) -> Optional[Process]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM processes WHERE evidence_id = ? AND pid = ?", (evidence_id, pid))
        row = c.fetchone()
        return Process.from_dict(dict(row)) if row else None

    def update_process_verdict(self, process_id: str, verdict: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("UPDATE processes SET verdict = ? WHERE id = ?", (verdict, process_id))
        self._get_conn().commit()
        return c.rowcount > 0

    # =========================================================================
    # Network Connections (Observed Artifacts)
    # =========================================================================
    def create_connections_bulk(self, ncs: List[NetworkConnection]):
        if not ncs:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO network_connections (
                id, evidence_id, pid, process_name, local_addr, local_port,
                remote_addr, remote_port, protocol, state, created_time,
                owner, scope, is_ioc, threat_intel
            ) VALUES (
                :id, :evidence_id, :pid, :process_name, :local_addr, :local_port,
                :remote_addr, :remote_port, :protocol, :state, :created_time,
                :owner, :scope, :is_ioc, :threat_intel
            )
        """, [nc.to_dict() for nc in ncs])
        conn.commit()

    def clear_connections_for_evidence(self, evidence_id: str):
        c = self._get_conn().cursor()
        c.execute("DELETE FROM network_connections WHERE evidence_id = ?", (evidence_id,))
        self._get_conn().commit()

    def list_connections(self, evidence_id: Optional[str] = None) -> List[NetworkConnection]:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT * FROM network_connections WHERE evidence_id = ?", (evidence_id,))
        else:
            c.execute("SELECT * FROM network_connections")
        return [NetworkConnection.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # DLLs & Memory Regions
    # =========================================================================
    def create_dlls_bulk(self, dll_list: List[DLL]):
        if not dll_list:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO dlls (id, evidence_id, pid, name, path, base_address, size)
            VALUES (:id, :evidence_id, :pid, :name, :path, :base_address, :size)
        """, [d.to_dict() for d in dll_list])
        conn.commit()

    def list_dlls(self, evidence_id: str, pid: Optional[int] = None) -> List[DLL]:
        c = self._get_conn().cursor()
        if pid is not None:
            c.execute("SELECT * FROM dlls WHERE evidence_id = ? AND pid = ? ORDER BY base_address", (evidence_id, pid))
        else:
            c.execute("SELECT * FROM dlls WHERE evidence_id = ? ORDER BY pid, base_address", (evidence_id,))
        return [DLL.from_dict(dict(row)) for row in c.fetchall()]

    def create_memory_regions_bulk(self, regions: List[MemoryRegion]):
        if not regions:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO memory_regions (id, evidence_id, pid, start_address, protection, tag, suspicious, details)
            VALUES (:id, :evidence_id, :pid, :start_address, :protection, :tag, :suspicious, :details)
        """, [m.to_dict() for m in regions])
        conn.commit()

    def list_memory_regions(self, evidence_id: str, pid: Optional[int] = None) -> List[MemoryRegion]:
        c = self._get_conn().cursor()
        if pid is not None:
            c.execute("SELECT * FROM memory_regions WHERE evidence_id = ? AND pid = ? ORDER BY start_address", (evidence_id, pid))
        else:
            c.execute("SELECT * FROM memory_regions WHERE evidence_id = ? ORDER BY pid, start_address", (evidence_id,))
        return [MemoryRegion.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # IOCs (Deduplicated, Analyst-Confirmed or Threat-Intel Verified)
    # =========================================================================
    def create_ioc(self, i: IOC):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO iocs (
                id, case_id, type, value, severity, source, description,
                associated_finding_id, associated_pid, created_at
            ) VALUES (
                :id, :case_id, :type, :value, :severity, :source, :description,
                :associated_finding_id, :associated_pid, :created_at
            )
        """, i.to_dict())
        self._get_conn().commit()

    def ioc_exists(self, case_id: str, ioc_type: str, value: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("SELECT 1 FROM iocs WHERE case_id = ? AND type = ? AND LOWER(value) = LOWER(?) LIMIT 1",
                  (case_id, ioc_type, value.strip()))
        return c.fetchone() is not None

    def list_iocs(self, case_id: str) -> List[IOC]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM iocs WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        return [IOC.from_dict(dict(row)) for row in c.fetchall()]

    def delete_ioc(self, ioc_id: str) -> bool:
        c = self._get_conn().cursor()
        c.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
        self._get_conn().commit()
        return c.rowcount > 0

    # =========================================================================
    # Timeline
    # =========================================================================
    def create_event(self, e: TimelineEvent):
        self.create_events_bulk([e])

    def create_events_bulk(self, events: List[TimelineEvent]):
        if not events:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT OR REPLACE INTO timeline_events (
                id, evidence_id, case_id, timestamp, event_type, description,
                pid, process_name, source_plugin, severity, details,
                plugin_execution_id, source_artifact_id, confidence, inferred
            ) VALUES (
                :id, :evidence_id, :case_id, :timestamp, :event_type, :description,
                :pid, :process_name, :source_plugin, :severity, :details,
                :plugin_execution_id, :source_artifact_id, :confidence, :inferred
            )
        """, [e.to_dict() for e in events])
        conn.commit()

    def clear_events(self, evidence_id: str):
        c = self._get_conn().cursor()
        c.execute("DELETE FROM timeline_events WHERE evidence_id = ?", (evidence_id,))
        self._get_conn().commit()

    def list_events(self, evidence_id: Optional[str] = None, case_id: Optional[str] = None) -> List[TimelineEvent]:
        c = self._get_conn().cursor()
        if evidence_id:
            c.execute("SELECT * FROM timeline_events WHERE evidence_id = ? ORDER BY timestamp ASC", (evidence_id,))
        elif case_id:
            c.execute("SELECT * FROM timeline_events WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
        else:
            c.execute("SELECT * FROM timeline_events ORDER BY timestamp ASC")
        return [TimelineEvent.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # Risk Assessments
    # =========================================================================
    def create_risk_assessments_bulk(self, assessments: List[RiskAssessment]):
        if not assessments:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO risk_assessments (
                id, evidence_id, pid, rule_id, rule_name, category,
                weight, reason, evidence_text, confidence, created_at
            ) VALUES (
                :id, :evidence_id, :pid, :rule_id, :rule_name, :category,
                :weight, :reason, :evidence_text, :confidence, :created_at
            )
        """, [a.to_dict() for a in assessments])
        conn.commit()

    def clear_risk_assessments(self, evidence_id: str):
        c = self._get_conn().cursor()
        c.execute("DELETE FROM risk_assessments WHERE evidence_id = ?", (evidence_id,))
        self._get_conn().commit()

    def list_risk_assessments(self, evidence_id: str, pid: Optional[int] = None) -> List[RiskAssessment]:
        c = self._get_conn().cursor()
        if pid is not None:
            c.execute("SELECT * FROM risk_assessments WHERE evidence_id = ? AND pid = ? ORDER BY weight DESC", (evidence_id, pid))
        else:
            c.execute("SELECT * FROM risk_assessments WHERE evidence_id = ? ORDER BY pid, weight DESC", (evidence_id,))
        return [RiskAssessment.from_dict(dict(row)) for row in c.fetchall()]

    # =========================================================================
    # Dumps & YARA
    # =========================================================================
    def create_dump_artifact(self, artifact: DumpArtifact):
        c = self._get_conn().cursor()
        c.execute("""
            INSERT INTO dump_artifacts (
                id, case_id, evidence_id, dump_type, source_plugin, output_path,
                sha256, pid, address, created_at
            ) VALUES (
                :id, :case_id, :evidence_id, :dump_type, :source_plugin, :output_path,
                :sha256, :pid, :address, :created_at
            )
        """, artifact.to_dict())
        self._get_conn().commit()

    def list_dump_artifacts(self, case_id: Optional[str] = None, evidence_id: Optional[str] = None) -> List[DumpArtifact]:
        c = self._get_conn().cursor()
        if case_id:
            c.execute("SELECT * FROM dump_artifacts WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        elif evidence_id:
            c.execute("SELECT * FROM dump_artifacts WHERE evidence_id = ? ORDER BY created_at DESC", (evidence_id,))
        else:
            c.execute("SELECT * FROM dump_artifacts ORDER BY created_at DESC")
        return [DumpArtifact.from_dict(dict(row)) for row in c.fetchall()]

    def create_yara_matches_bulk(self, matches: List[Dict]):
        if not matches:
            return
        conn = self._get_conn()
        c = conn.cursor()
        c.executemany("""
            INSERT INTO yara_matches (id, evidence_id, pid, process_name, rule, offset, details, created_at)
            VALUES (:id, :evidence_id, :pid, :process_name, :rule, :offset, :details, :created_at)
        """, matches)
        conn.commit()

    def list_yara_matches(self, evidence_id: str) -> List[Dict]:
        c = self._get_conn().cursor()
        c.execute("SELECT * FROM yara_matches WHERE evidence_id = ? ORDER BY pid, rule", (evidence_id,))
        return [dict(row) for row in c.fetchall()]
