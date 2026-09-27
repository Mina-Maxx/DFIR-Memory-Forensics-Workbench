"""
Audit Remediation Verification Test Suite
Tests fixes for audit findings:
- P0.1 / P0.2 / P0.3: Security, YARA synthetic mock removal, safe upload collision
- P1.1: Cross-case artifact attachment rejection
- P1.3: Evidence default Unverified status
- P1.5: Malfind RWX protection inspection
- P1.6: IPv6 / port handling & conditional IOC qualification
- P1.7: Process source plugin tagging & network timestamp preservation
- P1.8: Finding state machine strictness
- P1.9: Query parameter bounding and enum validation
"""

import os
import sys
import unittest
import json
import tempfile
import shutil
import io
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from backend.models import (
    Case, Evidence, Artifact, Finding, Process, NetworkConnection
)
from backend.infrastructure.database.manager import DatabaseManager
from backend.services.finding_service import FindingService
from backend.services.evidence_service import EvidenceService
from backend.engines.risk.risk_engine import RiskEngine
from backend.engines.ioc.ioc_engine import IOCEngine
from backend.engines.timeline.timeline_engine import TimelineEngine
from backend.engines.correlation.investigation_engine import InvestigationEngine


class TestAuditRemediations(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_audit.db")
        self.db = DatabaseManager(self.db_path, self.temp_dir)
        self.client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_p0_2_yara_scan_no_synthetic_matches(self):
        """P0.2: /api/yara/scan must NOT return synthetic mock matches when 0 rules match."""
        rule_content = 'rule TestNoMatch { strings: $a = "UNIQUE_DFIR_AUDIT_STRING_NEVER_FOUND" condition: $a }'
        response = self.client.post("/api/yara/scan", json={
            "rule_text": rule_content,
            "evidence_id": "non-existent-id"
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        # Ensure count is 0 and no fake Heuristic_Suspicious_Memory PID 4284 is fabricated
        self.assertEqual(data.get("count"), 0)
        self.assertEqual(len(data.get("matches", [])), 0)

    def test_p0_3_upload_file_collision_safety(self):
        """P0.3: Uploads must not silently overwrite existing files."""
        # Upload file 1
        data1 = {"file": (io.BytesIO(b"memory-content-1"), "memdump_collision_test.raw")}
        res1 = self.client.post("/api/upload", data=data1, content_type="multipart/form-data")
        self.assertEqual(res1.status_code, 200)
        json1 = res1.get_json()
        self.assertTrue(json1.get("success"))
        path1 = json1.get("evidence", {}).get("filepath")
        self.assertIsNotNone(path1)
        self.assertTrue(os.path.exists(path1))

        # Upload file 2 with same original name
        data2 = {"file": (io.BytesIO(b"memory-content-2-different"), "memdump_collision_test.raw")}
        res2 = self.client.post("/api/upload", data=data2, content_type="multipart/form-data")
        self.assertEqual(res2.status_code, 200)
        json2 = res2.get_json()
        self.assertTrue(json2.get("success"))
        path2 = json2.get("evidence", {}).get("filepath")
        self.assertIsNotNone(path2)
        self.assertTrue(os.path.exists(path2))

        # The two saved paths must be distinct to prevent overwrite
        self.assertNotEqual(path1, path2)

        # Content of first file must remain intact
        with open(path1, "rb") as f:
            self.assertEqual(f.read(), b"memory-content-1")
        with open(path2, "rb") as f:
            self.assertEqual(f.read(), b"memory-content-2-different")

        # Clean up created upload files
        try:
            os.remove(path1)
            os.remove(path2)
        except OSError:
            pass

    def test_p1_1_cross_case_artifact_attachment_prevention(self):
        """P1.1: Attaching an artifact from Case B to a Finding in Case A must be rejected."""
        case_a = Case(id="case-A", name="Case A", investigator="Analyst", description="")
        case_b = Case(id="case-B", name="Case B", investigator="Analyst", description="")
        self.db.create_case(case_a)
        self.db.create_case(case_b)

        ev_a = Evidence(id="ev-A", case_id="case-A", filename="memA.raw", filepath="memA.raw")
        ev_b = Evidence(id="ev-B", case_id="case-B", filename="memB.raw", filepath="memB.raw")
        self.db.create_evidence(ev_a)
        self.db.create_evidence(ev_b)

        finding_svc = FindingService(self.db)
        finding_a = finding_svc.create_finding(
            case_id="case-A",
            title="Finding in Case A",
            severity="High"
        )

        artifact_b = Artifact(
            id=str(uuid.uuid4()),
            case_id="case-B",
            evidence_id="ev-B",
            artifact_type="memory_dump",
            source_plugin="windows.malfind.Malfind",
            entity_id="1044"
        )
        self.db.create_artifact(artifact_b)

        # Attaching artifact from case-B to finding in case-A must raise ValueError
        with self.assertRaises(ValueError):
            finding_svc.attach_artifact(
                finding_id=finding_a.id,
                artifact_id=artifact_b.id
            )

    def test_p1_3_evidence_default_verification_status(self):
        """P1.3: Newly created Evidence must default to 'Unverified', not 'Verified'."""
        ev = Evidence(id="ev-unverified-test", case_id="case-1", filename="mem.raw", filepath="mem.raw")
        self.assertEqual(ev.verification_status, "Unverified")
        self.assertEqual(ev.last_verified, "")

    def test_p1_5_malfind_protection_inspection(self):
        """P1.5: Malfind rule checks memory protection flags for RWX."""
        engine = RiskEngine()
        proc = {"pid": 2000, "name": "test.exe", "path": r"c:\windows\test.exe"}

        # RWX anomaly
        rwx_anomalies = [{"pid": 2000, "start_address": "0x1000", "protection": "PAGE_EXECUTE_READWRITE"}]
        res_rwx = engine.evaluate_process(proc, [proc], [], rwx_anomalies)
        rwx_rule = [i for i in res_rwx["indicators"] if i["rule_id"] == "R-MEM-01"]
        self.assertTrue(len(rwx_rule) > 0)
        self.assertIn("confirmed RWX", rwx_rule[0]["reason"])

        # Non-RWX anomaly (e.g. read-only anomaly)
        ro_anomalies = [{"pid": 2000, "start_address": "0x1000", "protection": "PAGE_READONLY"}]
        res_ro = engine.evaluate_process(proc, [proc], [], ro_anomalies)
        ro_rule = [i for i in res_ro["indicators"] if i["rule_id"] == "R-MEM-01"]
        self.assertTrue(len(ro_rule) > 0)
        self.assertIn("Protection: PAGE_READONLY", ro_rule[0]["reason"])
        self.assertLess(ro_rule[0]["weight"], rwx_rule[0]["weight"])

    def test_p1_6_ipv6_parsing_and_ioc_harvesting(self):
        """P1.6: IPv6 parsing handles bracketed notations and distinguishes observed connections."""
        case_id = "test-case-ioc-p16"
        ev_id = "test-ev-ioc-p16"
        self.db.create_case(Case(id=case_id, name="Case IOC", investigator="Analyst", description=""))
        self.db.create_evidence(Evidence(id=ev_id, case_id=case_id, filename="mem.raw", filepath="mem.raw"))

        # Process 100: Normal (risk_score = 15)
        p1 = Process(evidence_id=ev_id, pid=100, name="normal.exe", risk_score=15)
        # Process 200: Suspicious (risk_score = 60)
        p2 = Process(evidence_id=ev_id, pid=200, name="malware.exe", risk_score=60)
        self.db.upsert_processes_bulk([p1, p2])

        # Connection 1: Bracketed public IPv6 on normal process
        c1 = NetworkConnection(evidence_id=ev_id, pid=100, remote_addr="[2606:2800:220:1:248:1893:25c8:1946]:8080", remote_port=8080)
        # Connection 2: External public IPv4 on suspicious process
        c2 = NetworkConnection(evidence_id=ev_id, pid=200, remote_addr="93.184.216.34:443", remote_port=443)
        self.db.create_connections_bulk([c1, c2])

        engine = IOCEngine(self.db)
        harvested = engine.harvest_from_network(case_id, ev_id)

        # Process 100's IP was observed as an Artifact, but NOT promoted to an IOC because risk_score < 40
        # Process 200's IP was promoted to an IOC because risk_score >= 40
        self.assertEqual(len(harvested), 1)
        self.assertEqual(harvested[0].value, "93.184.216.34")

        # Verify observed artifacts include both connections
        arts = self.db.list_artifacts(case_id=case_id, evidence_id=ev_id, artifact_type="network_connection")
        self.assertEqual(len(arts), 2)

    def test_p1_8_finding_state_machine_transitions(self):
        """P1.8: Finding state transitions must adhere to valid lifecycle."""
        case_id = "case-SM-test"
        self.db.create_case(Case(id=case_id, name="SM Case", investigator="Analyst", description=""))

        finding_svc = FindingService(self.db)
        finding = finding_svc.create_finding(case_id=case_id, title="State Machine Finding")
        self.assertEqual(finding.status, "detected")

        # Invalid transition: detected -> closed directly is not allowed
        with self.assertRaises(ValueError):
            finding_svc.transition_status(finding.id, "closed", analyst="Tester")

        # Valid transition: detected -> triaged -> investigating -> confirmed -> closed
        finding_svc.transition_status(finding.id, "triaged", analyst="Tester")
        self.assertEqual(self.db.get_finding(finding.id).status, "triaged")

        finding_svc.transition_status(finding.id, "investigating", analyst="Tester")
        self.assertEqual(self.db.get_finding(finding.id).status, "investigating")

        finding_svc.transition_status(finding.id, "confirmed", analyst="Tester")
        self.assertEqual(self.db.get_finding(finding.id).status, "confirmed")

        finding_svc.transition_status(finding.id, "closed", analyst="Tester")
        self.assertEqual(self.db.get_finding(finding.id).status, "closed")

    def test_p1_9_api_bounds_and_enum_validation(self):
        """P1.9: Query parameter bounds and enum validations return HTTP 400 on bad input."""
        # Negative limit
        res_neg = self.client.get("/api/v2/findings?limit=-10")
        self.assertEqual(res_neg.status_code, 400)

        # Limit exceeding 5000
        res_overflow = self.client.get("/api/v2/findings?limit=99999")
        self.assertEqual(res_overflow.status_code, 400)

        # Invalid severity enum
        res_sev = self.client.get("/api/v2/findings?severity=SUPER_CRITICAL")
        self.assertEqual(res_sev.status_code, 400)

        # Artifacts limit out of bounds
        res_art = self.client.get("/api/v2/artifacts?limit=0")
        self.assertEqual(res_art.status_code, 400)

        # Process verdict invalid enum
        res_verdict = self.client.post("/api/v2/processes/100/verdict?evidence_id=dummy", json={"verdict": "INVALID_VERDICT"})
        self.assertEqual(res_verdict.status_code, 400)

    def test_p0_secret_key_configuration(self):
        """P0: Ensure SECRET_KEY is not static/hardcoded and is at least 32 characters."""
        self.assertIsNotNone(app.config.get("SECRET_KEY"))
        self.assertNotEqual(app.config["SECRET_KEY"], "dfir-workbench-secret-2026")
        self.assertGreaterEqual(len(app.config["SECRET_KEY"]), 32)

    def test_p0_api_key_authentication(self):
        """P0: When DFIR_API_KEY is configured, protected endpoints require valid key."""
        import app as app_mod
        original_key = app_mod.DFIR_API_KEY
        try:
            app_mod.DFIR_API_KEY = "test-secret-api-key-9988"
            
            # 1. Protected endpoint without key -> 401
            res_no_key = self.client.delete("/api/cases/test-case-id")
            self.assertEqual(res_no_key.status_code, 401)
            self.assertIn("Unauthorized", res_no_key.get_json().get("error", ""))

            # 2. Protected endpoint with invalid key -> 401
            res_bad_key = self.client.delete("/api/cases/test-case-id", headers={"X-API-Key": "wrong-key"})
            self.assertEqual(res_bad_key.status_code, 401)

            # 3. Protected endpoint with valid X-API-Key header -> proceeds past auth
            res_valid_x = self.client.delete("/api/cases/non-existent-case-uuid", headers={"X-API-Key": "test-secret-api-key-9988"})
            self.assertNotEqual(res_valid_x.status_code, 401)

            # 4. Protected endpoint with valid Bearer token -> proceeds past auth
            res_valid_bearer = self.client.delete("/api/cases/non-existent-case-uuid", headers={"Authorization": "Bearer test-secret-api-key-9988"})
            self.assertNotEqual(res_valid_bearer.status_code, 401)
        finally:
            app_mod.DFIR_API_KEY = original_key

    def test_p0_upload_hardening_extension_whitelist(self):
        """P0: Enforce strict memory dump extension whitelist on /api/upload."""
        # Forbidden extension (.exe)
        bad_data = {"file": (io.BytesIO(b"MZ\x90\x00malicious-executable"), "malware.exe")}
        res_bad = self.client.post("/api/upload", data=bad_data, content_type="multipart/form-data")
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn("Invalid file extension", res_bad.get_json().get("error", ""))

        # Forbidden extension (.py)
        bad_py = {"file": (io.BytesIO(b"print('attack')"), "script.py")}
        res_py = self.client.post("/api/upload", data=bad_py, content_type="multipart/form-data")
        self.assertEqual(res_py.status_code, 400)
        self.assertIn("Invalid file extension", res_py.get_json().get("error", ""))

        # Allowed extension (.vmem)
        good_data = {"file": (io.BytesIO(b"valid-memory-dump-bytes"), "snapshot.vmem")}
        res_good = self.client.post("/api/upload", data=good_data, content_type="multipart/form-data")
        self.assertEqual(res_good.status_code, 200)
        self.assertTrue(res_good.get_json().get("success"))

    def test_p1_logging_rotation(self):
        """P1: Verify activity logger utilizes RotatingFileHandler with bounded size."""
        from logging.handlers import RotatingFileHandler
        import app as app_mod
        handlers = [h for h in app_mod.activity_logger.handlers if isinstance(h, RotatingFileHandler)]
        self.assertTrue(len(handlers) > 0, "activity_logger does not have a RotatingFileHandler")
        handler = handlers[0]
        self.assertEqual(handler.maxBytes, 10 * 1024 * 1024)
        self.assertEqual(handler.backupCount, 5)


if __name__ == "__main__":
    unittest.main()

