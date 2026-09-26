"""
Comprehensive V2 Architecture Verification Test Suite
Tests Domain Models, Strict Risk Thresholds, First-Class Artifacts & Detections,
Finding Lifecycle State Machine, Truthful Reporting (ISO 27037 reference, count consistency),
and V2 REST API Endpoints.
"""

import os
import sys
import unittest
import json
import uuid
import tempfile
import shutil
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from backend.models import (
    Case, Evidence, Artifact, Detection, DetectionRule,
    Finding, FindingArtifact, CustodyEvent, AnalystNote,
    Process, NetworkConnection, TimelineEvent, IOC
)
from backend.infrastructure.database.manager import DatabaseManager
from backend.engines.risk.risk_engine import (
    RiskEngine,
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_SUSPICIOUS
)
from backend.engines.ioc.ioc_engine import IOCEngine
from backend.engines.timeline.timeline_engine import TimelineEngine
from backend.engines.report.report_engine import ReportEngine
from backend.services.finding_service import FindingService


class TestV2Architecture(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_v2.db")
        self.db = DatabaseManager(self.db_path, self.temp_dir)
        self.app_client = app.test_client()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_strict_risk_thresholds(self):
        """Verify strict risk thresholds: <20 is strictly Normal, >=20 Suspicious, >=40 High, >=70 Critical."""
        engine = RiskEngine()

        # 1. Clean process (Risk 0)
        p_clean = {"pid": 100, "name": "explorer.exe", "path": r"c:\windows\explorer.exe"}
        res_clean = engine.evaluate_process(p_clean, [p_clean], [], [])
        self.assertEqual(res_clean["risk_score"], 0)
        self.assertEqual(res_clean["risk_level"], "Normal")
        self.assertEqual(res_clean["severity"], "Normal")

        # 2. Process with external connection only (Weight: 15) -> strictly Normal (< 20)
        p_net = {"pid": 200, "name": "app.exe", "path": r"c:\program files\app.exe"}
        conns = [{"pid": 200, "remote_addr": "8.8.8.8", "remote_port": 443}]
        res_net = engine.evaluate_process(p_net, [p_net], conns, [])
        self.assertEqual(res_net["risk_score"], 15)
        self.assertEqual(res_net["risk_level"], "Normal", "Score < 20 must be strictly Normal")

        # 3. Process with abnormal parent (Weight: 25) -> Suspicious (>= 20)
        p_abnormal = {"pid": 300, "ppid": 999, "name": "svchost.exe", "path": r"c:\windows\system32\svchost.exe"}
        parent = {"pid": 999, "name": "cmd.exe"}
        res_abnormal = engine.evaluate_process(p_abnormal, [p_abnormal, parent], [], [])
        self.assertEqual(res_abnormal["risk_score"], 25)
        self.assertEqual(res_abnormal["risk_level"], "Suspicious", "Score >= 20 must be Suspicious")

        # 4. Hidden process DKOM (Weight: 40) -> High (>= 40)
        p_dkom = {"pid": 400, "name": "rootkit.exe", "in_psscan": True, "in_pslist": False}
        res_dkom = engine.evaluate_process(p_dkom, [p_dkom], [], [])
        self.assertEqual(res_dkom["risk_score"], 40)
        self.assertEqual(res_dkom["risk_level"], "High", "Score >= 40 must be High")

        # 5. DKOM + Injected Memory (Weight: 40 + 35 = 75) -> Critical (>= 70)
        p_crit = {"pid": 500, "name": "malware.exe", "in_psscan": True, "in_pslist": False}
        mems = [{"pid": 500, "start_address": "0x400000"}]
        res_crit = engine.evaluate_process(p_crit, [p_crit], [], mems)
        self.assertEqual(res_crit["risk_score"], 75)
        self.assertEqual(res_crit["risk_level"], "Critical", "Score >= 70 must be Critical")

    def test_first_class_artifacts_and_provenance(self):
        """Verify first-class Artifact entity creation, query, and entity linkage."""
        case_id = "test-case-art"
        ev_id = "test-ev-art"
        self.db.create_case(Case(id=case_id, name="Art Case", investigator="Analyst", description=""))
        self.db.create_evidence(Evidence(id=ev_id, case_id=case_id, filename="dump.raw", filepath="dump.raw"))

        art = Artifact(
            id=str(uuid.uuid4()),
            case_id=case_id,
            evidence_id=ev_id,
            artifact_type="network_connection",
            source_plugin="windows.netscan.NetScan",
            source_execution_id="exec-123",
            entity_id="1044",
            timestamp="2026-09-27T01:00:00",
            raw_reference="Socket TCP 192.168.1.5:49152 -> 198.51.100.23:443",
            normalized_data={"local_ip": "192.168.1.5", "remote_ip": "198.51.100.23", "scope": "External"}
        )
        self.db.create_artifact(art)

        fetched = self.db.get_artifact(art.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.source_plugin, "windows.netscan.NetScan")
        self.assertEqual(fetched.entity_id, "1044")
        self.assertEqual(fetched.normalized_data["scope"], "External")

        by_entity = self.db.list_artifacts(evidence_id=ev_id, entity_id="1044")
        self.assertEqual(len(by_entity), 1)

    def test_finding_lifecycle_state_machine(self):
        """Verify full finding lifecycle and valid/invalid transitions."""
        svc = FindingService(self.db)
        case_id = "test-case-finding"
        self.db.create_case(Case(id=case_id, name="Finding Case", investigator="LeadAnalyst", description=""))

        # 1. Create Finding (Initial state: detected)
        f = svc.create_finding(
            case_id=case_id,
            title="Injected Code in svchost.exe",
            severity="Critical",
            confidence="High",
            status="detected",
            affected_entity="PID 1044 (svchost.exe)",
            associated_pid=1044,
            associated_process_name="svchost.exe"
        )
        self.assertEqual(f.status, "detected")

        # 2. Transition detected -> triaged -> investigating -> confirmed
        f_triaged = svc.transition_status(f.id, "triaged", analyst="LeadAnalyst", reason="Triage verified")
        self.assertEqual(f_triaged.status, "triaged")

        f_inv = svc.transition_status(f.id, "investigating", analyst="LeadAnalyst")
        self.assertEqual(f_inv.status, "investigating")

        f_conf = svc.transition_status(f.id, "confirmed", analyst="LeadAnalyst", reason="RWX shellcode dumped")
        self.assertEqual(f_conf.status, "confirmed")

        # 3. Transition to closed
        f_closed = svc.transition_status(f.id, "closed", analyst="LeadAnalyst", reason="Remediation documented")
        self.assertEqual(f_closed.status, "closed")

        # 4. Invalid status rejection
        with self.assertRaises(ValueError):
            svc.transition_status(f.id, "invalid_status_name")

        # 5. Verify audit notes recorded for transitions
        details = svc.get_finding_details(f.id)
        self.assertGreaterEqual(len(details["notes"]), 4)

    def test_ioc_deduplication_and_artifact_promotion(self):
        """Verify IOC deduplication and explicit artifact-to-IOC promotion."""
        ioc_eng = IOCEngine(self.db)
        case_id = "test-case-ioc"
        self.db.create_case(Case(id=case_id, name="IOC Case", investigator="Analyst", description=""))

        # 1. Add IOC
        ioc1 = ioc_eng.add_ioc(case_id, "IPv4", "198.51.100.25", severity="Medium")
        self.assertIsNotNone(ioc1)

        # 2. Attempt duplicate add -> returns existing, doesn't duplicate
        ioc2 = ioc_eng.add_ioc(case_id, "IPv4", "198.51.100.25", severity="High")
        all_iocs = ioc_eng.list_iocs(case_id)
        self.assertEqual(len(all_iocs), 1, "IOC must not be duplicated")

        # 3. Promote an observed Artifact
        self.db.create_evidence(Evidence(id="ev-1", case_id=case_id, filename="mem.raw", filepath="mem.raw"))
        art = Artifact(
            id=str(uuid.uuid4()),
            case_id=case_id,
            evidence_id="ev-1",
            artifact_type="network_connection",
            source_plugin="windows.netscan.NetScan",
            entity_id="2048",
            raw_reference="198.51.100.99",
            normalized_data={"remote_addr": "198.51.100.99"}
        )
        self.db.create_artifact(art)

        promoted_ioc = ioc_eng.promote_artifact_to_ioc(art.id, case_id, severity="High", analyst="AnalystA")
        self.assertIsNotNone(promoted_ioc)
        self.assertEqual(promoted_ioc.value, "198.51.100.99")
        self.assertEqual(len(ioc_eng.list_iocs(case_id)), 2)

    def test_timeline_engine_provenance_and_exit_integrity(self):
        """Verify timeline engine never asserts process termination unless exit_time is present."""
        tl_engine = TimelineEngine(self.db)
        case_id = "test-case-tl"
        ev_id = "test-ev-tl"

        # Case & Evidence records
        self.db.create_case(Case(id=case_id, name="TL Case", investigator="Analyst", description=""))
        self.db.create_evidence(Evidence(id=ev_id, case_id=case_id, filename="dump.raw", filepath="dump.raw"))

        # Process A: Running (no exit_time)
        p1 = Process(
            evidence_id=ev_id,
            pid=1000,
            name="running.exe",
            create_time="2026-09-27T01:10:00",
            exit_time=""  # Active, not exited
        )
        # Process B: Terminated (explicit exit_time)
        p2 = Process(
            evidence_id=ev_id,
            pid=2000,
            name="dead.exe",
            create_time="2026-09-27T01:05:00",
            exit_time="2026-09-27T01:12:00"
        )
        self.db.upsert_processes_bulk([p1, p2])

        events = tl_engine.generate_timeline(case_id, ev_id)
        
        # Verify: Running process should ONLY have Process Create, NEVER Process Exit
        p1_events = [e for e in events if e.pid == 1000]
        self.assertEqual(len(p1_events), 1)
        self.assertEqual(p1_events[0].event_type, "Process Create")

        # Verify: Terminated process has both Create and Exit
        p2_events = [e for e in events if e.pid == 2000]
        self.assertEqual(len(p2_events), 2)
        event_types = {e.event_type for e in p2_events}
        self.assertIn("Process Create", event_types)
        self.assertIn("Process Exit", event_types)

    def test_truthful_reporting_and_count_consistency(self):
        """Verify report legal claims reference ISO 27037 principles without overclaims,

        and executive summary numbers strictly equal detailed table rows.
        """
        rep_engine = ReportEngine(self.db)
        case_id = "test-case-rep"
        ev_id = "test-ev-rep"

        self.db.create_case(Case(id=case_id, name="Report Truth Case", investigator="Dr. Forensic", description="Test"))
        self.db.create_evidence(Evidence(id=ev_id, case_id=case_id, filename="mem.raw", filepath="mem.raw", file_size=4096, sha256="abc123def456"))

        # Add 3 processes: 1 Critical, 1 Suspicious, 1 Normal
        p1 = Process(evidence_id=ev_id, pid=101, name="bad.exe", risk_score=75, risk_level="Critical")
        p2 = Process(evidence_id=ev_id, pid=102, name="susp.exe", risk_score=25, risk_level="Suspicious")
        p3 = Process(evidence_id=ev_id, pid=103, name="ok.exe", risk_score=10, risk_level="Normal")
        self.db.upsert_processes_bulk([p1, p2, p3])

        # Add 2 connections: 1 external, 1 internal
        c1 = NetworkConnection(evidence_id=ev_id, pid=101, remote_addr="203.0.113.5", remote_port=443, scope="External")
        c2 = NetworkConnection(evidence_id=ev_id, pid=103, remote_addr="192.168.1.1", remote_port=80, scope="Internal")
        self.db.create_connections_bulk([c1, c2])

        # Add 1 finding
        f1 = Finding(case_id=case_id, title="Confirmed Malfind RWX", severity="Critical", status="confirmed")
        self.db.create_finding(f1)

        # Add 1 IOC
        i1 = IOC(case_id=case_id, type="IPv4", value="203.0.113.5", severity="High")
        self.db.create_ioc(i1)

        html_content = rep_engine.generate_html_report(case_id)

        # 1. Truthful ISO 27037 reference check (No unqualified compliance claim)
        self.assertIn("ISO/IEC 27037", html_content)
        self.assertIn("بالاستئناس بمبادئ معيار", html_content, "Must state 'with reference to ISO 27037 principles'")
        self.assertNotIn("معتمد بشهادة ISO", html_content)

        # 2. Executive summary counts consistency
        self.assertIn('<div class="metric-num">3</div>', html_content, "Total extracted processes must be 3")
        self.assertIn('<div class="metric-num">2</div>', html_content, "Suspicious/Critical processes must be 2")
        self.assertIn('<div class="metric-num">1</div>', html_content, "Findings must be 1")

        # 3. Risk threshold check: score 10 must be rendered as Normal
        self.assertIn("طبيعي (Normal)", html_content)

    def test_v2_rest_api_endpoints(self):
        """Verify new V2 REST API blueprints (/api/v2/*)."""
        # 1. Cases V2
        r = self.app_client.get("/api/v2/cases")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "success")

        # 2. Findings V2 creation & listing
        post_data = {
            "title": "API Test Finding",
            "severity": "High",
            "confidence": "High",
            "status": "detected"
        }
        r_post = self.app_client.post("/api/v2/findings", json=post_data)
        self.assertEqual(r_post.status_code, 201)
        fid = r_post.get_json()["finding"]["id"]

        r_get = self.app_client.get(f"/api/v2/findings/{fid}")
        self.assertEqual(r_get.status_code, 200)

        # 3. Status transition via V2 API
        r_trans = self.app_client.post(f"/api/v2/findings/{fid}/status", json={"status": "confirmed", "reason": "Verified"})
        self.assertEqual(r_trans.status_code, 200)
        self.assertEqual(r_trans.get_json()["finding"]["status"], "confirmed")

        # 4. Clean up finding
        r_del = self.app_client.delete(f"/api/v2/findings/{fid}")
        self.assertEqual(r_del.status_code, 200)


if __name__ == "__main__":
    unittest.main()
