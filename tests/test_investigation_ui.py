"""
Unit & Integration Tests for Investigation-First V2 Endpoints:
- Global Forensic Search (/api/v2/search)
- Investigation Coverage & Action Items (/api/v2/investigation/coverage)
- Analyst Notes (/api/v2/notes)
- Evidence Board (/api/v2/board)
- Memory Anomalies (/api/v2/memory)
- Loaded Modules/DLLs (/api/v2/dlls)
"""

import os
import sys
import unittest
import json
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app


class TestInvestigationUIEndpoints(unittest.TestCase):

    def setUp(self):
        self.app_client = app.test_client()

    def test_global_search_empty(self):
        """Verify global search handles empty and whitespace queries gracefully."""
        res = self.app_client.get("/api/v2/search?q=")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["query"], "")
        self.assertEqual(data["counts"]["processes"], 0)
        self.assertEqual(data["results"]["processes"], [])

    def test_global_search_query(self):
        """Verify global search returns structured grouped results."""
        res = self.app_client.get("/api/v2/search?q=svchost")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("counts", data)
        self.assertIn("results", data)
        self.assertIn("processes", data["results"])
        self.assertIn("network_connections", data["results"])
        self.assertIn("artifacts", data["results"])
        self.assertIn("detections", data["results"])
        self.assertIn("findings", data["results"])
        self.assertIn("iocs", data["results"])
        self.assertIn("timeline_events", data["results"])

    def test_investigation_coverage(self):
        """Verify investigation coverage endpoint computes correct structure and ratios."""
        res = self.app_client.get("/api/v2/investigation/coverage")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("process_coverage", data)
        self.assertIn("risk_coverage", data)
        self.assertIn("action_items", data)
        self.assertIn("findings_breakdown", data)
        self.assertIn("evidence", data)
        self.assertIn("coverage_percent", data["process_coverage"])
        self.assertIn("high_risk_total", data["risk_coverage"])

    def test_analyst_notes_lifecycle(self):
        """Verify creation, listing, and deletion of analyst investigation notes."""
        test_case_id = f"test-case-note-{uuid.uuid4().hex[:6]}"
        # Ensure parent case exists
        self.app_client.post("/api/cases", json={"case_id": test_case_id, "name": "Note Test Case"})

        payload = {
            "case_id": test_case_id,
            "note_text": "Investigating unlinked DKOM process in memory space",
            "entity_type": "process",
            "entity_id": "1428",
            "author": "Forensic Specialist"
        }
        create_res = self.app_client.post("/api/v2/notes", json=payload)
        self.assertEqual(create_res.status_code, 201)
        created = create_res.get_json()
        self.assertEqual(created["status"], "success")
        note_id = created["note"]["id"]

        # List notes
        list_res = self.app_client.get(f"/api/v2/notes?case_id={test_case_id}")
        self.assertEqual(list_res.status_code, 200)
        notes = list_res.get_json().get("notes", [])
        self.assertTrue(any(n["id"] == note_id for n in notes))

        # Delete note
        del_res = self.app_client.delete(f"/api/v2/notes/{note_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.get_json()["status"], "success")

    def test_evidence_board_lifecycle(self):
        """Verify pinning, listing, and unpinning items on the Evidence Board."""
        test_case_id = f"test-case-board-{uuid.uuid4().hex[:6]}"
        # Ensure parent case exists
        self.app_client.post("/api/cases", json={"case_id": test_case_id, "name": "Board Test Case"})

        payload = {
            "case_id": test_case_id,
            "entity_type": "process",
            "entity_id": "2968",
            "title": "svchost.exe (Injected)",
            "notes": "Observed hollowed process with RWX memory segments.",
            "color": "red",
            "tags": ["injection", "c2"]
        }
        create_res = self.app_client.post("/api/v2/board", json=payload)
        self.assertEqual(create_res.status_code, 201)
        created = create_res.get_json()
        self.assertEqual(created["status"], "success")
        item_id = created["item"]["id"]

        # List board items
        list_res = self.app_client.get(f"/api/v2/board?case_id={test_case_id}")
        self.assertEqual(list_res.status_code, 200)
        items = list_res.get_json().get("board_items", [])
        self.assertTrue(any(b["id"] == item_id for b in items))

        # Delete board item
        del_res = self.app_client.delete(f"/api/v2/board/{item_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.get_json()["status"], "success")

    def test_memory_anomalies_endpoint(self):
        """Verify /api/v2/memory returns properly formatted memory regions and counts."""
        res = self.app_client.get("/api/v2/memory")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("regions", data)
        self.assertIn("total", data)
        self.assertIn("rwx_count", data)
        self.assertIn("suspicious_count", data)
        self.assertIn("unique_pids", data)

    def test_dlls_endpoint(self):
        """Verify /api/v2/dlls returns properly formatted DLL enumeration and counts."""
        res = self.app_client.get("/api/v2/dlls")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("dlls", data)
        self.assertIn("total", data)
        self.assertIn("unique_names", data)


if __name__ == "__main__":
    unittest.main()
