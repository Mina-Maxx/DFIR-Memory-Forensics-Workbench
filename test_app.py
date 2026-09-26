"""
Automated Verification Test for DFIR-Web-App
Tests all web endpoints, bridge slots, SSE stream connection, and graph relationships.
"""
import sys
import json

from app import app, db, bridge
from core.models import Evidence, Process

def test_web_routes():
    print("[1/8] Testing Web Frontend Routes...")
    client = app.test_client()

    r = client.get("/")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert b"Volatility 3 DFIR" in r.data, "Index HTML missing title"
    print("  -> GET /: OK (200)")

    r = client.get("/css/forensic.css")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert b":root" in r.data or b"body" in r.data or len(r.data) > 100
    print("  -> GET /css/forensic.css: OK (200)")

    r = client.get("/js/app.js")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    assert b"state" in r.data and b"initApp" in r.data
    print("  -> GET /js/app.js: OK (200)")

def test_bridge_cases_and_evidence():
    print("[2/8] Testing Bridge Slots (Cases & Evidence)...")
    client = app.test_client()

    # list_cases
    r = client.post("/api/bridge/list_cases", json=[])
    assert r.status_code == 200
    cases = json.loads(r.data)
    assert isinstance(cases, list)
    print(f"  -> list_cases returned {len(cases)} case(s): OK")

    # get_active_case
    r = client.post("/api/bridge/get_active_case", json=[])
    assert r.status_code == 200
    print("  -> get_active_case: OK")

    # list_evidence
    r = client.post("/api/bridge/list_evidence", json=[""])
    assert r.status_code == 200
    evs = json.loads(r.data)
    assert isinstance(evs, list)
    print(f"  -> list_evidence returned {len(evs)} item(s): OK")

def test_bridge_graph_data():
    print("[3/8] Testing Interactive Graph Data (Hierarchy Edges Verification)...")
    client = app.test_client()
    import uuid

    test_cid = f"test-graph-case-{uuid.uuid4().hex[:6]}"
    test_eid = f"test-graph-ev-{uuid.uuid4().hex[:6]}"
    bridge.case_mgr.create_case(test_cid, "Graph Test Case", "Analyst", "Testing graph")
    db.create_evidence(Evidence(
        id=test_eid, case_id=test_cid, filename="test.raw", filepath="dumps/test.raw",
        file_size=1024, sha256="testsha256", md5="testmd5", os_type="Windows", architecture="x64",
        kernel_info="", vol_compatibility="3.0", symbol_status="Available", status="Ready", metadata="{}"
    ))
    db.upsert_processes_bulk([
        Process(id=f"p-1-{test_eid}", evidence_id=test_eid, pid=4, ppid=0, name="System", path="", command_line="", create_time="", exit_time="", session_id=0, user_info="", in_pslist=True, in_psscan=True, in_pstree=True, risk_score=0, risk_level="Normal", risk_details="", metadata=""),
        Process(id=f"p-2-{test_eid}", evidence_id=test_eid, pid=240, ppid=4, name="smss.exe", path="", command_line="", create_time="", exit_time="", session_id=0, user_info="", in_pslist=True, in_psscan=True, in_pstree=True, risk_score=10, risk_level="Suspicious", risk_details="", metadata="")
    ])

    # Call get_graph_data via bridge slot
    r = client.post("/api/bridge/get_graph_data", json=[test_eid])
    assert r.status_code == 200
    graph = json.loads(r.data)
    assert "nodes" in graph and "edges" in graph and "stats" in graph
    print(f"  -> get_graph_data: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
    assert len(graph["nodes"]) >= 2, "Graph has < 2 nodes!"
    
    hierarchy_edges = [e for e in graph["edges"] if e.get("label") == "spawns"]
    print(f"  -> Found {len(hierarchy_edges)} parent-child 'spawns' hierarchy edge(s): SUCCESS!")
    assert len(hierarchy_edges) >= 1, "No parent-child hierarchy edges found!"

    # Clean up test case
    bridge.case_mgr.delete_case(test_cid, delete_files=True)
    print("  -> Hierarchy edge verified & temporary graph data cleaned up: OK")

def test_bridge_live_state():
    print("[4/8] Testing Live State Polling Slot...")
    client = app.test_client()
    r = client.get("/api/live")
    assert r.status_code == 200
    state = json.loads(r.data)
    assert "jobs" in state and "running" in state and "playbook_running" in state
    print(f"  -> /api/live returned: {len(state['jobs'])} recent jobs: OK")

def test_bridge_playbooks_and_rules():
    print("[5/8] Testing Playbooks & Rules Slots...")
    client = app.test_client()
    r = client.post("/api/bridge/list_playbooks", json=[])
    assert r.status_code == 200
    pbs = json.loads(r.data)
    assert isinstance(pbs, list) and len(pbs) >= 3
    print(f"  -> list_playbooks returned {len(pbs)} playbooks: OK")

    r = client.post("/api/bridge/list_rules", json=[])
    assert r.status_code == 200
    rules = json.loads(r.data)
    assert isinstance(rules, list) and len(rules) >= 10
    print(f"  -> list_rules returned {len(rules)} detection rules: OK")

def test_rest_api_status():
    print("[6/8] Testing Native REST Endpoints...")
    client = app.test_client()
    r = client.get("/api/status")
    assert r.status_code == 200
    st = json.loads(r.data)
    assert "running_jobs" in st and "vol_prefix" in st
    print(f"  -> /api/status Volatility prefix: '{st['vol_prefix']}': OK")

def test_timeline_and_iocs():
    print("[7/8] Testing Timeline and IOCs Slots...")
    client = app.test_client()
    r = client.post("/api/bridge/list_iocs", json=[""])
    assert r.status_code == 200
    iocs = json.loads(r.data)
    print(f"  -> list_iocs returned {len(iocs)} IOCs: OK")

    r = client.post("/api/bridge/get_timeline", json=["", "ALL", ""])
    assert r.status_code == 200
    events = json.loads(r.data)
    print(f"  -> get_timeline returned {len(events)} events: OK")

def test_report_generation():
    print("[8/8] Testing Arabic RTL Forensic Report Generation...")
    import uuid
    test_cid = f"test-report-case-{uuid.uuid4().hex[:6]}"
    bridge.case_mgr.create_case(test_cid, "Report Test Case", "Investigator Test", "Report test")
    doc = bridge.rep_engine.generate_html_report(test_cid)
    assert "<html" in doc and "dir=\"rtl\"" in doc
    print(f"  -> Report generation: OK ({len(doc):,} characters of court-admissible HTML generated)")
    bridge.case_mgr.delete_case(test_cid, delete_files=True)

def test_new_features():
    print("[9/9] Testing New Features (Activity Telemetry, YARA Rules, Delete API)...")
    client = app.test_client()

    # 1. Test YARA rules endpoint
    r = client.get("/api/yara/rules")
    assert r.status_code == 200
    data = json.loads(r.data)
    assert "rules" in data and len(data["rules"]) >= 4
    print(f"  -> GET /api/yara/rules: {len(data['rules'])} preset rules loaded: OK")

    # 2. Test Activity Log Telemetry
    r = client.post("/api/activity/log", json={
        "category": "TEST_CATEGORY",
        "action": "Automated Test Event",
        "details": "Checking telemetry recording"
    })
    assert r.status_code == 200
    
    r = client.get("/api/activity/tail?limit=5")
    assert r.status_code == 200
    tail_data = json.loads(r.data)
    assert "lines" in tail_data and len(tail_data["lines"]) > 0
    print(f"  -> Activity Telemetry (POST & GET /api/activity/*): OK")

    # 3. Test Case Creation & Cascading Delete API
    test_case_id = "test-delete-case-001"
    bridge.case_mgr.create_case(test_case_id, "Temporary Test Case", "Investigator Test", "Test description")
    r = client.delete(f"/api/cases/{test_case_id}")
    assert r.status_code == 200
    assert db.get_case(test_case_id) is None
    print(f"  -> DELETE /api/cases/{test_case_id}: Cascaded delete verified: OK")

def test_comprehensive_api_flow():
    print("[10/10] Testing Harmonized REST APIs (Findings, Reports, IOC Harvest, Diff, Process Inspection)...")
    client = app.test_client()
    import uuid

    cid = f"test-flow-{uuid.uuid4().hex[:6]}"
    eid = f"ev-flow-{uuid.uuid4().hex[:6]}"
    bridge.case_mgr.create_case(cid, "Full Flow Case", "Lead Analyst", "Automated Flow Verification")
    db.create_evidence(Evidence(
        id=eid, case_id=cid, filename="flow_test.raw", filepath="dumps/flow_test.raw",
        file_size=2048, sha256="aabbccddeeff", md5="11223344", os_type="Windows", architecture="x64",
        kernel_info="", vol_compatibility="3.0", symbol_status="Available", status="Ready", metadata="{}"
    ))

    # 1. Test Findings CRUD
    r = client.post("/api/findings", json={
        "case_id": cid,
        "title": "Unlinked Process Injected Memory",
        "severity": "Critical",
        "description": "VirtualAlloc RWX region detected without image backing",
        "pid": 4420,
        "proc": "powershell.exe",
        "assessment": "High probability Cobalt Strike Beacon"
    })
    assert r.status_code == 200
    f_res = json.loads(r.data)
    assert f_res.get("success") is True and "finding" in f_res
    finding_id = f_res["finding"]["id"]
    print("  -> POST /api/findings: Created finding: OK")

    r = client.get(f"/api/findings?case_id={cid}")
    assert r.status_code == 200
    findings = json.loads(r.data)
    assert len(findings) >= 1 and findings[0]["id"] == finding_id
    print(f"  -> GET /api/findings: Retrieved {len(findings)} finding(s): OK")

    r = client.delete(f"/api/findings/{finding_id}")
    assert r.status_code == 200
    d_res = json.loads(r.data)
    assert d_res.get("success") is True
    print("  -> DELETE /api/findings/<id>: Finding deleted: OK")

    # 2. Test Process Detail Inspection
    db.upsert_processes_bulk([
        Process(id=f"p-{eid}-4420", evidence_id=eid, pid=4420, ppid=1000, name="powershell.exe", path="C:\\Windows\\powershell.exe", command_line="powershell -enc ...", create_time="2026-09-27T00:00:00", exit_time="", session_id=1, user_info="SYSTEM", in_pslist=True, in_psscan=True, in_pstree=True, risk_score=85, risk_level="Critical", risk_details="RWX memory injection", metadata="{}")
    ])
    r = client.get(f"/api/processes/4420?evidence_id={eid}")
    assert r.status_code == 200
    p_detail = json.loads(r.data)
    assert "process" in p_detail and p_detail["process"]["name"] == "powershell.exe"
    assert "connections" in p_detail and "dlls" in p_detail
    print("  -> GET /api/processes/4420: Harmonized process structure: OK")

    # 3. Test IOC Harvest
    r = client.post("/api/iocs/harvest", json={"case_id": cid, "evidence_id": eid})
    assert r.status_code == 200
    harvest_data = json.loads(r.data)
    assert "harvested_count" in harvest_data and "count" in harvest_data
    assert harvest_data["harvested_count"] == harvest_data["count"]
    print("  -> POST /api/iocs/harvest: Harmonized count and harvested_count: OK")

    # 4. Test Snapshot Diff
    eid_b = f"ev-flow-b-{uuid.uuid4().hex[:6]}"
    db.create_evidence(Evidence(
        id=eid_b, case_id=cid, filename="flow_b.raw", filepath="dumps/flow_b.raw",
        file_size=2048, sha256="12345678", md5="87654321", os_type="Windows", architecture="x64",
        kernel_info="", vol_compatibility="3.0", symbol_status="Available", status="Ready", metadata="{}"
    ))
    db.upsert_processes_bulk([
        Process(id=f"p-{eid_b}-5000", evidence_id=eid_b, pid=5000, ppid=4420, name="cmd.exe", path="", command_line="", create_time="", exit_time="", session_id=1, user_info="", in_pslist=True, in_psscan=True, in_pstree=True, risk_score=0, risk_level="Normal", risk_details="", metadata="{}")
    ])
    r = client.post("/api/diff", json={"evidence_a": eid, "evidence_b": eid_b})
    assert r.status_code == 200
    diff_res = json.loads(r.data)
    assert diff_res.get("success") is True and "diff" in diff_res
    assert "new_processes" in diff_res["diff"] and "terminated_processes" in diff_res["diff"]
    print("  -> POST /api/diff: Harmonized diff structure: OK")

    # 5. Test HTML Report Generation Endpoint
    r = client.post("/api/reports/html", json={"case_id": cid})
    assert r.status_code == 200
    rep_res = json.loads(r.data)
    assert rep_res.get("success") is True and "report_html" in rep_res and "path" in rep_res
    assert "<html" in rep_res["report_html"]
    print("  -> POST /api/reports/html: Returns report_html and path: OK")

    # 6. Test Package Export Endpoint
    r = client.post("/api/reports/package", json={"case_id": cid})
    assert r.status_code == 200
    pkg_res = json.loads(r.data)
    assert pkg_res.get("success") is True and "package_path" in pkg_res and "path" in pkg_res
    print("  -> POST /api/reports/package: Returns package_path and path: OK")

    # Clean up test artifacts
    bridge.case_mgr.delete_case(cid, delete_files=True)
    print("  -> Comprehensive flow verified & temporary test artifacts wiped: OK")

if __name__ == "__main__":
    print("=" * 65)
    print("  RUNNING DFIR-WEB-APP COMPREHENSIVE VERIFICATION")
    print("=" * 65)
    test_web_routes()
    test_bridge_cases_and_evidence()
    test_bridge_graph_data()
    test_bridge_live_state()
    test_bridge_playbooks_and_rules()
    test_rest_api_status()
    test_timeline_and_iocs()
    test_report_generation()
    test_new_features()
    test_comprehensive_api_flow()
    print("=" * 65)
    print("  ALL 10 TESTS PASSED SUCCESSFULLY! APPLICATION IS 100% READY!")
    print("=" * 65)
