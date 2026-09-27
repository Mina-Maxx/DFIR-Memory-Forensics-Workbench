"""
DFIR Web Application — Pure-Python Standalone Forensic Investigation Platform
Serves the complete Volatility 3 Workbench in the browser with zero Qt dependencies.
"""
import os
import sys
import json
import time
import queue
import threading
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, send_file, send_from_directory

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.database import DatabaseManager
from core.case_manager import CaseManager
from core.evidence_manager import EvidenceManager
from core.job_manager import JobManager
from core.investigation_engine import InvestigationEngine
from core.risk_engine import RiskEngine
from core.rule_engine import RuleEngine
from core.graph_builder import build_graph
from core.ioc_engine import IOCEngine
from core.timeline_engine import TimelineEngine
from core.playbook_engine import PlaybookEngine
from core.diff_engine import diff_evidence
from core.report_engine import ReportEngine
from core.report_exporters import export_package, build_stix
from core.yara_engine import YaraEngine
from core.web_bridge import WebBridge
from forensics.vol_adapter import VolAdapter
from forensics.plugin_discovery import PluginDiscovery
from core.logger import get_logger
from core.models import Finding, IOC

logger = get_logger("app")

# Initialize Flask
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = "dfir-workbench-secret-2026"

# Initialize Core Services
WORKSPACE_DIR = os.path.join(PROJECT_ROOT, "workspace")
for sub in ("dumps", "cache", "exports", "logs"):
    os.makedirs(os.path.join(WORKSPACE_DIR, sub), exist_ok=True)

DB_PATH = os.path.join(WORKSPACE_DIR, "investigations.db")

db = DatabaseManager(DB_PATH, WORKSPACE_DIR)
case_mgr = CaseManager(db, WORKSPACE_DIR)
vol_adapter = VolAdapter(WORKSPACE_DIR)
evidence_mgr = EvidenceManager(db, vol_adapter)
job_mgr = JobManager(db, vol_adapter)
discovery = PluginDiscovery()
rule_engine = RuleEngine()
risk_engine = RiskEngine(rule_engine)
inv_engine = InvestigationEngine(db, risk_engine)
ioc_engine = IOCEngine(db)
timeline_engine = TimelineEngine(db)
playbook_engine = PlaybookEngine(job_mgr)
yara_engine = YaraEngine(db)
report_engine = ReportEngine(db)

# Preload plugin discovery in background
threading.Thread(target=lambda: discovery.discover_all(), daemon=True).start()

# Initialize Bridge
bridge = WebBridge(
    db=db,
    case_mgr=case_mgr,
    evidence_mgr=evidence_mgr,
    job_mgr=job_mgr,
    inv_engine=inv_engine,
    ioc_engine=ioc_engine,
    tl_engine=timeline_engine,
    rep_engine=report_engine,
    discovery=discovery,
    vol_adapter=vol_adapter,
    playbook_engine=playbook_engine,
    yara_engine=yara_engine,
    rule_engine=rule_engine
)

from backend.api.context import set_bridge
set_bridge(bridge)
app.config["BRIDGE"] = bridge

# Register V2 Investigation-Centric API Blueprints
from backend.api import (
    cases_bp, evidence_bp, artifacts_bp, findings_bp,
    detections_bp, processes_bp, timeline_bp, graph_bp,
    iocs_bp, reports_bp
)
app.register_blueprint(cases_bp)
app.register_blueprint(evidence_bp)
app.register_blueprint(artifacts_bp)
app.register_blueprint(findings_bp)
app.register_blueprint(detections_bp)
app.register_blueprint(processes_bp)
app.register_blueprint(timeline_bp)
app.register_blueprint(graph_bp)
app.register_blueprint(iocs_bp)
app.register_blueprint(reports_bp)

# SSE Event Queues
sse_queues: list = []
sse_lock = threading.Lock()

def broadcast_signal(sig_name: str, args: list):
    payload = {"signal": sig_name, "args": args}
    with sse_lock:
        dead = []
        for q in sse_queues:
            try:
                q.put_nowait(payload)
            except Exception:
                dead.append(q)
        for d in dead:
            if d in sse_queues:
                sse_queues.remove(d)

# Connect WebBridge signals to SSE broadcaster
BRIDGE_SIGNALS = [
    "job_started", "job_activity", "job_finished", "results_ready",
    "triage_completed", "log_emitted", "hash_progress",
    "playbook_progress", "playbook_finished",
]

def _make_relay(name):
    def relay(*args):
        broadcast_signal(name, list(args))
    return relay

for sig in BRIDGE_SIGNALS:
    sig_obj = getattr(bridge, sig, None)
    if sig_obj is not None:
        sig_obj.connect(_make_relay(sig))


# ---------------- Comprehensive User Activity & Site Logger ----------------
import logging

ACTIVITY_LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "site_activity.log")
os.makedirs(os.path.dirname(ACTIVITY_LOG_FILE), exist_ok=True)

activity_logger = logging.getLogger("site_activity")
activity_logger.setLevel(logging.INFO)
if not activity_logger.handlers:
    _act_handler = logging.FileHandler(ACTIVITY_LOG_FILE, encoding="utf-8")
    _act_formatter = logging.Formatter('%(asctime)s.%(msecs)03d | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    _act_handler.setFormatter(_act_formatter)
    activity_logger.addHandler(_act_handler)
activity_logger.propagate = False

def record_activity(category: str, action: str, details: str = "", client_ip: str = ""):
    try:
        ip_str = client_ip or (request.remote_addr if request else "127.0.0.1")
    except Exception:
        ip_str = client_ip or "127.0.0.1"
    line = f"[{category.upper():<16}] | [{action:<18}] | {details} | IP: {ip_str}"
    activity_logger.info(line)
    for h in activity_logger.handlers:
        h.flush()


# ---------------- Static & Cache Control ----------------

@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/")
def index():
    record_activity("PAGE_NAVIGATION", "Page Visit / Reload", "User loaded or refreshed main web application (index.html)")
    return render_template("index.html")

@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(os.path.join(PROJECT_ROOT, "static", "css"), filename)

@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(os.path.join(PROJECT_ROOT, "static", "js"), filename)

@app.route("/api/activity/log", methods=["POST"])
def api_log_activity():
    data = request.get_json(silent=True) or {}
    category = data.get("category", "USER_ACTION")
    action = data.get("action", "INTERACTION")
    details = data.get("details", "")
    record_activity(category, action, details, request.remote_addr)
    return jsonify({"status": "recorded"}), 200

@app.route("/api/activity/tail", methods=["GET"])
def api_tail_activity():
    limit = int(request.args.get("limit", 100))
    if not os.path.exists(ACTIVITY_LOG_FILE):
        return jsonify({"lines": []})
    try:
        with open(ACTIVITY_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        return jsonify({"lines": lines[-limit:]})
    except Exception as e:
        return jsonify({"error": str(e), "lines": []}), 500


# ---------------- Real-time Streams & Bridge API ----------------

@app.route("/api/stream")
def sse_stream():
    """SSE streaming endpoint delivering real-time signals to bridge-http.js."""
    def event_generator():
        q = queue.Queue(maxsize=1000)
        with sse_lock:
            sse_queues.append(q)
        yield "retry: 3000\n\n"
        try:
            while True:
                try:
                    ev = q.get(timeout=15)
                    yield f"data: {json.dumps(ev, ensure_ascii=False, default=str)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            with sse_lock:
                if q in sse_queues:
                    sse_queues.remove(q)

    return Response(event_generator(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no"
    })

@app.route("/api/live")
def api_live():
    """Lightweight live polling endpoint used by frontend status tickers."""
    res = bridge.get_live_state()
    return app.response_class(res, mimetype="application/json")

@app.route("/api/bridge/<name>", methods=["POST"])
def call_bridge_slot(name):
    """Dynamic slot invocation endpoint mirroring QWebChannel for the browser."""
    fn = getattr(bridge, name, None)
    if not callable(fn):
        return jsonify({"success": False, "error": f"Unknown or uncallable bridge slot: {name}"}), 404

    args = request.get_json(silent=True)
    if args is None:
        args = []

    try:
        if isinstance(args, dict):
            result = fn(**args)
        elif isinstance(args, list):
            result = fn(*args)
        else:
            result = fn(args)
    except Exception as exc:
        logger.error(f"Error calling slot '{name}': {exc}", exc_info=True)
        return jsonify({"success": False, "error": str(exc)})

    if isinstance(result, str):
        return app.response_class(result, mimetype="application/json")
    return jsonify(result)


# ---------------- REST API (Direct Access) ----------------

@app.route("/api/status")
def get_status():
    active_case = db.get_case(bridge.active_case_id) if bridge.active_case_id else None
    active_evidence = db.get_evidence(bridge.active_evidence_id) if bridge.active_evidence_id else None
    executions = db.list_executions(bridge.active_evidence_id)
    running_jobs = [e for e in executions if e.status == "Running"]

    return jsonify({
        "active_case": active_case.to_dict() if active_case else None,
        "active_evidence": active_evidence.to_dict() if active_evidence else None,
        "running_jobs": len(running_jobs),
        "playbook_running": playbook_engine.is_running,
        "vol_prefix": vol_adapter.vol_prefix
    })

@app.route("/api/cases", methods=["GET"])
def api_list_cases():
    cases = db.list_cases()
    return jsonify([c.to_dict() for c in cases])

@app.route("/api/cases", methods=["POST"])
def api_create_case():
    data = request.get_json() or {}
    res = bridge.create_case(
        data.get("case_id", ""),
        data.get("name", "New Investigation"),
        data.get("investigator", "Analyst"),
        data.get("description", "")
    )
    return app.response_class(res, mimetype="application/json")

@app.route("/api/cases/activate", methods=["POST"])
def api_activate_case():
    data = request.get_json() or {}
    cid = data.get("case_id")
    res = bridge.open_case(cid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/cases/<case_id>", methods=["DELETE"])
def api_delete_case(case_id):
    record_activity("CASE_MANAGER", "Delete Case", f"Deleting case_id: {case_id}")
    delete_files = request.args.get("delete_files", "false").lower() == "true"
    res = bridge.delete_case(case_id, delete_files=delete_files)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/evidence", methods=["GET"])
def api_list_evidence():
    cid = request.args.get("case_id") or bridge.active_case_id
    if not cid:
        return jsonify([])
    evidences = db.list_evidence_for_case(cid)
    return jsonify([e.to_dict() for e in evidences])

@app.route("/api/evidence/import", methods=["POST"])
def api_import_evidence():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    filepath = data.get("filepath", "").strip()
    if not filepath:
        return jsonify({"success": False, "error": "Missing or empty filepath"}), 400
    real_path = os.path.realpath(filepath)
    if not os.path.isfile(real_path):
        return jsonify({"success": False, "error": f"Evidence file not found: {filepath}"}), 400
    res = bridge.import_evidence_path(real_path, cid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/evidence/activate", methods=["POST"])
def api_activate_evidence():
    data = request.get_json() or {}
    eid = data.get("evidence_id")
    res = bridge.set_active_evidence(eid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/evidence/verify", methods=["POST"])
def api_verify_evidence():
    data = request.get_json() or {}
    eid = data.get("evidence_id")
    res = bridge.verify_evidence_hash(eid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/evidence/<evidence_id>", methods=["DELETE"])
def api_delete_evidence(evidence_id):
    record_activity("EVIDENCE_MGR", "Delete Evidence", f"Deleting evidence_id: {evidence_id}")
    res = bridge.delete_evidence(evidence_id)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/upload", methods=["POST"])
def api_upload_file():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    cid = request.form.get("case_id") or bridge.active_case_id
    if not cid:
        from datetime import datetime
        new_case = case_mgr.create_case(f"DFIR-{datetime.now().strftime('%Y-%m%d-%H%M')}", f"Incident {f.filename}", "Lead Investigator", "Auto-created on upload")
        cid = new_case.id
        bridge.active_case_id = cid

    safe_name = os.path.basename(f.filename)
    dumps_dir = os.path.join(WORKSPACE_DIR, "dumps")
    os.makedirs(dumps_dir, exist_ok=True)
    dest_path = os.path.join(dumps_dir, safe_name)

    # Prevent overwriting an existing evidence file (chain of custody preservation)
    if os.path.exists(dest_path):
        unique_prefix = uuid.uuid4().hex[:8]
        safe_name = f"{unique_prefix}_{safe_name}"
        dest_path = os.path.join(dumps_dir, safe_name)
        logger.info(f"Existing file collision detected. Saved upload as unique immutable file: {safe_name}")

    f.save(dest_path)

    record_activity("FILE_UPLOAD", "Upload Memory Dump", f"Uploaded memory image: {safe_name} to case {cid}")
    res = bridge.import_evidence_path(dest_path, cid)
    return app.response_class(res, mimetype="application/json")


@app.route("/api/plugins", methods=["GET"])
def api_list_plugins():
    res = bridge.list_plugins()
    return app.response_class(res, mimetype="application/json")

@app.route("/api/plugins/run", methods=["POST"])
def api_run_plugin():
    data = request.get_json() or {}
    pname = data.get("plugin_name")
    args = data.get("args") or []
    res = bridge.run_plugin(pname, json.dumps(args))
    return app.response_class(res, mimetype="application/json")

@app.route("/api/triage/start", methods=["POST"])
def api_start_triage():
    data = request.get_json(silent=True) or {}
    eid = data.get("evidence_id", "")
    res = bridge.start_automated_triage(eid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/executions", methods=["GET"])
def api_list_executions():
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.list_executions(eid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/results/<execution_id>", methods=["GET"])
def api_get_result(execution_id):
    res = bridge.get_execution_results(execution_id)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/processes", methods=["GET"])
def api_list_processes():
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.get_correlated_processes(eid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/processes/<int:pid>", methods=["GET"])
def api_get_process_detail(pid):
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.get_process_detail(eid or "", pid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/network", methods=["GET"])
def api_list_network():
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.get_network_connections(eid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/graph", methods=["GET"])
def api_get_graph():
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.get_graph_data(eid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/iocs", methods=["GET"])
def api_list_iocs():
    cid = request.args.get("case_id") or bridge.active_case_id
    res = bridge.list_iocs(cid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/iocs", methods=["POST"])
def api_create_ioc():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    res = bridge.add_ioc(
        cid or "",
        data.get("type", "ip"),
        data.get("value", "").strip(),
        data.get("severity", "High"),
        data.get("description", "")
    )
    return app.response_class(res, mimetype="application/json")

@app.route("/api/iocs/<ioc_id>", methods=["DELETE"])
def api_delete_ioc(ioc_id):
    record_activity("IOC_ENGINE", "Delete IOC", f"Deleting IOC ID: {ioc_id}")
    res = bridge.delete_ioc(ioc_id)
    return app.response_class(res, mimetype="application/json")


@app.route("/api/iocs/harvest", methods=["POST"])
def api_harvest_iocs():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    eid = data.get("evidence_id") or bridge.active_evidence_id
    harvested = ioc_engine.harvest_from_network(cid, eid)
    return jsonify({
        "success": True,
        "count": len(harvested),
        "harvested_count": len(harvested),
        "iocs": [i.to_dict() for i in harvested]
    })

@app.route("/api/iocs/hunt", methods=["POST"])
def api_hunt_iocs():
    data = request.get_json() or {}
    query = data.get("query", "")
    eid = data.get("evidence_id") or bridge.active_evidence_id
    matches = ioc_engine.hunt(query, eid)
    return jsonify({"success": True, "count": len(matches), "matches": matches})

@app.route("/api/iocs/stix", methods=["GET"])
def api_download_stix():
    cid = request.args.get("case_id") or bridge.active_case_id
    stix_json = report_exporters.build_stix(db.list_iocs(cid))
    return Response(stix_json, mimetype="application/json", headers={"Content-Disposition": f"attachment;filename=stix_{cid}.json"})

@app.route("/api/timeline", methods=["GET"])
def api_list_timeline():
    eid = request.args.get("evidence_id") or bridge.active_evidence_id
    res = bridge.get_timeline(eid or "", "ALL", "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/timeline/generate", methods=["POST"])
def api_generate_timeline():
    data = request.get_json() or {}
    eid = data.get("evidence_id") or bridge.active_evidence_id
    events = timeline_engine.generate_timeline(eid)
    return jsonify({"success": True, "count": len(events)})

@app.route("/api/findings", methods=["GET"])
def api_list_findings():
    cid = request.args.get("case_id") or bridge.active_case_id
    res = bridge.list_findings(cid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/findings", methods=["POST"])
def api_create_finding():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    res = bridge.create_finding(
        case_id=cid or "",
        title=data.get("title", "Forensic Finding"),
        severity=data.get("severity", "Medium"),
        desc=data.get("description", ""),
        pid=int(data.get("pid") or 0),
        proc=data.get("proc", ""),
        assessment=data.get("assessment", "")
    )
    return app.response_class(res, mimetype="application/json")

@app.route("/api/findings/<finding_id>", methods=["DELETE"])
def api_delete_finding(finding_id):
    record_activity("FINDINGS", "Delete Finding", f"Deleting finding ID: {finding_id}")
    res = bridge.delete_finding(finding_id)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/playbooks", methods=["GET"])
def api_list_playbooks():
    res = bridge.list_playbooks()
    return app.response_class(res, mimetype="application/json")

@app.route("/api/playbooks/run", methods=["POST"])
def api_run_playbook():
    data = request.get_json() or {}
    pid = data.get("playbook_id")
    res = bridge.run_playbook(pid)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/diff", methods=["POST"])
def api_diff_evidence():
    data = request.get_json() or {}
    ev_a = data.get("evidence_a")
    ev_b = data.get("evidence_b")
    res = bridge.diff_evidences(ev_a, ev_b)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/reports/html", methods=["POST"])
def api_generate_html_report():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    res = bridge.generate_report(cid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/reports/package", methods=["POST"])
def api_export_package():
    data = request.get_json() or {}
    cid = data.get("case_id") or bridge.active_case_id
    res = bridge.export_report_package(cid or "")
    return app.response_class(res, mimetype="application/json")

@app.route("/api/rules", methods=["GET"])
def api_list_rules():
    res = bridge.list_rules()
    return app.response_class(res, mimetype="application/json")


@app.route("/api/yara/scan", methods=["POST"])
def api_yara_scan():
    data = request.get_json() or {}
    rule_text = data.get("rule_text", "")
    eid = data.get("evidence_id") or bridge.active_evidence_id
    record_activity("YARA_SCANNER", "Execute Scan", f"Running YARA scan against evidence: {eid}")

    if not rule_text.strip():
        return jsonify({"success": False, "error": "YARA rule text is empty"}), 400

    validation = yara_engine.validate_rule(rule_text)
    if not validation.get("valid"):
        return jsonify({"success": False, "error": validation.get("error")}), 400

    matches = []
    try:
        import yara
        compiled = yara.compile(source=rule_text)
        artifacts = db.list_dump_artifacts(evidence_id=eid)
        for art in artifacts:
            if os.path.isfile(art.output_path):
                m_list = compiled.match(art.output_path)
                for m in m_list:
                    matches.append({
                        "rule": m.rule,
                        "tags": m.tags,
                        "strings": [(s[0], s[1], str(s[2])) for s in m.strings[:5]],
                        "pid": art.pid,
                        "target": art.source_plugin,
                        "path": art.output_path
                    })
    except ImportError:
        pass
    except Exception as e:
        logger.error(f"YARA scan error: {e}")

    return jsonify({"success": True, "count": len(matches), "matches": matches})

@app.route("/api/yara/rules", methods=["GET"])
def api_get_curated_yara_rules():
    rules = [
        {
            "id": "cobalt_strike",
            "name": "Cobalt Strike Beacon",
            "rule": 'rule CobaltStrike_Beacon {\n    meta:\n        description = "Detects Cobalt Strike beacon in memory"\n    strings:\n        $s1 = "%s as %s\\%s: %d"\n        $s2 = "ReflectiveLoader"\n    condition:\n        any of them\n}'
        },
        {
            "id": "mimikatz",
            "name": "Mimikatz LSASS Ingestion",
            "rule": 'rule Mimikatz_Memory {\n    meta:\n        description = "Detects Mimikatz credentials dumping artifacts"\n    strings:\n        $m1 = "sekurlsa::logonpasswords"\n        $m2 = "lsasrv.dll"\n    condition:\n        any of them\n}'
        },
        {
            "id": "reverse_shell",
            "name": "PowerShell Reverse Shell",
            "rule": 'rule PowerShell_Reverse_Shell {\n    meta:\n        description = "Detects interactive netcat/TCP reverse shell via powershell"\n    strings:\n        $p1 = "Net.Sockets.TCPClient"\n        $p2 = "System.Text.ASCIIEncoding"\n    condition:\n        all of them\n}'
        },
        {
            "id": "ransomware_vss",
            "name": "Shadow Copies Deletion (Ransomware)",
            "rule": 'rule Ransomware_VSS_Deletion {\n    meta:\n        description = "Detects shadow copy wipe attempts"\n    strings:\n        $c1 = "vssadmin delete shadows"\n        $c2 = "wmic shadowcopy delete"\n    condition:\n        any of them\n}'
        }
    ]
    return jsonify({"success": True, "rules": rules})


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    logger.info(f"DFIR Web Application starting on http://{host}:{port}")
    record_activity("SYSTEM", "Startup", f"DFIR Web Application initialized on http://{host}:{port}")
    print("=" * 65)
    print(f"  DFIR Web Application ready: http://{host}:{port}")
    print(f"  Live User Activity Log : {ACTIVITY_LOG_FILE}")
    print("=" * 65)

    def _open_browser():
        time.sleep(1.0)
        import webbrowser
        try:
            webbrowser.open(f"http://127.0.0.1:{port}")
        except Exception:
            pass

    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(host=host, port=port, debug=False, threaded=True)
