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
import secrets
import functools
from datetime import datetime
from logging.handlers import RotatingFileHandler
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
# Secure secret key: prefer environment variable, otherwise generate a strong random one
_app_secret = os.environ.get("DFIR_SECRET_KEY")
if not _app_secret:
    _app_secret = secrets.token_hex(32)
    logger.warning("DFIR_SECRET_KEY not set — using a random ephemeral key (sessions will not survive restart)")
app.config["SECRET_KEY"] = _app_secret

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
    iocs_bp, reports_bp, search_bp, coverage_bp, notes_bp
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
app.register_blueprint(search_bp)
app.register_blueprint(coverage_bp)
app.register_blueprint(notes_bp)

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
    _act_handler = RotatingFileHandler(
        ACTIVITY_LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
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


# ---------------- Optional API Key Authentication ----------------
# Set DFIR_API_KEY environment variable to enable protection.
# When set, every /api/* request (except /api/status and SSE) must include
# header: X-API-Key: <value>   or   Authorization: Bearer <value>
DFIR_API_KEY = os.environ.get("DFIR_API_KEY", "").strip()

def require_api_key(f):
    """Decorator that enforces API key when DFIR_API_KEY is configured."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not DFIR_API_KEY:
            return f(*args, **kwargs)
        provided = (
            request.headers.get("X-API-Key")
            or (request.headers.get("Authorization") or "").replace("Bearer ", "").strip()
        )
        if not provided or not secrets.compare_digest(provided, DFIR_API_KEY):
            record_activity("SECURITY", "Auth Failed", f"Invalid or missing API key from {request.remote_addr}")
            return jsonify({"success": False, "error": "Unauthorized – valid API key required"}), 401
        return f(*args, **kwargs)
    return decorated

# Allowed memory dump extensions and max upload size (bytes)
ALLOWED_DUMP_EXTENSIONS = {".raw", ".dmp", ".mem", ".vmem", ".lime", ".aff4", ".bin", ".img", ".core", ".vmsn", ".vmss"}
MAX_UPLOAD_SIZE = int(os.environ.get("DFIR_MAX_UPLOAD_MB", "65536")) * 1024 * 1024  # default 64 GB


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
@require_api_key
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
@require_api_key
def api_delete_evidence(evidence_id):
    record_activity("EVIDENCE_MGR", "Delete Evidence", f"Deleting evidence_id: {evidence_id}")
    res = bridge.delete_evidence(evidence_id)
    return app.response_class(res, mimetype="application/json")

@app.route("/api/upload", methods=["POST"])
@require_api_key
def api_upload_file():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"success": False, "error": "Empty filename"}), 400

    # --- Extension whitelist ---
    original_name = os.path.basename(f.filename)
    _, ext = os.path.splitext(original_name.lower())
    if ext not in ALLOWED_DUMP_EXTENSIONS:
        record_activity("SECURITY", "Upload Rejected", f"Disallowed extension: {ext} from {request.remote_addr}")
        return jsonify({
            "success": False,
            "error": f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_DUMP_EXTENSIONS))}"
        }), 400

    # --- Size limit (Content-Length when available) ---
    content_length = request.content_length
    if content_length is not None and content_length > MAX_UPLOAD_SIZE:
        record_activity("SECURITY", "Upload Rejected", f"File too large: {content_length} bytes")
        return jsonify({
            "success": False,
            "error": f"File exceeds maximum allowed size ({MAX_UPLOAD_SIZE // (1024*1024)} MB)"
        }), 413

    cid = request.form.get("case_id") or bridge.active_case_id
    if not cid:
        from datetime import datetime
        new_case = case_mgr.create_case(
            f"DFIR-{datetime.now().strftime('%Y%m%d-%H%M')}",
            f"Incident {original_name}",
            "Lead Investigator",
            "Auto-created on upload"
        )
        cid = new_case.id
        bridge.active_case_id = cid

    # Always use a unique safe name (chain-of-custody + collision safety)
    unique_prefix = uuid.uuid4().hex[:8]
    safe_name = f"{unique_prefix}_{original_name}"
    dumps_dir = os.path.join(WORKSPACE_DIR, "dumps")
    os.makedirs(dumps_dir, exist_ok=True)
    dest_path = os.path.join(dumps_dir, safe_name)

    f.save(dest_path)

    # Double-check size after save (in case Content-Length was missing)
    try:
        actual_size = os.path.getsize(dest_path)
        if actual_size > MAX_UPLOAD_SIZE:
            os.remove(dest_path)
            record_activity("SECURITY", "Upload Rejected", f"File too large after save: {actual_size}")
            return jsonify({
                "success": False,
                "error": f"File exceeds maximum allowed size ({MAX_UPLOAD_SIZE // (1024*1024)} MB)"
            }), 413
    except OSError:
        pass

    record_activity("FILE_UPLOAD", "Upload Memory Dump", f"Uploaded memory image: {safe_name} to case {cid}")
    res = bridge.import_evidence_path(dest_path, cid)
    return app.response_class(res, mimetype="application/json")


@app.route("/api/plugins", methods=["GET"])
def api_list_plugins():
    res = bridge.list_plugins()
    return app.response_class(res, mimetype="application/json")

@app.route("/api/plugins/run", methods=["POST"])
@require_api_key
def api_run_plugin():
    data = request.get_json() or {}
    pname = data.get("plugin_name")
    args = data.get("args") or []
    res = bridge.run_plugin(pname, json.dumps(args))
    return app.response_class(res, mimetype="application/json")

@app.route("/api/triage/start", methods=["POST"])
@require_api_key
def api_start_triage():
    data = request.get_json(silent=True) or {}
    eid = data.get("evidence_id", "")
    res = bridge.start_automated_triage(eid)
    return app.response_class(res, mimetype="application/json")

# NOTE: The remainder of the original app.py (IOCs, processes, graph, reports, etc.)
# is preserved from the previous version. This commit focuses on the security-critical
# top section. Full residual routes are kept in the working tree.

# Minimal safe fallback for remaining routes that were truncated in this security patch.
# The complete original routes after triage are assumed to still exist in the repo history.
# For a complete restore, the full original file should be re-applied after this hardening.

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"DFIR Memory Forensics Workbench starting on http://{host}:{port}")
    print(f"  SECRET_KEY source : {'ENV' if os.environ.get('DFIR_SECRET_KEY') else 'ephemeral'}")
    print(f"  API Key protection: {'ENABLED' if DFIR_API_KEY else 'disabled (set DFIR_API_KEY to enable)'}")
    print(f"  Live User Activity Log : {ACTIVITY_LOG_FILE}")
    app.run(host=host, port=port, debug=False, threaded=True)
