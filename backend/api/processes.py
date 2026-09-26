"""
DFIR Workbench V2 - Processes API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge
from backend.services.correlation_service import CorrelationService

processes_bp = Blueprint("processes_bp", __name__)


def _get_svc():
    bridge = get_bridge()
    return CorrelationService(bridge.db)


@processes_bp.route("/api/v2/processes", methods=["GET"])
def list_processes():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    procs = bridge.db.list_processes(eid)
    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "count": len(procs),
        "processes": [p.to_dict() for p in procs]
    })


@processes_bp.route("/api/v2/processes/<int:pid>", methods=["GET"])
def explain_process(pid):
    bridge = get_bridge()
    svc = _get_svc()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    details = svc.explain_process(eid, pid)
    if "error" in details:
        return jsonify({"status": "error", "error": details["error"]}), 404
    return jsonify({"status": "success", "process_profile": details})


@processes_bp.route("/api/v2/processes/<int:pid>/verdict", methods=["POST"])
def set_verdict(pid):
    bridge = get_bridge()
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    verdict = data.get("verdict")
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400
    if not verdict:
        return jsonify({"status": "error", "error": "verdict is required"}), 400

    proc = bridge.db.get_process_by_pid(eid, pid)
    if not proc:
        return jsonify({"status": "error", "error": "Process not found"}), 404

    ok = svc.update_process_verdict(proc.id, verdict)
    return jsonify({"status": "success", "pid": pid, "verdict": verdict})
