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
    ALLOWED_VERDICTS = {"legitimate", "suspicious", "malicious", "inconclusive", "whitelisted", "unreviewed"}
    if not verdict or str(verdict).lower() not in ALLOWED_VERDICTS:
        return jsonify({
            "status": "error",
            "error": f"Invalid verdict: {verdict}. Allowed verdicts: {sorted(ALLOWED_VERDICTS)}"
        }), 400
    verdict = str(verdict).lower()

    proc = bridge.db.get_process_by_pid(eid, pid)
    if not proc:
        return jsonify({"status": "error", "error": "Process not found"}), 404

    ok = svc.update_process_verdict(proc.id, verdict)
    return jsonify({"status": "success", "pid": pid, "verdict": verdict})


@processes_bp.route("/api/v2/memory", methods=["GET"])
def list_memory_regions():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({
            "status": "success",
            "evidence_id": None,
            "count": 0,
            "total": 0,
            "rwx_count": 0,
            "suspicious_count": 0,
            "unique_pids": 0,
            "regions": [],
            "memory_regions": []
        }), 200
    raw_pid = request.args.get("pid")
    pid = None
    if raw_pid is not None:
        try:
            pid = int(raw_pid)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "error": "Invalid PID parameter"}), 400

    rwx_only = request.args.get("rwx") in ("1", "true", "True")
    suspicious_only = request.args.get("suspicious") in ("1", "true", "True")

    all_regions = bridge.db.list_memory_regions(eid, pid=pid)
    rwx_count = sum(
        1 for m in all_regions
        if any(x in (m.protection or "").upper() for x in ("EXECUTE_READWRITE", "EXECUTE_WRITECOPY", "RWX"))
        or ("EXECUTE" in (m.protection or "").upper() and "WRITE" in (m.protection or "").upper())
    )
    suspicious_count = sum(1 for m in all_regions if getattr(m, "suspicious", False) or getattr(m, "is_suspicious", False))
    unique_pids = len(set(m.pid for m in all_regions if m.pid is not None))

    if rwx_only:
        filtered = [
            m for m in all_regions
            if any(x in (m.protection or "").upper() for x in ("EXECUTE_READWRITE", "EXECUTE_WRITECOPY", "RWX"))
            or ("EXECUTE" in (m.protection or "").upper() and "WRITE" in (m.protection or "").upper())
        ]
    else:
        filtered = all_regions
    if suspicious_only:
        filtered = [m for m in filtered if getattr(m, "suspicious", False) or getattr(m, "is_suspicious", False)]

    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "count": len(filtered),
        "total": len(all_regions),
        "rwx_count": rwx_count,
        "suspicious_count": suspicious_count,
        "unique_pids": unique_pids,
        "regions": [m.to_dict() for m in filtered],
        "memory_regions": [m.to_dict() for m in filtered]
    })


@processes_bp.route("/api/v2/dlls", methods=["GET"])
def list_dlls():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({
            "status": "success",
            "evidence_id": None,
            "count": 0,
            "total": 0,
            "unique_names": 0,
            "dlls": []
        }), 200
    raw_pid = request.args.get("pid")
    pid = None
    if raw_pid is not None:
        try:
            pid = int(raw_pid)
        except (ValueError, TypeError):
            return jsonify({"status": "error", "error": "Invalid PID parameter"}), 400

    dlls = bridge.db.list_dlls(eid, pid=pid)
    unique_names = len(set((d.name or "").lower() for d in dlls if d.name))
    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "count": len(dlls),
        "total": len(dlls),
        "unique_names": unique_names,
        "dlls": [d.to_dict() for d in dlls]
    })

