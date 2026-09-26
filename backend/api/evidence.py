"""
DFIR Workbench V2 - Evidence API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

evidence_bp = Blueprint("evidence_bp", __name__)


@evidence_bp.route("/api/v2/evidence", methods=["GET"])
def list_evidence():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    active_eid = bridge.get_active_evidence_id()
    ev_list = bridge.list_evidence(cid)
    return jsonify({
        "status": "success",
        "case_id": cid,
        "active_evidence_id": active_eid,
        "evidence": ev_list
    })


@evidence_bp.route("/api/v2/evidence/<evidence_id>", methods=["GET"])
def get_evidence(evidence_id):
    bridge = get_bridge()
    ev = bridge.evidence_mgr.get_evidence(evidence_id)
    if not ev:
        return jsonify({"status": "error", "error": "Evidence not found"}), 404
    return jsonify({"status": "success", "evidence": ev.to_dict()})


@evidence_bp.route("/api/v2/evidence/<evidence_id>/activate", methods=["POST"])
def activate_evidence(evidence_id):
    bridge = get_bridge()
    res = bridge.set_active_evidence(evidence_id)
    if isinstance(res, str):
        import json
        res = json.loads(res)
    if not res.get("success", False):
        return jsonify({"status": "error", "error": res.get("error", "Evidence not found")}), 404
    return jsonify({"status": "success", "active_evidence_id": evidence_id})


@evidence_bp.route("/api/v2/evidence/<evidence_id>/verify", methods=["POST"])
def verify_evidence(evidence_id):
    bridge = get_bridge()
    from backend.services.evidence_service import EvidenceService
    svc = EvidenceService(bridge.db)
    res = svc.verify_evidence_integrity(evidence_id)
    return jsonify({"status": "success", "result": res})
