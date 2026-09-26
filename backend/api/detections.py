"""
DFIR Workbench V2 - Detections & Rules API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

detections_bp = Blueprint("detections_bp", __name__)


@detections_bp.route("/api/v2/detections", methods=["GET"])
def list_detections():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    entity = request.args.get("entity")

    items = bridge.db.list_detections(case_id=cid, evidence_id=eid, affected_entity=entity)
    return jsonify({
        "status": "success",
        "count": len(items),
        "detections": [d.to_dict() for d in items]
    })


@detections_bp.route("/api/v2/detections/rules", methods=["GET"])
def list_rules():
    bridge = get_bridge()
    rules = bridge.risk_engine.rules.list_rules()
    return jsonify({
        "status": "success",
        "count": len(rules),
        "rules": rules
    })


@detections_bp.route("/api/v2/detections/rules/<rule_id>/override", methods=["POST"])
def override_rule(rule_id):
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled")
    weight = data.get("weight")

    ok = bridge.risk_engine.rules.set_override(rule_id, enabled=enabled, weight=weight)
    if not ok:
        return jsonify({"status": "error", "error": f"Rule {rule_id} not found"}), 404
    return jsonify({"status": "success", "rule_id": rule_id, "enabled": enabled, "weight": weight})
