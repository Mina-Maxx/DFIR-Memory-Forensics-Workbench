"""
DFIR Workbench V2 - Artifacts API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

artifacts_bp = Blueprint("artifacts_bp", __name__)


@artifacts_bp.route("/api/v2/artifacts", methods=["GET"])
def list_artifacts():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    atype = request.args.get("type")
    entity_id = request.args.get("entity_id")
    raw_limit = request.args.get("limit")
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
            if limit < 1 or limit > 5000:
                return jsonify({"status": "error", "error": "Invalid limit parameter; must be an integer between 1 and 5000"}), 400
        except (ValueError, TypeError):
            return jsonify({"status": "error", "error": "Invalid limit parameter; must be an integer between 1 and 5000"}), 400
    else:
        limit = 500

    artifacts = bridge.db.list_artifacts(
        case_id=cid,
        evidence_id=eid,
        artifact_type=atype,
        entity_id=entity_id,
        limit=limit
    )
    return jsonify({
        "status": "success",
        "count": len(artifacts),
        "artifacts": [a.to_dict() for a in artifacts]
    })


@artifacts_bp.route("/api/v2/artifacts/<artifact_id>", methods=["GET"])
def get_artifact(artifact_id):
    bridge = get_bridge()
    art = bridge.db.get_artifact(artifact_id)
    if not art:
        return jsonify({"status": "error", "error": "Artifact not found"}), 404
    return jsonify({"status": "success", "artifact": art.to_dict()})
