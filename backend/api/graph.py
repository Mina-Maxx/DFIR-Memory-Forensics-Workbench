"""
DFIR Workbench V2 - Graph API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

graph_bp = Blueprint("graph_bp", __name__)


@graph_bp.route("/api/v2/graph", methods=["GET"])
def get_graph():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    data = bridge.get_graph_data(eid)
    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "graph": data
    })
