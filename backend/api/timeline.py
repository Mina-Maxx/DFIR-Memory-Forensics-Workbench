"""
DFIR Workbench V2 - Timeline API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

timeline_bp = Blueprint("timeline_bp", __name__)


@timeline_bp.route("/api/v2/timeline", methods=["GET"])
def get_timeline():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    filter_type = request.args.get("filter", "ALL")
    search_query = request.args.get("search", "")

    events = bridge.timeline_engine.get_events(eid, filter_type=filter_type, search_query=search_query)
    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "count": len(events),
        "events": [e.to_dict() for e in events]
    })


@timeline_bp.route("/api/v2/timeline/generate", methods=["POST"])
def generate_timeline():
    bridge = get_bridge()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    events = bridge.timeline_engine.generate_timeline(cid, eid)
    return jsonify({
        "status": "success",
        "evidence_id": eid,
        "count": len(events)
    })
