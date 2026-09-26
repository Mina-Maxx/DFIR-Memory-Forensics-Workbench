"""
DFIR Workbench V2 - IOCs API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

iocs_bp = Blueprint("iocs_bp", __name__)


@iocs_bp.route("/api/v2/iocs", methods=["GET"])
def list_iocs():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    iocs = bridge.ioc_engine.list_iocs(cid)
    return jsonify({
        "status": "success",
        "case_id": cid,
        "count": len(iocs),
        "iocs": [i.to_dict() for i in iocs]
    })


@iocs_bp.route("/api/v2/iocs", methods=["POST"])
def add_ioc():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    itype = data.get("type", "ip")
    val = data.get("value", "")
    sev = data.get("severity", "Medium")
    src = data.get("source", "Analyst Manual")
    desc = data.get("description", "")
    pid = int(data.get("associated_pid") or data.get("pid") or 0)

    ioc = bridge.ioc_engine.add_ioc(cid, itype, val, sev, src, desc, pid=pid)
    if not ioc:
        return jsonify({"status": "error", "error": "Failed to add IOC or already exists"}), 400
    return jsonify({"status": "success", "ioc": ioc.to_dict()}), 201


@iocs_bp.route("/api/v2/iocs/harvest", methods=["POST"])
def harvest_iocs():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    eid = data.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    harvested = bridge.ioc_engine.harvest_from_network(cid, eid)
    return jsonify({
        "status": "success",
        "count": len(harvested),
        "harvested_count": len(harvested),
        "iocs": [i.to_dict() for i in harvested]
    })


@iocs_bp.route("/api/v2/iocs/hunt", methods=["POST"])
def hunt_iocs():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    eid = data.get("evidence_id") or bridge.get_active_evidence_id()
    if not eid:
        return jsonify({"status": "error", "error": "No active evidence selected"}), 400

    matches = bridge.ioc_engine.hunt(query, eid)
    return jsonify({
        "status": "success",
        "query": query,
        "count": len(matches),
        "matches": matches
    })


@iocs_bp.route("/api/v2/iocs/promote", methods=["POST"])
def promote_artifact():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    art_id = data.get("artifact_id")
    cid = data.get("case_id") or bridge.get_active_case_id()
    sev = data.get("severity", "High")
    analyst = data.get("analyst", "Analyst")
    notes = data.get("notes", "")

    if not art_id:
        return jsonify({"status": "error", "error": "artifact_id is required"}), 400

    ioc = bridge.ioc_engine.promote_artifact_to_ioc(art_id, cid, severity=sev, analyst=analyst, notes=notes)
    if not ioc:
        return jsonify({"status": "error", "error": "Failed to promote artifact"}), 400
    return jsonify({"status": "success", "ioc": ioc.to_dict()})


@iocs_bp.route("/api/v2/iocs/<ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    bridge = get_bridge()
    ok = bridge.db.delete_ioc(ioc_id)
    if not ok:
        return jsonify({"status": "error", "error": "IOC not found"}), 404
    return jsonify({"status": "success", "deleted_ioc_id": ioc_id})
