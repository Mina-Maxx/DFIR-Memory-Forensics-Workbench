"""
DFIR Workbench V2 - Cases API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

cases_bp = Blueprint("cases_bp", __name__)


@cases_bp.route("/api/v2/cases", methods=["GET"])
def list_cases():
    bridge = get_bridge()
    active_cid = bridge.get_active_case_id()
    cases = bridge.list_cases()
    return jsonify({
        "status": "success",
        "active_case_id": active_cid,
        "cases": cases
    })


@cases_bp.route("/api/v2/cases", methods=["POST"])
def create_case():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("id") or f"case-{int(__import__('time').time())}"
    name = data.get("name") or cid
    inv = data.get("investigator") or "Analyst"
    desc = data.get("description") or ""

    case = bridge.case_mgr.create_case(cid, name, inv, desc)
    bridge.set_active_case(cid)
    return jsonify({
        "status": "success",
        "case": case.to_dict()
    }), 201


@cases_bp.route("/api/v2/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    bridge = get_bridge()
    case = bridge.case_mgr.get_case(case_id)
    if not case:
        return jsonify({"status": "error", "error": "Case not found"}), 404
    return jsonify({"status": "success", "case": case.to_dict()})


@cases_bp.route("/api/v2/cases/<case_id>/activate", methods=["POST"])
def activate_case(case_id):
    bridge = get_bridge()
    ok = bridge.set_active_case(case_id)
    if not ok:
        return jsonify({"status": "error", "error": "Case not found"}), 404
    return jsonify({"status": "success", "active_case_id": case_id})


@cases_bp.route("/api/v2/cases/<case_id>", methods=["DELETE"])
def delete_case(case_id):
    bridge = get_bridge()
    ok = bridge.case_mgr.delete_case(case_id, delete_files=True)
    if not ok:
        return jsonify({"status": "error", "error": "Failed to delete case"}), 400
    return jsonify({"status": "success", "deleted_case_id": case_id})
