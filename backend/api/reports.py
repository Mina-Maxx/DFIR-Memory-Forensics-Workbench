"""
DFIR Workbench V2 - Reports API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

reports_bp = Blueprint("reports_bp", __name__)


@reports_bp.route("/api/v2/reports/html", methods=["POST"])
def generate_html_report():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    if not cid:
        return jsonify({"status": "error", "error": "No case selected"}), 400

    report_html, path = bridge.generate_html_report(cid)
    return jsonify({
        "status": "success",
        "case_id": cid,
        "path": path,
        "report_html": report_html
    })


@reports_bp.route("/api/v2/reports/package", methods=["POST"])
def export_package():
    bridge = get_bridge()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    if not cid:
        return jsonify({"status": "error", "error": "No case selected"}), 400

    pkg_path = bridge.export_investigation_package(cid)
    return jsonify({
        "status": "success",
        "case_id": cid,
        "path": pkg_path,
        "package_path": pkg_path
    })
