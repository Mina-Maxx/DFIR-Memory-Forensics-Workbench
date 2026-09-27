"""
DFIR Workbench V2 - Findings API Blueprint
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge
from backend.services.finding_service import FindingService

findings_bp = Blueprint("findings_bp", __name__)


def _get_svc():
    bridge = get_bridge()
    return FindingService(bridge.db)


@findings_bp.route("/api/v2/findings", methods=["GET"])
def list_findings():
    bridge = get_bridge()
    svc = _get_svc()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    status = request.args.get("status")
    raw_limit = request.args.get("limit")
    if raw_limit is not None:
        try:
            limit = int(raw_limit)
            if limit < 1 or limit > 5000:
                return jsonify({"status": "error", "error": "Limit must be an integer between 1 and 5000"}), 400
        except (ValueError, TypeError):
            return jsonify({"status": "error", "error": "Limit must be an integer between 1 and 5000"}), 400
    else:
        limit = 500

    sev = request.args.get("severity")
    if sev:
        ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational", "Info"}
        if sev not in ALLOWED_SEVERITIES:
            return jsonify({"status": "error", "error": f"Invalid severity: {sev}. Allowed: {sorted(ALLOWED_SEVERITIES)}"}), 400

    items = svc.list_findings(cid, status=status)
    if sev:
        items = [f for f in items if f.severity.lower() == sev.lower()]
    items = items[:limit]
    return jsonify({
        "status": "success",
        "case_id": cid,
        "count": len(items),
        "findings": [f.to_dict() for f in items]
    })


@findings_bp.route("/api/v2/findings", methods=["POST"])
def create_finding():
    bridge = get_bridge()
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    cid = data.get("case_id") or bridge.get_active_case_id()
    title = data.get("title") or "Untitled Forensic Finding"
    sev = data.get("severity") or "Medium"
    ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational", "Info"}
    if sev not in ALLOWED_SEVERITIES:
        return jsonify({"status": "error", "error": f"Invalid severity: {sev}. Allowed: {sorted(ALLOWED_SEVERITIES)}"}), 400
    conf = data.get("confidence") or "Medium"
    status = data.get("status") or "detected"
    aff = data.get("affected_entity") or ""
    try:
        raw_pid = data.get("associated_pid") or data.get("related_pid") or 0
        pid = int(raw_pid) if raw_pid else 0
    except (ValueError, TypeError):
        return jsonify({"status": "error", "error": "Invalid PID; must be an integer"}), 400
    pname = data.get("associated_process_name") or data.get("related_process") or ""
    summary = data.get("summary") or data.get("description") or ""
    tech_desc = data.get("technical_description") or ""
    supp_ev = data.get("supporting_evidence") or data.get("evidence_details") or "[]"
    assessment = data.get("analyst_assessment") or ""
    limitations = data.get("limitations") or ""
    mitre = data.get("mitre_attack") or "[]"
    threat_intel = data.get("threat_intel") or ""
    inv = data.get("investigator") or "Analyst"

    finding = svc.create_finding(
        case_id=cid,
        title=title,
        severity=sev,
        confidence=conf,
        status=status,
        affected_entity=aff,
        associated_pid=pid,
        associated_process_name=pname,
        summary=summary,
        technical_description=tech_desc,
        supporting_evidence=supp_ev,
        analyst_assessment=assessment,
        limitations=limitations,
        mitre_attack=mitre,
        threat_intel=threat_intel,
        investigator=inv
    )
    return jsonify({"status": "success", "finding": finding.to_dict()}), 201


@findings_bp.route("/api/v2/findings/<finding_id>", methods=["GET"])
def get_finding(finding_id):
    svc = _get_svc()
    details = svc.get_finding_details(finding_id)
    if "error" in details:
        return jsonify({"status": "error", "error": details["error"]}), 404
    return jsonify({"status": "success", "details": details})


@findings_bp.route("/api/v2/findings/<finding_id>", methods=["PUT"])
def update_finding(finding_id):
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    analyst = data.get("analyst") or "Analyst"
    finding = svc.update_finding(finding_id, data, analyst=analyst)
    if not finding:
        return jsonify({"status": "error", "error": "Finding not found"}), 404
    return jsonify({"status": "success", "finding": finding.to_dict()})


@findings_bp.route("/api/v2/findings/<finding_id>/status", methods=["POST"])
def transition_status(finding_id):
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    analyst = data.get("analyst") or "Analyst"
    reason = data.get("reason") or ""
    try:
        finding = svc.transition_status(finding_id, new_status, analyst=analyst, reason=reason)
        if not finding:
            return jsonify({"status": "error", "error": "Finding not found"}), 404
        return jsonify({"status": "success", "finding": finding.to_dict()})
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@findings_bp.route("/api/v2/findings/<finding_id>/artifacts", methods=["POST"])
def attach_artifact(finding_id):
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    artifact_id = data.get("artifact_id")
    role = data.get("role") or "supports"
    explanation = data.get("explanation") or ""
    if not artifact_id:
        return jsonify({"status": "error", "error": "artifact_id is required"}), 400
    try:
        link = svc.attach_artifact(finding_id, artifact_id, role=role, explanation=explanation)
        return jsonify({"status": "success", "link": link.to_dict()})
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400


@findings_bp.route("/api/v2/findings/<finding_id>/notes", methods=["POST"])
def add_finding_note(finding_id):
    svc = _get_svc()
    data = request.get_json(silent=True) or {}
    author = data.get("author") or "Analyst"
    content = data.get("content") or ""
    if not content:
        return jsonify({"status": "error", "error": "content is required"}), 400
    note = svc.add_note(finding_id, author, content)
    return jsonify({"status": "success", "note": note.to_dict()}), 201


@findings_bp.route("/api/v2/findings/<finding_id>", methods=["DELETE"])
def delete_finding(finding_id):
    svc = _get_svc()
    ok = svc.delete_finding(finding_id)
    if not ok:
        return jsonify({"status": "error", "error": "Finding not found or delete failed"}), 404
    return jsonify({"status": "success", "deleted_finding_id": finding_id})
