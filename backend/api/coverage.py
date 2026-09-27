"""
DFIR Workbench V2 - Investigation Coverage API Blueprint
Calculates investigation metrics and unresolved action items.
Answers:
- What am I investigating?
- What has been reviewed?
- What remains unresolved?
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

coverage_bp = Blueprint("coverage_bp", __name__)


@coverage_bp.route("/api/v2/investigation/coverage", methods=["GET"])
def get_investigation_coverage():
    bridge = get_bridge()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()

    conn = bridge.db._get_conn()
    cursor = conn.cursor()

    # 1. Process Metrics
    p_sql = "SELECT pid, name, risk_score, risk_level, severity, verdict FROM processes"
    p_params = []
    if eid:
        p_sql += " WHERE evidence_id = ?"
        p_params.append(eid)
    cursor.execute(p_sql, p_params)
    procs = [dict(row) for row in cursor.fetchall()]

    total_procs = len(procs)
    reviewed_procs = sum(1 for p in procs if p.get("verdict") and p.get("verdict") != "unreviewed")
    unreviewed_procs = total_procs - reviewed_procs

    high_risk_procs = [p for p in procs if (p.get("risk_score") or 0) >= 40]
    unreviewed_high_risk = [p for p in high_risk_procs if not p.get("verdict") or p.get("verdict") == "unreviewed"]

    critical_procs = [p for p in procs if (p.get("risk_score") or 0) >= 70]

    # 2. Detection Metrics
    d_sql = "SELECT id, rule_id, name, category, severity, confidence, entity_id, reason FROM detections"
    d_params = []
    if eid:
        d_sql += " WHERE evidence_id = ?"
        d_params.append(eid)
    elif cid:
        d_sql += " WHERE case_id = ?"
        d_params.append(cid)
    cursor.execute(d_sql, d_params)
    detections = [dict(row) for row in cursor.fetchall()]
    total_detections = len(detections)

    # 3. Finding Metrics
    f_sql = "SELECT id, title, severity, status FROM findings"
    f_params = []
    if cid:
        f_sql += " WHERE case_id = ?"
        f_params.append(cid)
    cursor.execute(f_sql, f_params)
    findings = [dict(row) for row in cursor.fetchall()]

    findings_by_status = {}
    for f in findings:
        st = f.get("status", "detected")
        findings_by_status[st] = findings_by_status.get(st, 0) + 1

    open_findings = sum(findings_by_status.get(s, 0) for s in ("detected", "triaged", "investigating"))
    confirmed_findings = findings_by_status.get("confirmed", 0)
    closed_findings = findings_by_status.get("closed", 0)

    # 4. IOC Metrics
    i_sql = "SELECT id, type, severity FROM iocs"
    i_params = []
    if cid:
        i_sql += " WHERE case_id = ?"
        i_params.append(cid)
    cursor.execute(i_sql, i_params)
    iocs = [dict(row) for row in cursor.fetchall()]
    iocs_by_sev = {}
    for i in iocs:
        sv = i.get("severity", "Medium")
        iocs_by_sev[sv] = iocs_by_sev.get(sv, 0) + 1

    # 5. Evidence Integrity
    ev_info = {"status": "Unknown", "last_verified": "", "filename": ""}
    if eid:
        cursor.execute("SELECT filename, verification_status, last_verified, sha256 FROM evidence WHERE id = ?", (eid,))
        row = cursor.fetchone()
        if row:
            ev_info = {
                "filename": row["filename"],
                "status": row["verification_status"] or "Unverified",
                "last_verified": row["last_verified"] or "",
                "sha256": row["sha256"] or ""
            }

    # 6. Action Items (Unresolved items needing analyst attention)
    action_items = []
    for p in unreviewed_high_risk[:10]:
        action_items.append({
            "type": "unreviewed_process",
            "entity": f"PID {p['pid']} ({p['name']})",
            "title": f"{p['name']} (PID {p['pid']})",
            "risk_score": p.get("risk_score", 0),
            "score": p.get("risk_score", 0),
            "severity": p.get("severity", "High"),
            "priority": p.get("severity", "High"),
            "pid": p["pid"],
            "id": p["pid"],
            "reason": p.get("explanation") or "Elevated heuristic risk score",
            "action": "Set analyst verdict on high-risk process"
        })

    for d in detections[:10]:
        action_items.append({
            "type": "unreviewed_detection",
            "entity": d.get("entity_id") or "Detection",
            "rule": d.get("name") or "Rule",
            "title": f"Detection: {d.get('name') or 'Rule'}",
            "severity": d.get("severity") or "High",
            "priority": d.get("severity") or "High",
            "id": d.get("id"),
            "reason": d.get("reason") or "Automated heuristic flag",
            "action": "Correlate detection into a formal Finding or mark false positive"
        })

    proc_coverage = {
        "total_processes": total_procs,
        "reviewed_processes": reviewed_procs,
        "unreviewed_processes": unreviewed_procs,
        "coverage_percent": round((reviewed_procs / total_procs * 100), 1) if total_procs > 0 else 100.0,
        "total": total_procs,
        "reviewed": reviewed_procs,
        "unreviewed": unreviewed_procs
    }

    risk_coverage = {
        "high_risk_total": len(high_risk_procs),
        "high_risk_reviewed": len(high_risk_procs) - len(unreviewed_high_risk),
        "high_risk_unreviewed": len(unreviewed_high_risk),
        "critical_threats_count": len(critical_procs),
        "total": len(high_risk_procs),
        "critical": len(critical_procs),
        "unreviewed": len(unreviewed_high_risk)
    }

    return jsonify({
        "status": "success",
        "case_id": cid,
        "evidence_id": eid,
        "process_coverage": proc_coverage,
        "risk_coverage": risk_coverage,
        "action_items": action_items,
        "findings_breakdown": findings_by_status,
        "evidence": ev_info,
        "coverage": {
            "processes": proc_coverage,
            "high_risk": risk_coverage,
            "detections": {
                "total": total_detections
            },
            "findings": {
                "total": len(findings),
                "open": open_findings,
                "confirmed": confirmed_findings,
                "closed": closed_findings,
                "by_status": findings_by_status
            },
            "iocs": {
                "total": len(iocs),
                "by_severity": iocs_by_sev
            },
            "evidence_integrity": ev_info,
            "action_items": action_items
        }
    })
