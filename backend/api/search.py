"""
DFIR Workbench V2 - Global Forensic Search Blueprint
Unified search across processes, network sockets, artifacts, detections, findings, IOCs, and timeline.
"""

from flask import Blueprint, request, jsonify
from backend.api.context import get_bridge

search_bp = Blueprint("search_bp", __name__)


@search_bp.route("/api/v2/search", methods=["GET"])
def global_search():
    bridge = get_bridge()
    q = (request.args.get("q") or "").strip()
    cid = request.args.get("case_id") or bridge.get_active_case_id()
    eid = request.args.get("evidence_id") or bridge.get_active_evidence_id()

    if not q:
        counts = {
            "processes": 0,
            "network_connections": 0,
            "connections": 0,
            "artifacts": 0,
            "detections": 0,
            "findings": 0,
            "iocs": 0,
            "timeline_events": 0,
            "timeline": 0,
            "evidence": 0
        }
        return jsonify({
            "status": "success",
            "query": "",
            "total_matches": 0,
            "counts": counts,
            "results": {
                "processes": [],
                "network_connections": [],
                "connections": [],
                "artifacts": [],
                "detections": [],
                "findings": [],
                "iocs": [],
                "timeline_events": [],
                "timeline": [],
                "evidence": []
            }
        })

    pattern = f"%{q}%"
    conn = bridge.db._get_conn()
    cursor = conn.cursor()

    results = {
        "processes": [],
        "connections": [],
        "artifacts": [],
        "detections": [],
        "findings": [],
        "iocs": [],
        "timeline": [],
        "evidence": []
    }

    # 1. Search Processes
    p_sql = """
        SELECT id, pid, ppid, name, path, command_line, risk_score, risk_level, severity, verdict, in_pslist, in_psscan
        FROM processes
        WHERE (name LIKE ? OR path LIKE ? OR command_line LIKE ? OR CAST(pid AS TEXT) LIKE ?)
    """
    p_params = [pattern, pattern, pattern, pattern]
    if eid:
        p_sql += " AND evidence_id = ?"
        p_params.append(eid)
    p_sql += " LIMIT 25"
    cursor.execute(p_sql, p_params)
    results["processes"] = [dict(row) for row in cursor.fetchall()]

    # 2. Search Network Connections
    n_sql = """
        SELECT id, pid, process_name, protocol, local_addr, local_port, remote_addr, remote_port, state
        FROM network_connections
        WHERE (local_addr LIKE ? OR remote_addr LIKE ? OR process_name LIKE ? OR CAST(local_port AS TEXT) LIKE ? OR CAST(remote_port AS TEXT) LIKE ?)
    """
    n_params = [pattern, pattern, pattern, pattern, pattern]
    if eid:
        n_sql += " AND evidence_id = ?"
        n_params.append(eid)
    n_sql += " LIMIT 25"
    cursor.execute(n_sql, n_params)
    results["connections"] = [dict(row) for row in cursor.fetchall()]

    # 3. Search Evidence Artifacts
    a_sql = """
        SELECT id, case_id, evidence_id, artifact_type, source_plugin, entity_id, raw_reference, hash
        FROM artifacts
        WHERE (id LIKE ? OR source_plugin LIKE ? OR entity_id LIKE ? OR raw_reference LIKE ? OR hash LIKE ?)
    """
    a_params = [pattern, pattern, pattern, pattern, pattern]
    if cid:
        a_sql += " AND case_id = ?"
        a_params.append(cid)
    if eid:
        a_sql += " AND evidence_id = ?"
        a_params.append(eid)
    a_sql += " LIMIT 25"
    cursor.execute(a_sql, a_params)
    raw_artifacts = [dict(row) for row in cursor.fetchall()]
    for a in raw_artifacts:
        a["type"] = a.get("artifact_type")
        a["plugin"] = a.get("source_plugin")
        a["raw_ref"] = a.get("raw_reference")
        a["sha256"] = a.get("hash")
    results["artifacts"] = raw_artifacts

    # 4. Search Detections & Rules
    d_sql = """
        SELECT id, case_id, evidence_id, rule_id, name, category, severity, confidence, entity_id, entity_type, reason, mitre_attack
        FROM detections
        WHERE (rule_id LIKE ? OR name LIKE ? OR entity_id LIKE ? OR reason LIKE ? OR mitre_attack LIKE ?)
    """
    d_params = [pattern, pattern, pattern, pattern, pattern]
    if cid:
        d_sql += " AND case_id = ?"
        d_params.append(cid)
    if eid:
        d_sql += " AND evidence_id = ?"
        d_params.append(eid)
    d_sql += " LIMIT 25"
    cursor.execute(d_sql, d_params)
    results["detections"] = [dict(row) for row in cursor.fetchall()]

    # 5. Search Findings
    f_sql = """
        SELECT id, case_id, title, severity, confidence, status, affected_entity, associated_pid, associated_process_name, summary, technical_description
        FROM findings
        WHERE (title LIKE ? OR affected_entity LIKE ? OR associated_process_name LIKE ? OR summary LIKE ? OR technical_description LIKE ?)
    """
    f_params = [pattern, pattern, pattern, pattern, pattern]
    if cid:
        f_sql += " AND case_id = ?"
        f_params.append(cid)
    f_sql += " LIMIT 25"
    cursor.execute(f_sql, f_params)
    results["findings"] = [dict(row) for row in cursor.fetchall()]

    # 6. Search IOCs
    i_sql = """
        SELECT id, case_id, type, value, severity, source, description, associated_pid
        FROM iocs
        WHERE (value LIKE ? OR description LIKE ? OR source LIKE ? OR type LIKE ?)
    """
    i_params = [pattern, pattern, pattern, pattern]
    if cid:
        i_sql += " AND case_id = ?"
        i_params.append(cid)
    i_sql += " LIMIT 25"
    cursor.execute(i_sql, i_params)
    results["iocs"] = [dict(row) for row in cursor.fetchall()]

    # 7. Search Timeline
    t_sql = """
        SELECT id, evidence_id, timestamp, event_type, description, source_plugin, pid, process_name, inferred, confidence
        FROM timeline_events
        WHERE (description LIKE ? OR event_type LIKE ? OR source_plugin LIKE ? OR process_name LIKE ? OR CAST(pid AS TEXT) = ?)
    """
    t_params = [pattern, pattern, pattern, pattern, q]
    if eid:
        t_sql += " AND evidence_id = ?"
        t_params.append(eid)
    t_sql += " ORDER BY timestamp DESC LIMIT 25"
    cursor.execute(t_sql, t_params)
    results["timeline"] = [dict(row) for row in cursor.fetchall()]

    # 8. Search Evidence
    e_sql = """
        SELECT id, case_id, filename, filepath, file_size, sha256, os_type, verification_status
        FROM evidence
        WHERE (filename LIKE ? OR filepath LIKE ? OR sha256 LIKE ? OR id LIKE ?)
    """
    e_params = [pattern, pattern, pattern, pattern]
    if cid:
        e_sql += " AND case_id = ?"
        e_params.append(cid)
    e_sql += " LIMIT 10"
    cursor.execute(e_sql, e_params)
    results["evidence"] = [dict(row) for row in cursor.fetchall()]

    results["network_connections"] = results["connections"]
    results["timeline_events"] = results["timeline"]

    counts = {k: len(v) for k, v in results.items()}
    total_matches = sum(len(v) for k, v in results.items() if k not in ("network_connections", "timeline_events"))

    return jsonify({
        "status": "success",
        "query": q,
        "total_matches": total_matches,
        "counts": counts,
        "results": results
    })
