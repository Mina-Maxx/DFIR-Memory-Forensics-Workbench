"""
Database DDL and Schema Definitions for DFIR Workbench V2
"""

SCHEMA_DDL = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- 1. Cases
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    investigator TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    status TEXT DEFAULT 'Open',
    workspace_path TEXT,
    chain_of_custody TEXT
);

-- 2. Evidence
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    file_size INTEGER,
    sha256 TEXT,
    md5 TEXT,
    os_type TEXT,
    architecture TEXT,
    kernel_info TEXT,
    vol_compatibility TEXT,
    symbol_status TEXT,
    import_timestamp TEXT,
    acquisition_timestamp TEXT,
    status TEXT DEFAULT 'Ready',
    verification_status TEXT DEFAULT 'Verified',
    last_verified TEXT,
    metadata TEXT,
    created_at TEXT
);

-- 3. Plugin Executions (Reproducibility records)
CREATE TABLE IF NOT EXISTS plugin_executions (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    plugin_name TEXT NOT NULL,
    arguments TEXT,
    command TEXT,
    status TEXT,
    current_activity TEXT,
    stdout_tail TEXT,
    stderr TEXT,
    error_message TEXT,
    raw_output_path TEXT,
    stdout_hash TEXT,
    stderr_hash TEXT,
    result_hash TEXT,
    vol_version TEXT,
    python_version TEXT,
    platform TEXT,
    plugin_version TEXT,
    symbol_table TEXT,
    configuration TEXT,
    working_directory TEXT,
    execution_host TEXT,
    start_time TEXT,
    end_time TEXT,
    runtime_seconds REAL,
    result_count INTEGER,
    created_at TEXT
);

-- 4. Plugin Results (Parsed tables)
CREATE TABLE IF NOT EXISTS plugin_results (
    id TEXT PRIMARY KEY,
    execution_id TEXT REFERENCES plugin_executions(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    plugin_name TEXT,
    headers TEXT,
    data TEXT,
    storage_mode TEXT,
    file_path TEXT,
    row_count INTEGER,
    created_at TEXT
);

-- 5. Processes
CREATE TABLE IF NOT EXISTS processes (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    name TEXT NOT NULL,
    path TEXT,
    command_line TEXT,
    create_time TEXT,
    exit_time TEXT,
    session_id INTEGER,
    user_info TEXT,
    in_pslist BOOLEAN DEFAULT 0,
    in_psscan BOOLEAN DEFAULT 0,
    in_pstree BOOLEAN DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'Normal',
    confidence TEXT DEFAULT 'Medium',
    severity TEXT DEFAULT 'Normal',
    verdict TEXT DEFAULT 'unreviewed',
    risk_details TEXT,
    metadata TEXT
);

-- 6. Network Connections
CREATE TABLE IF NOT EXISTS network_connections (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    pid INTEGER,
    process_name TEXT,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    protocol TEXT,
    state TEXT,
    created_time TEXT,
    owner TEXT,
    scope TEXT DEFAULT 'Internal',
    is_ioc BOOLEAN DEFAULT 0,
    threat_intel TEXT DEFAULT 'Unknown'
);

-- 7. DLLs
CREATE TABLE IF NOT EXISTS dlls (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    pid INTEGER,
    name TEXT,
    path TEXT,
    base_address TEXT,
    size INTEGER
);

-- 8. Memory Regions (RWX / VAD)
CREATE TABLE IF NOT EXISTS memory_regions (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    pid INTEGER,
    start_address TEXT,
    protection TEXT,
    tag TEXT,
    suspicious BOOLEAN DEFAULT 0,
    details TEXT
);

-- 9. Artifacts (First-class normalized artifacts with provenance)
CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL,
    source_plugin TEXT NOT NULL,
    source_execution_id TEXT,
    entity_id TEXT NOT NULL,
    timestamp TEXT,
    raw_reference TEXT,
    normalized_data TEXT,
    hash TEXT,
    created_at TEXT
);

-- 10. Detection Rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    category TEXT,
    weight INTEGER DEFAULT 10,
    conditions TEXT,
    confidence TEXT DEFAULT 'Medium',
    severity TEXT DEFAULT 'Medium',
    references_json TEXT,
    mitre_attack TEXT,
    mitre_tactic TEXT,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    enabled BOOLEAN DEFAULT 1,
    version TEXT DEFAULT '2.0',
    author TEXT,
    created_at TEXT
);

-- 11. Detections (Heuristic detections distinct from confirmed findings)
CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    rule_id TEXT,
    name TEXT NOT NULL,
    category TEXT,
    severity TEXT DEFAULT 'Medium',
    confidence TEXT DEFAULT 'Medium',
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT 'process',
    reason TEXT,
    contributing_factors TEXT,
    mitre_attack TEXT,
    mitre_tactic TEXT,
    mitre_technique_id TEXT,
    mitre_technique_name TEXT,
    supporting_artifacts TEXT,
    created_at TEXT
);

-- 12. Findings (Formal analyst findings with lifecycle)
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'Medium',
    confidence TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'detected',
    source_type TEXT DEFAULT 'correlation',
    affected_entity TEXT,
    associated_pid INTEGER DEFAULT 0,
    associated_process_name TEXT DEFAULT '',
    description TEXT,
    summary TEXT,
    technical_description TEXT,
    supporting_evidence TEXT,
    analyst_assessment TEXT,
    limitations TEXT,
    mitre_attack TEXT,
    created_at TEXT,
    updated_at TEXT
);

-- 13. Finding Associations
CREATE TABLE IF NOT EXISTS finding_artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    artifact_id TEXT REFERENCES artifacts(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'supports',
    relationship TEXT DEFAULT 'supports',
    explanation TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_iocs (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    ioc_id TEXT REFERENCES iocs(id) ON DELETE CASCADE,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_timeline_events (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    timeline_event_id TEXT REFERENCES timeline_events(id) ON DELETE CASCADE,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS finding_entities (
    id TEXT PRIMARY KEY,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    created_at TEXT
);

-- 14. IOCs
CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    severity TEXT DEFAULT 'Medium',
    confidence TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'Observed',
    source TEXT,
    description TEXT,
    associated_finding_id TEXT,
    associated_pid INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT
);

-- 15. Timeline Events
CREATE TABLE IF NOT EXISTS timeline_events (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    pid INTEGER,
    process_name TEXT,
    entity_id TEXT,
    source_plugin TEXT,
    plugin_execution_id TEXT,
    source_artifact_id TEXT,
    confidence TEXT DEFAULT 'High',
    severity TEXT DEFAULT 'Low',
    inferred BOOLEAN DEFAULT 0,
    details TEXT,
    created_at TEXT
);

-- 16. Event-based Chain of Custody
CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    source TEXT,
    destination TEXT,
    hash_before TEXT,
    hash_after TEXT,
    notes TEXT,
    metadata TEXT,
    timestamp TEXT NOT NULL
);

-- 17. Analyst Notes & Bookmarks
CREATE TABLE IF NOT EXISTS analyst_notes (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    text TEXT NOT NULL,
    author TEXT DEFAULT 'Analyst',
    timestamp TEXT NOT NULL,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS bookmarks (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    notes TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    content TEXT,
    author TEXT,
    created_at TEXT,
    updated_at TEXT
);

-- 18. Heuristics & Artifact Dumps
CREATE TABLE IF NOT EXISTS risk_assessments (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    pid INTEGER,
    rule_id TEXT,
    rule_name TEXT,
    category TEXT,
    weight INTEGER,
    reason TEXT,
    evidence_text TEXT,
    confidence TEXT,
    is_false_positive BOOLEAN DEFAULT 0,
    analyst_override TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS dump_artifacts (
    id TEXT PRIMARY KEY,
    case_id TEXT REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    dump_type TEXT,
    source_plugin TEXT,
    output_path TEXT,
    sha256 TEXT,
    pid INTEGER,
    address TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS yara_matches (
    id TEXT PRIMARY KEY,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE CASCADE,
    rule TEXT,
    tags TEXT,
    pid INTEGER,
    target TEXT,
    strings_matched TEXT,
    offset TEXT,
    details TEXT,
    process_name TEXT,
    created_at TEXT
);

-- Indexes for lightning fast lookups
CREATE INDEX IF NOT EXISTS idx_proc_ev_pid ON processes(evidence_id, pid);
CREATE INDEX IF NOT EXISTS idx_net_ev ON network_connections(evidence_id);
CREATE INDEX IF NOT EXISTS idx_tl_ev ON timeline_events(evidence_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_exec_ev ON plugin_executions(evidence_id);
CREATE INDEX IF NOT EXISTS idx_iocs_case ON iocs(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_ev ON artifacts(evidence_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_artifacts_entity ON artifacts(evidence_id, entity_id);
CREATE INDEX IF NOT EXISTS idx_detections_ev ON detections(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_ev ON custody_events(evidence_id, timestamp);
"""
