-- BugHunter Pro Database Schema
-- Version: 7.0
-- Purpose: Store CVEs, Exploits, and Scan History

-- ============================================================================
-- CVE Database Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    published_date TEXT,
    last_modified_date TEXT,
    cvss_v3_score REAL,
    cvss_v3_severity TEXT,
    cvss_v2_score REAL,
    cvss_v2_severity TEXT,
    cwe_id TEXT,
    refs TEXT, -- JSON array of reference URLs (renamed from 'references' to avoid SQL keyword)
    vulnerable_products TEXT, -- JSON array of CPE strings
    exploit_available INTEGER DEFAULT 0, -- Boolean: 0 = No, 1 = Yes
    exploit_maturity TEXT, -- proof-of-concept, functional, high
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for CVE table
CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cvss_score ON cves(cvss_v3_score);
CREATE INDEX IF NOT EXISTS idx_severity ON cves(cvss_v3_severity);
CREATE INDEX IF NOT EXISTS idx_cwe ON cves(cwe_id);
CREATE INDEX IF NOT EXISTS idx_published ON cves(published_date);

-- ============================================================================
-- Exploits Database Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS exploits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exploit_id TEXT UNIQUE,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    author TEXT,
    type TEXT, -- remote, local, webapps, dos, etc.
    platform TEXT, -- php, asp, jsp, python, etc.
    exploit_date TEXT,
    verified INTEGER DEFAULT 0, -- Boolean: verified by ExploitDB
    exploit_code TEXT, -- Full exploit code or URL
    source TEXT, -- exploitdb, github, metasploit, etc.
    source_url TEXT,
    tags TEXT, -- JSON array of tags
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Indexes for Exploits table
CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploit_type ON exploits(type);
CREATE INDEX IF NOT EXISTS idx_exploit_platform ON exploits(platform);
CREATE INDEX IF NOT EXISTS idx_exploit_verified ON exploits(verified);

-- ============================================================================
-- Scan History Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    target_url TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    duration REAL,
    status TEXT, -- running, completed, failed, cancelled
    pages_scanned INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    scanner_version TEXT,
    config TEXT, -- JSON of scan configuration
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for Scan History table
CREATE INDEX IF NOT EXISTS idx_scan_id ON scan_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_target_url ON scan_history(target_url);
CREATE INDEX IF NOT EXISTS idx_scan_date ON scan_history(start_time);
CREATE INDEX IF NOT EXISTS idx_scan_status ON scan_history(status);

-- ============================================================================
-- Vulnerability Findings Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT,
    payload TEXT,
    evidence TEXT,
    cve_id TEXT,
    remediation TEXT,
    confidence REAL DEFAULT 0.0, -- 0.0 to 1.0
    false_positive INTEGER DEFAULT 0, -- Boolean
    owasp_category TEXT,
    cwe_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_history(scan_id),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Indexes for Findings table
CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_finding_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_finding_cve ON findings(cve_id);

-- ============================================================================
-- CVE Sync Metadata Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS sync_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL, -- nvd, exploitdb, github_advisory
    last_sync_time TEXT,
    last_sync_status TEXT, -- success, failed, partial
    records_synced INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_failed INTEGER DEFAULT 0,
    sync_duration REAL,
    error_message TEXT,
    next_sync_time TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Index for Sync Metadata
CREATE INDEX IF NOT EXISTS idx_sync_source ON sync_metadata(source);
CREATE INDEX IF NOT EXISTS idx_sync_time ON sync_metadata(last_sync_time);

-- ============================================================================
-- Payload Library Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vuln_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    description TEXT,
    encoding TEXT, -- none, url, base64, unicode, etc.
    category TEXT, -- injection, xss, xxe, etc.
    effectiveness_score REAL DEFAULT 0.0, -- Based on success rate
    usage_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    cve_id TEXT,
    source TEXT, -- manual, cve, auto-generated
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
);

-- Indexes for Payloads table
CREATE INDEX IF NOT EXISTS idx_payload_type ON payloads(vuln_type);
CREATE INDEX IF NOT EXISTS idx_payload_category ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payload_effectiveness ON payloads(effectiveness_score);

-- ============================================================================
-- Initial Data: Insert some metadata
-- ============================================================================
INSERT OR IGNORE INTO sync_metadata (source, last_sync_status) VALUES 
    ('nvd', 'never'),
    ('exploitdb', 'never'),
    ('github_advisory', 'never');
