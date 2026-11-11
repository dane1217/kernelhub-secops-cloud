CREATE TABLE organizations (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL,
 quota_daily INTEGER NOT NULL DEFAULT 100000, rate_minute INTEGER NOT NULL DEFAULT 1000,
 retention_days INTEGER NOT NULL DEFAULT 30, ai_enabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE workspaces (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL,
 UNIQUE (org_id,id)
);
CREATE TABLE users (
 id TEXT PRIMARY KEY, subject TEXT NOT NULL UNIQUE, email TEXT NOT NULL,
 platform_admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE memberships (
 org_id TEXT NOT NULL REFERENCES organizations(id), user_id TEXT NOT NULL REFERENCES users(id),
 role TEXT NOT NULL CHECK(role IN ('org_admin','analyst','viewer')), PRIMARY KEY(org_id,user_id)
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), csrf TEXT NOT NULL,
 expires_at TEXT NOT NULL
);
CREATE TABLE oidc_states (
 state_hash TEXT PRIMARY KEY, verifier TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE invitations (
 token_hash TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), email TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('org_admin','analyst','viewer')), expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE TABLE sources (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), workspace_id TEXT NOT NULL,
 name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('normalized','windows','linux')),
 last_seen TEXT, parser_failures INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(org_id,workspace_id) REFERENCES workspaces(org_id,id), UNIQUE(org_id,id)
);
CREATE TABLE credentials (
 token_hash TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), source_id TEXT,
 purpose TEXT NOT NULL CHECK(purpose IN ('ingest','api')), role TEXT NOT NULL, user_id TEXT,
 expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(org_id,source_id) REFERENCES sources(org_id,id)
);
CREATE TABLE usage_counters (
 org_id TEXT NOT NULL REFERENCES organizations(id), bucket TEXT NOT NULL, count INTEGER NOT NULL,
 PRIMARY KEY(org_id,bucket)
);
CREATE TABLE events (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), source_id TEXT NOT NULL,
 workspace_id TEXT NOT NULL, external_id TEXT NOT NULL, source_time TEXT NOT NULL, received_at TEXT NOT NULL,
 action TEXT NOT NULL, category TEXT NOT NULL, hostname TEXT, username TEXT, source_ip TEXT, destination_ip TEXT,
 outcome TEXT NOT NULL, severity TEXT NOT NULL, document TEXT NOT NULL, raw_json TEXT NOT NULL,
 raw_key TEXT NOT NULL, indexed INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(org_id,source_id) REFERENCES sources(org_id,id),
 FOREIGN KEY(org_id,workspace_id) REFERENCES workspaces(org_id,id),
 UNIQUE(org_id,source_id,external_id), UNIQUE(org_id,id)
);
CREATE INDEX event_correlation ON events(org_id,username,source_ip,source_time);
CREATE INDEX event_time ON events(org_id,received_at);
CREATE TABLE outbox (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), event_id TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','dead')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt TEXT NOT NULL, last_error TEXT,
 FOREIGN KEY(org_id,event_id) REFERENCES events(org_id,id), UNIQUE(event_id)
);
CREATE INDEX outbox_ready ON outbox(status,next_attempt);
CREATE TABLE rule_settings (
 org_id TEXT NOT NULL REFERENCES organizations(id), rule_id TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, suppressed_until TEXT, excluded_users TEXT NOT NULL DEFAULT '[]',
 threshold_count INTEGER, PRIMARY KEY(org_id,rule_id)
);
CREATE TABLE alerts (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), rule_id TEXT NOT NULL,
 rule_version TEXT NOT NULL, rule_snapshot TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'new', assigned_to TEXT, fingerprint TEXT NOT NULL,
 created_at TEXT NOT NULL, evidence_ids TEXT NOT NULL,
 UNIQUE(org_id,fingerprint), UNIQUE(org_id,id)
);
CREATE TABLE incidents (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id), title TEXT NOT NULL,
 severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', assigned_to TEXT,
 resolution TEXT, customer_summary TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 UNIQUE(org_id,id)
);
CREATE TABLE incident_alerts (
 org_id TEXT NOT NULL, incident_id TEXT NOT NULL, alert_id TEXT NOT NULL,
 FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id),
 FOREIGN KEY(org_id,alert_id) REFERENCES alerts(org_id,id), PRIMARY KEY(org_id,incident_id,alert_id)
);
CREATE TABLE incident_entries (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, kind TEXT NOT NULL,
 body TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(org_id,incident_id) REFERENCES incidents(org_id,id)
);
CREATE TABLE audit (
 id TEXT PRIMARY KEY, org_id TEXT REFERENCES organizations(id), actor TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX audit_tenant_time ON audit(org_id,created_at);
CREATE TABLE worker_health (name TEXT PRIMARY KEY, last_seen TEXT NOT NULL);
