-- Looking Glass schema. Idempotent: executed on every start.

CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    source       TEXT NOT NULL,            -- firewall, nginx, unbound, crowdsec, suricata, zenarmor, qfeeds, auth, vpn, dhcp, system
    host         TEXT,
    program      TEXT,
    severity     SMALLINT NOT NULL DEFAULT 6,  -- syslog severity 0 (emerg) .. 7 (debug)
    action       TEXT,                     -- pass/block/drop/ban/alert/login_failed/...
    src_ip       INET,
    src_port     INTEGER,
    dst_ip       INET,
    dst_port     INTEGER,
    proto        TEXT,
    interface    TEXT,
    direction    TEXT,
    username     TEXT,
    domain       TEXT,
    src_country  TEXT,
    dst_country  TEXT,
    message      TEXT,
    data         JSONB,
    uid          TEXT                      -- dedupe key for API-pulled records
);

CREATE INDEX IF NOT EXISTS events_ts_idx         ON events USING BRIN (ts);
-- (source, ts): events_source_ts_cover_idx, built in the background (db.BACKGROUND_INDEXES)
CREATE INDEX IF NOT EXISTS events_src_ip_idx     ON events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_dst_ip_idx     ON events (dst_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_action_ts_idx  ON events (action, ts DESC);
CREATE INDEX IF NOT EXISTS events_domain_idx     ON events (domain) WHERE domain IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS events_uid_idx ON events (uid) WHERE uid IS NOT NULL;
-- more indexes for the dashboards are built in the background after the start: db.BACKGROUND_INDEXES
-- vacuum the (append-only) events table after every ~1 % new rows instead of 20 %: the dashboards read the blocked
-- traffic from an index alone (index-only scan) only for pages vacuum has marked all-visible - with 20 % the newest
-- days of a large table would not be. Such a vacuum only visits the new pages. (PostgreSQL 13+)
DO $$ BEGIN
    ALTER TABLE events SET (autovacuum_vacuum_insert_scale_factor = 0.01);
EXCEPTION WHEN invalid_parameter_value OR syntax_error THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS metrics (
    ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
    name   TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '',
    value  DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS metrics_name_ts_idx ON metrics (name, labels, ts DESC);

-- latest result of every OPNsense API call (system status, gateways, ...)
CREATE TABLE IF NOT EXISTS snapshots (
    key  TEXT PRIMARY KEY,
    ts   TIMESTAMPTZ NOT NULL DEFAULT now(),
    data JSONB
);

CREATE TABLE IF NOT EXISTS alerts (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,             -- info, low, medium, high, critical
    title       TEXT NOT NULL,
    description TEXT,
    src_ip      INET,
    dst_ip      INET,
    count       INTEGER NOT NULL DEFAULT 1,
    status      TEXT NOT NULL DEFAULT 'open',  -- open, acknowledged, closed
    fingerprint TEXT NOT NULL,
    data        JSONB
);
CREATE INDEX IF NOT EXISTS alerts_status_idx ON alerts (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_fp_idx ON alerts (fingerprint, status);

-- devices seen through DHCP leases / ARP, used for "new device" detection
CREATE TABLE IF NOT EXISTS devices (
    mac        TEXT PRIMARY KEY,
    ip         INET,
    hostname   TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    period_h   INTEGER NOT NULL,
    title      TEXT NOT NULL,
    data       JSONB NOT NULL,
    ai_summary TEXT
);

CREATE TABLE IF NOT EXISTS ai_chats (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    title      TEXT NOT NULL,
    messages   JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value JSONB
);

-- ---------------------------------------------------------------- auth ---
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    BOOLEAN NOT NULL DEFAULT false,
    session_version INTEGER NOT NULL DEFAULT 1,   -- bumped on password/MFA reset to invalidate sessions
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login      TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,          -- base64url
    public_key    BYTEA NOT NULL,
    sign_count    BIGINT NOT NULL DEFAULT 0,
    name          TEXT NOT NULL,
    transports    JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used     TIMESTAMPTZ
);

-- ------------------------------------------------------------ devices+ ---
ALTER TABLE devices ADD COLUMN IF NOT EXISTS vendor TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS interface TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS sources TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS lease_type TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS lease_expires TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS online BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS trusted BOOLEAN NOT NULL DEFAULT false;
-- where the name came from (manual, dnsmasq-static, dhcp-*, dns, arp, zenarmor); a better source replaces a worse one
ALTER TABLE devices ADD COLUMN IF NOT EXISTS name_source TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS name_rank SMALLINT NOT NULL DEFAULT 0;
-- where the device is connected, from UniFi: "wifi" / "wired", "AP Living room · Home (5 GHz)" / "Switch Office port 5"
ALTER TABLE devices ADD COLUMN IF NOT EXISTS conn_type TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS conn_where TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS conn_signal INTEGER;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS conn_seen TIMESTAMPTZ;
-- per-device alert limits set on the Devices page; a missing key = the global setting (Settings › Behaviour & ML):
-- {"volume_factor": 0..1000 (0 = off), "ml_sensitivity": off|low|medium|high, "risk_threshold": 0..1000 (0 = never),
--  "volume_alerts" / "ml_alerts": alert|silent, "new_country" / "new_port" / "new_domain" / "new_tls" / "odd_hours":
--  alert|silent|off, "stable_max": 0..1000, "min_days": 1..60}  (behavior.LIMITS). silent = the alert is stored closed
-- with close_reason 'muted': never shown as open, but it counts for attack chains, corroboration and the risk score
ALTER TABLE devices ADD COLUMN IF NOT EXISTS limits JSONB NOT NULL DEFAULT '{}';
-- the kind of device, set on the Devices page (behavior.DEVICE_TYPES): its defaults sit between the device's own
-- limits and the global settings - a laptop or phone does not get "new country" alerts like a camera. NULL = not set
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type TEXT;
-- every address of a device with several (OPNsense: one MAC for a port and its VLANs); ip is the main one
ALTER TABLE devices ADD COLUMN IF NOT EXISTS ips INET[];
-- the hardware address of a device not keyed by it (OPNsense interface "if:vlan0.20": VLANs share the port's MAC)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS hwaddr TEXT;
-- dnsmasq writes "*" and the ARP table "-" / "?" when a device has no name: these are no names
UPDATE devices SET hostname = NULL, name_source = NULL, name_rank = 0
 WHERE hostname IS NOT NULL AND name_rank < 100 AND lower(btrim(hostname)) IN ('', '*', '-', '?', 'unknown', '<unknown>', '(unknown)');
-- tunnel clients (WireGuard) that Zenarmor reported with a placeholder MAC were merged into one bogus device; they
-- are listed under their IP now (ip: keys)
DELETE FROM devices WHERE mac IN ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff');
-- Zenarmor reports the IP as host name when it knows none: no name either
UPDATE devices SET hostname = NULL, name_source = NULL, name_rank = 0
 WHERE name_source = 'zenarmor' AND hostname ~ '^[0-9.]+$|^[0-9a-fA-F:]*:[0-9a-fA-F:]*$';

-- ------------------------------------------------------------- unraid ---
CREATE TABLE IF NOT EXISTS unraid_servers (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,                 -- e.g. http://tower.lan  (GraphQL at /graphql)
    api_key     TEXT NOT NULL,
    verify_ssl  BOOLEAN NOT NULL DEFAULT false,
    docker_url  TEXT,                          -- optional docker socket proxy, e.g. http://tower.lan:2375
    collect_logs BOOLEAN NOT NULL DEFAULT true,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- per array/pool preferences: {"sensor_temps": "auto"|"off", "groups": {"<name>": {"exclude": bool, "smart_minutes": int}}}
ALTER TABLE unraid_servers ADD COLUMN IF NOT EXISTS storage JSONB NOT NULL DEFAULT '{}';
-- UPS through NUT (upsd): '' = try the Unraid host when the API knows no UPS, 'off', or '[ups@]host[:port]'
ALTER TABLE unraid_servers ADD COLUMN IF NOT EXISTS nut TEXT NOT NULL DEFAULT '';

-- log alert rules for Unraid Docker containers (Unraid › Docker): which lines count, how many in how many minutes
CREATE TABLE IF NOT EXISTS container_log_rules (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    server_id  BIGINT,                              -- NULL = every Unraid server
    containers TEXT[] NOT NULL DEFAULT '{}',        -- name patterns with * and ?; empty = all containers
    match      TEXT[] NOT NULL DEFAULT '{}',        -- text (contains) or /regex/, case-insensitive; empty = error lines
    ignore     TEXT[] NOT NULL DEFAULT '{}',
    threshold  INTEGER NOT NULL DEFAULT 50,         -- 0 = no log alerts for these containers
    minutes    INTEGER NOT NULL DEFAULT 10,
    severity   TEXT NOT NULL DEFAULT 'low',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------- app settings ---
-- settings edited in the web UI; secrets are Fernet-encrypted ("fernet:..."), key file lives in the data volume
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CrowdSec alerts pulled before the scenario was stored (OPNsense calls it "reason"): it starts the message
UPDATE events SET data = coalesce(data, '{}'::jsonb) || jsonb_build_object('scenario', split_part(message, ' from ', 1))
 WHERE source = 'crowdsec' AND action = 'alert' AND data->>'scenario' IS NULL AND data->>'reason' IS NULL
   AND message LIKE '% from %' AND split_part(message, ' from ', 1) NOT IN ('', 'None');

-- Q-Feeds plugin events stored before they carried their blocklist (Threats › Q-Feeds links filter on it)
UPDATE events SET data = coalesce(data, '{}'::jsonb) || '{"blocklist": "Q-Feeds"}'::jsonb
 WHERE source = 'qfeeds' AND data->>'blocklist' IS NULL;

-- alert filters (Settings › Alert filters): stop or auto-close alerts by severity, rule, text and IP / network
CREATE TABLE IF NOT EXISTS alert_filters (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    name         TEXT,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    max_severity TEXT,                 -- matches this severity and everything below it
    rules        TEXT[] NOT NULL DEFAULT '{}',
    contains     TEXT,                 -- case-insensitive, title or description
    networks     TEXT,                 -- comma separated IPs / CIDRs, source or destination
    action       TEXT NOT NULL DEFAULT 'suppress',  -- suppress (not created) | close (created as closed)
    hits         BIGINT NOT NULL DEFAULT 0,
    last_hit     TIMESTAMPTZ
);
ALTER TABLE alert_filters ADD COLUMN IF NOT EXISTS match_mode TEXT NOT NULL DEFAULT 'all';  -- conditions: all (AND) / any (OR)
ALTER TABLE alert_filters ADD COLUMN IF NOT EXISTS text_mode TEXT NOT NULL DEFAULT 'any';   -- text terms: any (OR) / all (AND)
ALTER TABLE alert_filters ADD COLUMN IF NOT EXISTS set_severity TEXT;  -- action 'severity': the severity alerts get
-- ports and ranges ("22, 8000-8100"): every port of the alert's events on that side must be in the list
ALTER TABLE alert_filters ADD COLUMN IF NOT EXISTS src_ports TEXT;
ALTER TABLE alert_filters ADD COLUMN IF NOT EXISTS dst_ports TEXT;

-- email notification rules (Settings › Email & notifications)
CREATE TABLE IF NOT EXISTS notification_rules (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    name          TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    recipients    TEXT NOT NULL,
    min_severity  TEXT,                 -- this severity and above
    rules         TEXT[] NOT NULL DEFAULT '{}',
    contains      TEXT,
    networks      TEXT,
    match_mode    TEXT NOT NULL DEFAULT 'all',
    text_mode     TEXT NOT NULL DEFAULT 'any',
    on_escalation BOOLEAN NOT NULL DEFAULT true,  -- mail again when an alert's severity goes up
    min_interval  INTEGER NOT NULL DEFAULT 0,     -- minutes: at most one mail per interval (alerts are bundled)
    last_sent     TIMESTAMPTZ,
    sent_count    BIGINT NOT NULL DEFAULT 0,
    last_error    TEXT,
    last_error_at TIMESTAMPTZ
);

-- behaviour profiles: what each device (MAC, or IP when unknown) normally does
CREATE TABLE IF NOT EXISTS device_profile (
    key        TEXT NOT NULL,          -- MAC address, or IP
    kind       TEXT NOT NULL,          -- country | port | domain | tls | hour
    value      TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    hits       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key, kind, value)
);
CREATE INDEX IF NOT EXISTS device_profile_kind_value_idx ON device_profile (kind, value);

-- per device and hour: the features for volume checks and the Isolation Forest
CREATE TABLE IF NOT EXISTS device_hourly (
    key      TEXT NOT NULL,
    hour     TIMESTAMPTZ NOT NULL,
    ip       INET,
    features JSONB NOT NULL,
    PRIMARY KEY (key, hour)
);
CREATE INDEX IF NOT EXISTS device_hourly_hour_idx ON device_hourly (hour);

-- network-wide totals per hour (hour-of-week baselines)
CREATE TABLE IF NOT EXISTS hourly_stats (
    metric TEXT NOT NULL,
    hour   TIMESTAMPTZ NOT NULL,
    value  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (metric, hour)
);

-- threat intel indicators (abuse.ch, Tor, mining pools)
CREATE TABLE IF NOT EXISTS intel_indicators (
    kind  TEXT NOT NULL,                -- domain | ip | ja3
    value TEXT NOT NULL,
    feed  TEXT NOT NULL,
    info  TEXT,
    PRIMARY KEY (kind, value, feed)
);

-- first time any device looked up a (registered) domain
CREATE TABLE IF NOT EXISTS seen_domains (
    domain       TEXT PRIMARY KEY,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_client INET,
    registered   TIMESTAMPTZ,
    rdap_checked BOOLEAN NOT NULL DEFAULT false
);

-- risk score per device / address
CREATE TABLE IF NOT EXISTS risk_scores (
    entity  TEXT PRIMARY KEY,
    score   DOUBLE PRECISION NOT NULL,
    parts   JSONB,
    updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS close_reason TEXT;  -- 'false_positive' | 'resolved'

-- AI analysis of a report runs in the background: running | done | failed (+ the reason)
ALTER TABLE reports ADD COLUMN IF NOT EXISTS ai_state TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS ai_error TEXT;

-- alerts on API-pulled events (CrowdSec, Suricata, Q-Feeds) remember the time span of those events (they carry the
-- tool's own time, possibly long before the alert): alerts from before that get it from their events once
UPDATE alerts a SET data = coalesce(a.data, '{}'::jsonb) || jsonb_build_object(
    'events_from', to_char(s.f AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'events_to', to_char(s.t AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
FROM (SELECT a2.id, min(e.ts) f, max(e.ts) t FROM alerts a2 JOIN events e ON e.src_ip = a2.src_ip
        AND e.source = CASE a2.rule WHEN 'crowdsec' THEN 'crowdsec' WHEN 'ids' THEN 'suricata' ELSE 'qfeeds' END
      WHERE a2.rule IN ('crowdsec', 'ids', 'threat_intel_outbound', 'threat_intel_inbound')
        AND NOT coalesce(a2.data ? 'events_from', false) GROUP BY a2.id) s
WHERE a.id = s.id;

-- AI analyst privacy mode (Settings › AI analyst): the pseudonym of every local identifier sent to the AI, so a device
-- keeps the same pseudonym in every request, report and conversation. Conversations themselves keep the real values.
CREATE TABLE IF NOT EXISTS ai_pseudonyms (
    kind       TEXT NOT NULL,          -- net4 (private /24) | ip4 (own public) | net6 (/48 site) | ip6 | mac | email | name
    key        TEXT NOT NULL,          -- normalised real value
    real       TEXT NOT NULL,          -- real value as first seen (shown in the answers)
    fake       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key)
);

-- comments on alerts (Alerts page): why one was closed / a false positive, extra context ... also read by the AI analyst.
-- No foreign key on purpose: TRUNCATE alerts keeps working; the comments are deleted with their alert in the code.
CREATE TABLE IF NOT EXISTS alert_comments (
    id         BIGSERIAL PRIMARY KEY,
    alert_id   BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ,
    author     TEXT,
    body       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_comments_alert_idx ON alert_comments (alert_id, created_at);

-- hourly event counts for the dashboards (rollup.py): per hour and source, action, protocol, interface, direction,
-- destination port, source country and severity. Charts over 2+ days read these instead of every raw event. No NULLs
-- (PostgreSQL 14 has no NULLS NOT DISTINCT): '' / -1 stand for "none".
CREATE TABLE IF NOT EXISTS event_rollup (
    bucket      TIMESTAMPTZ NOT NULL,
    source      TEXT NOT NULL,
    action      TEXT NOT NULL,
    proto       TEXT NOT NULL,
    interface   TEXT NOT NULL,
    direction   TEXT NOT NULL,
    dst_port    INTEGER NOT NULL,
    src_country TEXT NOT NULL,
    severity    SMALLINT NOT NULL,
    n           INTEGER NOT NULL,
    PRIMARY KEY (bucket, source, action, proto, interface, direction, dst_port, src_country, severity)
);
-- upto: every event with id <= upto is counted in event_rollup; seen: the newest id at the previous run (events up to
-- there are counted next time - one run later, so a batch still being written is never skipped)
CREATE TABLE IF NOT EXISTS event_rollup_state (
    one  BOOLEAN PRIMARY KEY DEFAULT true CHECK (one),
    upto BIGINT NOT NULL DEFAULT 0,
    seen BIGINT NOT NULL DEFAULT 0
);
INSERT INTO event_rollup_state (one) VALUES (true) ON CONFLICT DO NOTHING;

-- container packages (packages.py, Unraid › Packages): one row per image in use; its list is in /data/packages
CREATE TABLE IF NOT EXISTS image_packages (
    key        TEXT PRIMARY KEY,                   -- digest, or image id / name:tag when the digest is unknown
    image      TEXT NOT NULL,                      -- as the containers use it
    repo       TEXT NOT NULL,
    digest     TEXT,
    containers JSONB NOT NULL DEFAULT '[]',        -- [{server, name, state}]
    status     TEXT NOT NULL DEFAULT 'pending',    -- ok | error | pending
    error      TEXT,
    read_at    TIMESTAMPTZ,
    source     TEXT,                               -- registry (exact digest) | Docker API export | registry (tag)
    packages   INTEGER,
    distro     TEXT,
    created    TEXT,                               -- when its containers were (re)created, when read
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- backups (backups.py, Infrastructure › Backups): one row per run of a backup tool, the same for every tool (Backrest
-- now, others later). Kept after the tool itself forgets the run; removed after 400 days (housekeeping).
CREATE TABLE IF NOT EXISTS backup_runs (
    source          TEXT NOT NULL,                -- backrest
    ext_id          TEXT NOT NULL,                -- the tool's own id of the run
    kind            TEXT NOT NULL,                -- backup | forget | prune | check | stats | restore
    job             TEXT NOT NULL DEFAULT '',     -- the backup job (Backrest: plan); '' for repository tasks
    repo            TEXT NOT NULL DEFAULT '',     -- where it is stored (Backrest: repository id)
    status          TEXT NOT NULL,                -- success | warning | error | running | pending | cancelled | unknown
    started         TIMESTAMPTZ,
    ended           TIMESTAMPTZ,
    duration_s      DOUBLE PRECISION,
    bytes_processed BIGINT,                       -- data read / scanned (restore: restored)
    bytes_added     BIGINT,                       -- new data written to the repository
    files_new       BIGINT,
    files_changed   BIGINT,
    files_total     BIGINT,
    snapshot_id     TEXT,
    message         TEXT,                         -- error / warning text
    data            JSONB NOT NULL DEFAULT '{}',  -- tool specific: progress, errors, repository stats ...
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source, ext_id)
);
CREATE INDEX IF NOT EXISTS backup_runs_started ON backup_runs (started DESC);
CREATE INDEX IF NOT EXISTS backup_runs_job ON backup_runs (source, kind, job, started DESC);

-- 7 / 30 day results of the Overview and the dashboards (periods.py): counted in the background on a schedule (or
-- with the refresh button) and shown from here - switching to such a period counts nothing. key = JSON
-- ["overview", hours] or ["dash", name, hours, tab]; viewed_at: those not looked at for a week are no longer refreshed
CREATE TABLE IF NOT EXISTS period_results (
    key         TEXT PRIMARY KEY,
    hours       DOUBLE PRECISION NOT NULL,
    computed_at TIMESTAMPTZ,
    viewed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    data        JSONB,
    error       TEXT
);
