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
CREATE INDEX IF NOT EXISTS events_source_ts_idx  ON events (source, ts DESC);
CREATE INDEX IF NOT EXISTS events_src_ip_idx     ON events (src_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_dst_ip_idx     ON events (dst_ip, ts DESC);
CREATE INDEX IF NOT EXISTS events_action_ts_idx  ON events (action, ts DESC);
CREATE INDEX IF NOT EXISTS events_domain_idx     ON events (domain) WHERE domain IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS events_uid_idx ON events (uid) WHERE uid IS NOT NULL;

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
-- dnsmasq writes "*" and the ARP table "-" / "?" when a device has no name: these are no names
UPDATE devices SET hostname = NULL, name_source = NULL, name_rank = 0
 WHERE hostname IS NOT NULL AND name_rank < 100 AND lower(btrim(hostname)) IN ('', '*', '-', '?', 'unknown', '<unknown>', '(unknown)');

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
