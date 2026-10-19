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

-- ------------------------------------------------------- app settings ---
-- settings edited in the web UI; secrets are Fernet-encrypted ("fernet:..."), key file lives in the data volume
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
