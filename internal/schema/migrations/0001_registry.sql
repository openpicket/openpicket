-- Node registry shared by openpicket-manager and openpicket-suricontroller,
-- the suricontroller store and the audit log.

CREATE SCHEMA IF NOT EXISTS openpicket;
CREATE SCHEMA IF NOT EXISTS suricontroller;

CREATE TABLE openpicket.nodes (
    id                text PRIMARY KEY,
    -- "ssh-ed25519 AAAA... <id>"
    public_key        text NOT NULL,
    -- X25519 form of the key: the identity both channels authenticate.
    x25519            bytea NOT NULL UNIQUE,
    fingerprint       text NOT NULL UNIQUE,
    enabled           boolean NOT NULL DEFAULT true,
    description       text NOT NULL DEFAULT '',
    labels            jsonb NOT NULL DEFAULT '{}',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    -- Owned by suricontroller: hello, interface modes, log policy, desired
    -- and applied state, last apply report.
    suri_state        jsonb NOT NULL DEFAULT '{}',
    suri_last_seen_at timestamptz,
    -- Channel B (data plane) presence.
    dp_last_seen_at   timestamptz
);

-- Registry changes (not suri_state, which changes on every heartbeat).
CREATE FUNCTION openpicket.notify_node_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('openpicket_nodes', COALESCE(NEW.id, OLD.id));
    RETURN NULL;
END $$;

CREATE TRIGGER nodes_registry_insert_delete AFTER INSERT OR DELETE ON openpicket.nodes
    FOR EACH ROW EXECUTE FUNCTION openpicket.notify_node_changed();
-- suricontroller rewrites every column on each update, so compare values.
CREATE TRIGGER nodes_registry_update AFTER UPDATE ON openpicket.nodes
    FOR EACH ROW
    WHEN (OLD.public_key IS DISTINCT FROM NEW.public_key OR OLD.x25519 IS DISTINCT FROM NEW.x25519
          OR OLD.enabled IS DISTINCT FROM NEW.enabled OR OLD.labels IS DISTINCT FROM NEW.labels)
    EXECUTE FUNCTION openpicket.notify_node_changed();

CREATE TABLE openpicket.audit (
    id        bigserial PRIMARY KEY,
    time      timestamptz NOT NULL DEFAULT now(),
    -- openpicket | suricontroller
    source    text NOT NULL,
    principal text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL DEFAULT '',
    detail    text NOT NULL DEFAULT ''
);
CREATE INDEX audit_time ON openpicket.audit (time DESC);

CREATE TABLE suricontroller.apply_history (
    id         bigserial PRIMARY KEY,
    node_id    text NOT NULL REFERENCES openpicket.nodes(id) ON DELETE CASCADE,
    report     jsonb NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX apply_history_node ON suricontroller.apply_history (node_id, id);

CREATE TABLE suricontroller.deploy_policies (
    kind             text PRIMARY KEY,
    mode             text NOT NULL,
    pinned_commit    text NOT NULL,
    effective_commit text NOT NULL,
    updated_at       timestamptz NOT NULL,
    updated_by       text NOT NULL
);

CREATE TABLE suricontroller.providers (
    name             text PRIMARY KEY,
    type             text NOT NULL,
    enabled          boolean NOT NULL,
    interval_seconds bigint NOT NULL,
    options          jsonb NOT NULL,
    last_fetch_at    timestamptz,
    last_success_at  timestamptz,
    last_error       text NOT NULL DEFAULT '',
    last_commit      text NOT NULL DEFAULT '',
    checksum         text NOT NULL DEFAULT ''
);

CREATE TABLE suricontroller.settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);
