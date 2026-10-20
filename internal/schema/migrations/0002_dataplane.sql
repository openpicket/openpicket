-- Data plane state of openpicket-manager replicas.

-- Which replica holds the channel B session of a node. A new session
-- replaces the row; the previous holder closes its session on NOTIFY.
CREATE TABLE openpicket.node_sessions (
    node_id      text PRIMARY KEY REFERENCES openpicket.nodes(id) ON DELETE CASCADE,
    session_id   text NOT NULL,
    replica      text NOT NULL,
    remote_addr  text NOT NULL DEFAULT '',
    boot_id      text NOT NULL DEFAULT '',
    connected_at timestamptz NOT NULL,
    heartbeat_at timestamptz NOT NULL
);

-- Last log batch delivered to each acknowledgement sink, so a batch
-- resent to another replica is not delivered twice (§4.2).
CREATE TABLE openpicket.sink_watermarks (
    node_id    text NOT NULL,
    boot_id    text NOT NULL,
    sink       text NOT NULL,
    seq        bigint NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, boot_id, sink)
);
CREATE INDEX sink_watermarks_updated ON openpicket.sink_watermarks (updated_at);

-- Runtime settings edited in the UI (JSON values).
CREATE TABLE openpicket.settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION openpicket.notify_setting_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('openpicket_settings', COALESCE(NEW.key, OLD.key));
    RETURN NULL;
END $$;

CREATE TRIGGER settings_changed AFTER INSERT OR UPDATE OR DELETE ON openpicket.settings
    FOR EACH ROW EXECUTE FUNCTION openpicket.notify_setting_changed();

-- Fencing for leader-only tasks: a leader writes only while its epoch is
-- the current one.
CREATE TABLE openpicket.leader_epochs (
    task       text PRIMARY KEY,
    epoch      bigint NOT NULL,
    holder     text NOT NULL,
    acquired_at timestamptz NOT NULL
);
