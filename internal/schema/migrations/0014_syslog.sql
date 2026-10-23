-- Syslog devices (docs/ARCHITECTURE.md §4.10): equipment without an agent
-- (switches, firewalls, NAS) sends syslog to the gateways, which take the
-- device from the sender's address. The device id shares the namespace
-- of node ids (Loki node label, CrowdSec node_id).
CREATE TABLE openpicket.syslog_devices (
    id          text PRIMARY KEY,
    description text NOT NULL DEFAULT '',
    -- Addresses or networks the device sends from; the longest match wins.
    sources     cidr[] NOT NULL,
    labels      jsonb NOT NULL DEFAULT '{}',
    -- Program names by syslog tag ("%ASA-4-106023" -> "cisco-asa"); the
    -- key "*" names lines without a syslog header.
    programs    jsonb NOT NULL DEFAULT '{}',
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT ''
);

CREATE FUNCTION openpicket.notify_syslog_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('openpicket_syslog', COALESCE(NEW.id, OLD.id));
    RETURN NULL;
END $$;

CREATE TRIGGER syslog_devices_changed AFTER INSERT OR UPDATE OR DELETE ON openpicket.syslog_devices
    FOR EACH ROW EXECUTE FUNCTION openpicket.notify_syslog_changed();

-- Messages received per sender address, registered or not (the UI lists
-- unregistered senders to register them). Counts are added by the
-- gateways every 30 seconds; rows not seen for 30 days are removed.
CREATE TABLE openpicket.syslog_sources (
    addr       inet PRIMARY KEY,
    -- The device the last messages were taken for; NULL: unregistered.
    device_id  text,
    messages   bigint NOT NULL DEFAULT 0,
    -- Messages of an unregistered sender that were dropped.
    dropped    bigint NOT NULL DEFAULT 0,
    -- The latest message (truncated), to recognize the sender.
    sample     text NOT NULL DEFAULT '',
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now()
);

-- The syslog listeners of each gateway replica ("udp :5514").
ALTER TABLE openpicket.gateway_info ADD COLUMN syslog text[] NOT NULL DEFAULT '{}';
