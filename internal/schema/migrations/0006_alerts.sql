-- Copy of the CrowdSec LAPI alerts and their decisions for search, facets
-- and the dashboard (docs/ARCHITECTURE.md §5.7). Written by the "alerts"
-- leader; one LAPI instance per name.

CREATE TABLE openpicket.alerts (
    instance     text NOT NULL,
    id           bigint NOT NULL,
    uuid         text NOT NULL DEFAULT '',
    scenario     text NOT NULL,
    message      text NOT NULL DEFAULT '',
    source_scope text NOT NULL DEFAULT '',
    source_value text NOT NULL DEFAULT '',
    source_ip    text NOT NULL DEFAULT '',
    source_range text NOT NULL DEFAULT '',
    country      text NOT NULL DEFAULT '',
    as_number    text NOT NULL DEFAULT '',
    as_name      text NOT NULL DEFAULT '',
    latitude     real NOT NULL DEFAULT 0,
    longitude    real NOT NULL DEFAULT 0,
    events_count int NOT NULL DEFAULT 0,
    simulated    boolean NOT NULL DEFAULT false,
    remediation  boolean NOT NULL DEFAULT false,
    machine_id   text NOT NULL DEFAULT '',
    start_at     timestamptz,
    stop_at      timestamptz,
    created_at   timestamptz NOT NULL,
    -- Alert context: {"key": ["value", ...]}.
    meta         jsonb NOT NULL DEFAULT '{}',
    node_id      text NOT NULL DEFAULT '',
    direction    text NOT NULL DEFAULT '',
    events       jsonb NOT NULL DEFAULT '[]',
    synced_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance, id)
);
CREATE INDEX alerts_created ON openpicket.alerts (created_at DESC);
CREATE INDEX alerts_value ON openpicket.alerts (source_value);
CREATE INDEX alerts_scenario ON openpicket.alerts (scenario);

CREATE TABLE openpicket.alert_decisions (
    instance  text NOT NULL,
    id        bigint NOT NULL,
    alert_id  bigint NOT NULL,
    type      text NOT NULL,
    scope     text NOT NULL,
    value     text NOT NULL,
    origin    text NOT NULL,
    scenario  text NOT NULL,
    until     timestamptz NOT NULL,
    simulated boolean NOT NULL DEFAULT false,
    PRIMARY KEY (instance, id),
    FOREIGN KEY (instance, alert_id) REFERENCES openpicket.alerts (instance, id) ON DELETE CASCADE
);
CREATE INDEX alert_decisions_alert ON openpicket.alert_decisions (instance, alert_id);
CREATE INDEX alert_decisions_value ON openpicket.alert_decisions (value);
CREATE INDEX alert_decisions_until ON openpicket.alert_decisions (until DESC);

CREATE TABLE openpicket.alert_sync (
    instance     text PRIMARY KEY,
    url          text NOT NULL,
    last_poll_at timestamptz,
    last_full_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    error_at     timestamptz
);
