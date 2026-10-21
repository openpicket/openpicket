-- Recent searches and notifications (docs/ARCHITECTURE.md §5.7).

CREATE TABLE openpicket.recent_queries (
    owner   text NOT NULL,
    page    text NOT NULL,
    query   text NOT NULL,
    used_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner, page, query)
);

CREATE TABLE openpicket.notify_destinations (
    id         text PRIMARY KEY,
    name       text NOT NULL,
    type       text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    config     jsonb NOT NULL DEFAULT '{}',
    -- Never returned by the API.
    secrets    jsonb NOT NULL DEFAULT '{}',
    severities text[] NOT NULL DEFAULT '{}',
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);

CREATE TABLE openpicket.notify_rules (
    id         text PRIMARY KEY,
    name       text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    spec       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT ''
);

-- Evaluation state per rule: watermarks (last alert/decision id per
-- instance), last firing per subject.
CREATE TABLE openpicket.notify_state (
    rule_id  text NOT NULL REFERENCES openpicket.notify_rules(id) ON DELETE CASCADE,
    key      text NOT NULL,
    value    jsonb NOT NULL,
    PRIMARY KEY (rule_id, key)
);

CREATE TABLE openpicket.notifications (
    id        bigserial PRIMARY KEY,
    time      timestamptz NOT NULL DEFAULT now(),
    rule_id   text NOT NULL,
    rule_name text NOT NULL,
    severity  text NOT NULL,
    title     text NOT NULL,
    body      text NOT NULL,
    subject   text NOT NULL DEFAULT '',
    link      text NOT NULL DEFAULT '',
    -- Users who read it.
    read_by   text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX notifications_time ON openpicket.notifications (time DESC);

CREATE TABLE openpicket.notify_deliveries (
    notification_id bigint NOT NULL REFERENCES openpicket.notifications(id) ON DELETE CASCADE,
    destination_id  text NOT NULL,
    status          text NOT NULL DEFAULT 'pending',
    attempts        int NOT NULL DEFAULT 0,
    error           text NOT NULL DEFAULT '',
    next_at         timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (notification_id, destination_id)
);
CREATE INDEX notify_deliveries_pending ON openpicket.notify_deliveries (next_at) WHERE status = 'pending';
