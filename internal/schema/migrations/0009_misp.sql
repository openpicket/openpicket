-- Cache of the MISP attributes OpenPicket manages (docs/ARCHITECTURE.md
-- §5.5). The approval state lives in MISP (openpicket:* tags); this copy
-- serves the approval queue and the decision reconciler.

CREATE TABLE openpicket.misp_iocs (
    uuid              text PRIMARY KEY,
    attribute_id      text NOT NULL,
    event_id          text NOT NULL,
    event_info        text NOT NULL DEFAULT '',
    type              text NOT NULL,
    value             text NOT NULL,
    to_ids            boolean NOT NULL,
    -- proposed | approved | rejected | revoked (openpicket:state tag)
    state             text NOT NULL,
    ttl               text NOT NULL DEFAULT '',
    comment           text NOT NULL DEFAULT '',
    tags              text[] NOT NULL DEFAULT '{}',
    modified_at       timestamptz,
    -- First time the copy saw the attribute approved: the TTL counts from
    -- there.
    approved_at       timestamptz,
    synced_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX misp_iocs_state ON openpicket.misp_iocs (state);
CREATE INDEX misp_iocs_value ON openpicket.misp_iocs (value);

CREATE TABLE openpicket.misp_sync (
    id           int PRIMARY KEY CHECK (id = 1),
    last_sync_at timestamptz,
    last_error   text NOT NULL DEFAULT '',
    error_at     timestamptz,
    active       int NOT NULL DEFAULT 0
);
INSERT INTO openpicket.misp_sync (id) VALUES (1);
