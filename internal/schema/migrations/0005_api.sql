-- Management API state (docs/ARCHITECTURE.md §5.7).

-- Latest Hello and Status of each session (protobuf), so every replica can
-- show nodes connected to another one.
ALTER TABLE openpicket.node_sessions
    ADD COLUMN hello     bytea,
    ADD COLUMN status    bytea,
    ADD COLUMN status_at timestamptz;

-- Search filters saved per user, optionally shared.
CREATE TABLE openpicket.saved_filters (
    id         text PRIMARY KEY,
    owner      text NOT NULL,
    page       text NOT NULL,
    name       text NOT NULL,
    query      text NOT NULL,
    state      jsonb NOT NULL DEFAULT '{}',
    shared     boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX saved_filters_page ON openpicket.saved_filters (page, owner);

CREATE INDEX audit_principal ON openpicket.audit (principal, time DESC);
