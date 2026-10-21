-- Decision distribution (docs/ARCHITECTURE.md §4.3).

-- Copy of the primary LAPI's active decisions, written by the relay leader.
-- eligible/both are computed by the relay from the edge filter and the
-- direction rules when the row is written.
CREATE TABLE openpicket.lapi_decisions (
    id          bigint PRIMARY KEY,
    value       text NOT NULL,
    scope       text NOT NULL,
    type        text NOT NULL,
    origin      text NOT NULL,
    scenario    text NOT NULL,
    until       timestamptz NOT NULL,
    eligible    boolean NOT NULL,
    both_ways   boolean NOT NULL,
    received_at timestamptz NOT NULL
);
CREATE INDEX lapi_decisions_value ON openpicket.lapi_decisions (value);

-- The edge view: one row per blocked value (longest until, BOTH wins).
-- Every change takes the next version; deletions stay as tombstones until
-- pruned, so a node can catch up with a delta.
CREATE SEQUENCE openpicket.edge_version;
CREATE TABLE openpicket.edge_decisions (
    value      text PRIMARY KEY,
    scope      text NOT NULL,
    direction  text NOT NULL,
    until      timestamptz NOT NULL,
    origin     text NOT NULL,
    scenario   text NOT NULL,
    version    bigint NOT NULL,
    deleted    boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX edge_decisions_version ON openpicket.edge_decisions (version);

-- horizon: tombstones up to this version may have been pruned, so a node
-- below it needs a snapshot.
CREATE TABLE openpicket.edge_meta (
    id      int PRIMARY KEY CHECK (id = 1),
    horizon bigint NOT NULL DEFAULT 0
);
INSERT INTO openpicket.edge_meta (id) VALUES (1);

-- What each node acknowledged.
CREATE TABLE openpicket.node_decision_state (
    node_id  text PRIMARY KEY REFERENCES openpicket.nodes(id) ON DELETE CASCADE,
    version  bigint NOT NULL,
    set_size int NOT NULL,
    error    text NOT NULL DEFAULT '',
    acked_at timestamptz NOT NULL
);
