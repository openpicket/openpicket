-- Port policies and the MaxMind databases they use (§4.4, §5.6).

-- Uploaded MaxMind databases (one per kind). The data is the single geo
-- source for enrichment, policies and the UI.
CREATE TABLE openpicket.geo_databases (
    kind          text PRIMARY KEY CHECK (kind IN ('country', 'asn')),
    database_type text NOT NULL,
    build_epoch   bigint NOT NULL,
    sha256        text NOT NULL,
    data          bytea NOT NULL,
    uploaded_at   timestamptz NOT NULL,
    uploaded_by   text NOT NULL
);

-- Named address lists (CIDRs and/or AS numbers).
CREATE TABLE openpicket.ip_lists (
    name        text PRIMARY KEY,
    description text NOT NULL DEFAULT '',
    spec        jsonb NOT NULL,
    updated_at  timestamptz NOT NULL,
    updated_by  text NOT NULL
);

-- Port policies, applied in position order.
CREATE TABLE openpicket.port_policies (
    id         text PRIMARY KEY,
    position   int NOT NULL,
    spec       jsonb NOT NULL,
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL
);

CREATE TABLE openpicket.policy_history (
    id         bigserial PRIMARY KEY,
    policy_id  text NOT NULL,
    version    bigint NOT NULL,
    action     text NOT NULL,
    spec       jsonb,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL
);
CREATE INDEX policy_history_policy ON openpicket.policy_history (policy_id, id);

-- Generation of everything bundles depend on (policies, lists, geo data).
CREATE TABLE openpicket.policy_meta (
    id      int PRIMARY KEY CHECK (id = 1),
    version bigint NOT NULL
);
INSERT INTO openpicket.policy_meta (id, version) VALUES (1, 0);

CREATE TABLE openpicket.node_policy_state (
    node_id  text PRIMARY KEY REFERENCES openpicket.nodes(id) ON DELETE CASCADE,
    version  bigint NOT NULL,
    error    text NOT NULL DEFAULT '',
    skipped  jsonb NOT NULL DEFAULT '[]',
    acked_at timestamptz NOT NULL
);
