-- CrowdSec content (docs/ARCHITECTURE.md §8): parsers, scenarios,
-- collections... kept here and pushed to the log processors, whose image
-- carries none. Built-in items are written by the manager at start
-- (hub.Builtin), hub and custom items through the API.
CREATE TABLE openpicket.hub_items (
    type        text NOT NULL,
    name        text NOT NULL,
    -- builtin | hub | custom
    source      text NOT NULL,
    version     text NOT NULL DEFAULT '',
    -- parsers and postoverflows: s00-raw, s01-parse...
    stage       text NOT NULL DEFAULT '',
    -- The item file; empty for collections.
    content     bytea NOT NULL DEFAULT ''::bytea,
    -- sha256 of content.
    digest      text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    -- Collections: their members as [{"type":..., "name":...}].
    members     jsonb NOT NULL DEFAULT '[]',
    -- Data files the item reads (hub_data dest files).
    data        jsonb NOT NULL DEFAULT '[]',
    -- Installed on its own, not only as a collection member.
    explicit    boolean NOT NULL DEFAULT true,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT '',
    PRIMARY KEY (type, name)
);

-- The state of an item, apart from its content: an upgrade of a built-in
-- item keeps what the user chose.
CREATE TABLE openpicket.hub_item_state (
    type       text NOT NULL,
    name       text NOT NULL,
    -- enabled | simulation (scenarios) | disabled
    state      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL DEFAULT '',
    PRIMARY KEY (type, name)
);

CREATE TABLE openpicket.hub_data (
    dest_file  text PRIMARY KEY,
    source_url text NOT NULL DEFAULT '',
    content    bytea NOT NULL,
    digest     text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Every change takes the next revision; the log processors run one.
CREATE SEQUENCE openpicket.hub_revision;
CREATE TABLE openpicket.hub_meta (
    id               int PRIMARY KEY CHECK (id = 1),
    -- hub.BuiltinRevision of the built-in items stored.
    builtin_revision int NOT NULL DEFAULT 0,
    -- Content revision (hub_revision).
    revision         bigint NOT NULL DEFAULT 0,
    -- Last revision a log processor accepted, and its bundle (gzip JSON):
    -- pushed to the others while a newer revision is refused.
    good_revision    bigint NOT NULL DEFAULT 0,
    good_bundle      bytea,
    -- A revision a log processor refused (crowdsec -t), and why.
    failed_revision  bigint NOT NULL DEFAULT 0,
    failed_error     text NOT NULL DEFAULT '',
    -- The CrowdSec hub index (hub update).
    hub_index        bytea,
    hub_index_etag   text NOT NULL DEFAULT '',
    hub_index_at     timestamptz
);
INSERT INTO openpicket.hub_meta (id) VALUES (1);

-- What each log processor runs (written by the rollout leader).
CREATE TABLE openpicket.hub_lp_state (
    endpoint   text PRIMARY KEY,
    revision   bigint NOT NULL DEFAULT 0,
    running    boolean NOT NULL DEFAULT false,
    error      text NOT NULL DEFAULT '',
    seen_at    timestamptz NOT NULL DEFAULT now()
);
