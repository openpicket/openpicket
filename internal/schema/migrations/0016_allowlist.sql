-- Central allowlist (docs/ARCHITECTURE.md §4.7): networks CrowdSec
-- decisions never block at the edge, whatever their origin. The relay
-- leaves decisions overlapping an active entry out of the edge view; the
-- API and MISP refuse to add them.
CREATE TABLE openpicket.allowlist (
    network     cidr PRIMARY KEY,
    description text NOT NULL DEFAULT '',
    -- NULL: never expires.
    expires_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL DEFAULT ''
);
CREATE INDEX allowlist_network ON openpicket.allowlist USING gist (network inet_ops);

-- The openpicket allowlist of each LAPI follows the entries
-- (openpicket-crowdsec-sync applies them with cscli): last push per
-- instance.
CREATE TABLE openpicket.allowlist_lapi_sync (
    instance   text PRIMARY KEY,
    attempt_at timestamptz NOT NULL,
    -- Last push the LAPI applied.
    synced_at  timestamptz,
    -- Last push that changed something.
    changed_at timestamptz,
    items      int NOT NULL DEFAULT 0,
    error      text NOT NULL DEFAULT ''
);
