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
