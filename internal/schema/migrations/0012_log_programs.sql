-- Programs of the generic logs each node sends (docs/ARCHITECTURE.md §4.8):
-- the UI shows them with the parsers that handle them. Counts are added by
-- the replicas every 30 seconds; rows not seen for 30 days are removed.
CREATE TABLE openpicket.log_programs (
    node_id    text NOT NULL,
    program    text NOT NULL,
    lines      bigint NOT NULL DEFAULT 0,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, program)
);
