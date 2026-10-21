-- Last good compilation of each port policy (docs/ARCHITECTURE.md §4.4).
-- A policy that stops compiling (GeoIP database deleted or not loaded)
-- keeps its last good version on the nodes instead of disappearing, which
-- would open the ports it protects.
CREATE TABLE openpicket.policy_compiled (
    policy_id   text PRIMARY KEY,
    -- Policy generation the row was written at: an older replica never
    -- overwrites a newer result.
    version     bigint NOT NULL,
    -- dataplane.v1.PolicyBundle holding the policy and its sets; NULL when
    -- the policy never compiled.
    compiled    bytea,
    compiled_at timestamptz,
    -- Why the current version does not compile ('' when it does).
    last_error  text NOT NULL DEFAULT '',
    error_at    timestamptz
);
