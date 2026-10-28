-- Gateway replicas (docs/ARCHITECTURE.md §5.10): the agents' endpoint runs
-- apart from the UI/API. Each gateway replica records the channel B host
-- key the API shows (Nodes > Connection info) and whether its database
-- account is restricted to what a gateway needs.
CREATE TABLE openpicket.gateway_info (
    replica       text PRIMARY KEY,
    host_key      text NOT NULL,
    db_user       text NOT NULL,
    db_restricted boolean NOT NULL,
    version       text NOT NULL DEFAULT '',
    -- Log sinks whose deliveries fail on the replica (loki, crowdsec).
    sinks_down    text[] NOT NULL DEFAULT '{}',
    sessions      integer NOT NULL DEFAULT 0,
    seen_at       timestamptz NOT NULL DEFAULT now()
);
