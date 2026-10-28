-- Periodic download of the MaxMind databases (docs/ARCHITECTURE.md §5.6):
-- the settings edited in the UI and the state of the last checks. The
-- downloaded files are stored like uploads (geo_databases).
CREATE TABLE openpicket.geo_update (
    id                int PRIMARY KEY CHECK (id = 1),
    enabled           boolean NOT NULL DEFAULT false,
    -- Never returned by the API.
    license_key       text NOT NULL DEFAULT '',
    -- MaxMind edition ids; '' skips the kind.
    country_edition   text NOT NULL DEFAULT 'GeoLite2-Country',
    asn_edition       text NOT NULL DEFAULT 'GeoLite2-ASN',
    interval_hours    int NOT NULL DEFAULT 24 CHECK (interval_hours BETWEEN 1 AND 720),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    updated_by        text NOT NULL DEFAULT '',
    last_check_at     timestamptz,
    -- Last check that stored a new database.
    last_download_at  timestamptz,
    last_error        text NOT NULL DEFAULT '',
    error_at          timestamptz,
    -- edition -> {"file": "GeoLite2-Country_20261027.tar.gz", "sha256": mmdb sha256}
    editions          jsonb NOT NULL DEFAULT '{}'
);
INSERT INTO openpicket.geo_update (id) VALUES (1);
