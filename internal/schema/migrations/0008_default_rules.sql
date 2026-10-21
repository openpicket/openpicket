-- Default rules: they fill the in-app notification center; destinations
-- are added by the administrator.
INSERT INTO openpicket.notify_rules (id, name, enabled, spec, updated_by) VALUES
    ('compromised-hosts', 'Compromised hosts', true,
     '{"id":"compromised-hosts","name":"Compromised hosts","type":"compromised_host","severity":"critical","cooldown_seconds":3600}', 'openpicket'),
    ('lapi-down', 'CrowdSec LAPI unavailable', true,
     '{"id":"lapi-down","name":"CrowdSec LAPI unavailable","type":"lapi_down","severity":"critical","cooldown_seconds":3600}', 'openpicket'),
    ('nodes-offline', 'Nodes offline', true,
     '{"id":"nodes-offline","name":"Nodes offline","type":"node_offline","severity":"warning","window_seconds":300,"cooldown_seconds":600}', 'openpicket'),
    ('apply-errors', 'Nodes failing to apply', true,
     '{"id":"apply-errors","name":"Nodes failing to apply","type":"policy_error","severity":"warning","cooldown_seconds":3600}', 'openpicket'),
    ('sinks-down', 'Log delivery failing', true,
     '{"id":"sinks-down","name":"Log delivery failing","type":"sink_down","severity":"critical","cooldown_seconds":1800}', 'openpicket');
