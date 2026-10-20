#!/bin/sh
# Seeds empty volumes with defaults, then runs openpicket-agent.
set -e
if [ ! -f /etc/suricata/suricata.yaml ]; then
	cp -a /usr/share/openpicket-agent/suricata/. /etc/suricata/
fi
mkdir -p /etc/suricata/rules.local
config="${OPENPICKET_AGENT_CONFIG:-/etc/suri-agent/agent.yaml}"
if [ "$1" = "run" ] && [ ! -f "$config" ]; then
	cp /usr/share/openpicket-agent/agent.yaml.example /etc/suri-agent/agent.yaml.example
	echo "error: $config not found; see /etc/suri-agent/agent.yaml.example" >&2
	exit 1
fi
exec /usr/bin/openpicket-agent "$@"
