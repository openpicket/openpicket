#!/bin/bash
# Entrypoint of the OpenPicket CrowdSec image: registers the
# openpicket-manager watcher machine on LAPI containers, then runs the
# stock entrypoint. The agents' machine (AGENT_USERNAME) and the relay
# bouncer (BOUNCER_KEY_<name>) use the stock variables.
set -euo pipefail
secret() { # VAR or VAR_FILE
	local v="${!1:-}" f="${1}_FILE"
	if [ -z "$v" ] && [ -n "${!f:-}" ]; then v="$(cat "${!f}")"; fi
	printf '%s' "$v"
}
for v in OPENPICKET_ACQUIS_TOKEN AGENT_PASSWORD; do
	val="$(secret "$v")"
	[ -n "$val" ] && export "$v=$val"
done
for b in $(compgen -A variable | grep -E '^BOUNCER_KEY_.*_FILE$' || true); do
	export "${b%_FILE}=$(cat "${!b}")"
	# The stock entrypoint registers every BOUNCER_KEY* variable.
	unset "$b"
done
if [ "${DISABLE_LOCAL_API:-false}" != "true" ]; then
	login="${OPENPICKET_WATCHER_LOGIN:-}"
	password="$(secret OPENPICKET_WATCHER_PASSWORD)"
	if [ -n "$login" ] && [ -n "$password" ]; then
		# Re-registered on every start: the password may have changed.
		for _ in $(seq 1 30); do
			if cscli machines add "$login" --password "$password" -f /dev/null --force >/dev/null 2>&1; then
				echo "registered watcher machine $login"
				break
			fi
			echo "waiting for the database to register $login"
			sleep 2
		done
	fi
fi
exec /bin/bash /docker_start.sh "$@"
