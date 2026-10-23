#!/usr/bin/env bash
# Runs the OpenPicket CrowdSec image without network access, pushes it the
# built-in content as openpicket-manager does, feeds it the records the
# manager would send, and checks alerts and decisions (docs/ARCHITECTURE.md
# §8: "offline" means this test passes). Then changes item states
# (disabled, simulation) and pushes a bundle CrowdSec must refuse.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${1:-openpicket-crowdsec:dev}"
name="openpicket-cs-test-$$"
docker run -d --rm --name "$name" --network none -e OPENPICKET_ACQUIS_TOKEN=test-token "$IMAGE" >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
ex() { docker exec "$name" "$@"; }

fail=0
check() { if [ "$(echo "$2" | jq -r "$3")" != "$4" ]; then echo "FAIL: $1 (got $(echo "$2" | jq -c "$3"), want $4)"; fail=1; else echo "ok   $1"; fi; }
status() { ex wget -q -O - --header "X-OpenPicket-Token: test-token" http://127.0.0.1:8082/hub/status; }
for _ in $(seq 1 30); do status >/dev/null 2>&1 && break; sleep 1; done
# No content: CrowdSec waits, its datasource is closed.
check "no content: not running" "$(status)" ".running" "false"
if ex wget -q -O /dev/null http://127.0.0.1:8081/openpicket 2>/dev/null; then echo "FAIL: datasource open without content"; fail=1; fi
bundle="$(mktemp)"
trap 'docker rm -f "$name" >/dev/null 2>&1; rm -f "$bundle"' EXIT
go run ./cmd/openpicket-manager hub-bundle > "$bundle"
push() { docker exec -i -e OPENPICKET_ACQUIS_TOKEN=test-token "$name" openpicket-crowdsec-sync put; }
push < "$bundle" >/dev/null || { docker logs "$name" | tail -40; echo "FAIL: content refused"; exit 1; }
for _ in $(seq 1 90); do
  if ex sh -c 'cscli lapi status >/dev/null 2>&1 && wget -q -O /dev/null --header "X-OpenPicket-Token: test-token" http://127.0.0.1:8081/openpicket' 2>/dev/null; then break; fi
  sleep 1
done
ex cscli lapi status >/dev/null || { docker logs "$name" | tail -40; echo "FAIL: crowdsec did not start"; exit 1; }
check "content applied" "$(status)" ".revision" "1"

now="$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"
meta() { echo "\"openpicket_meta\":{\"ts\":\"$now\",\"node_id\":\"$1\",\"site\":\"seoul\",\"remote_geo\":{\"cc\":\"$2\",\"asn\":4134,\"as_org\":\"TEST-AS\"}}"; }
records="$(mktemp)"
{
  # Inbound severity 1 exploit attempt -> ban 198.51.100.4 (inbound).
  echo "{\"timestamp\":\"2026-10-20T10:59:01.000000+0900\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.4\",\"src_port\":40000,\"dest_ip\":\"192.168.1.50\",\"dest_port\":443,\"proto\":\"TCP\",\"direction\":\"to_server\",\"alert\":{\"signature_id\":2000001,\"rev\":1,\"signature\":\"ET EXPLOIT test\",\"category\":\"Attempted Administrator Privilege Gain\",\"severity\":1},\"openpicket\":{\"rid\":\"r1\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"198.51.100.4\",\"local_ip\":\"192.168.1.50\"},$(meta edge-01 CN)}"
  # Reply of a C2 server to an inside host -> ban the server (24h), alert on the host.
  echo "{\"timestamp\":\"2026-10-20T10:59:02.000000+0900\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.9\",\"src_port\":443,\"dest_ip\":\"203.0.113.10\",\"dest_port\":40123,\"proto\":\"TCP\",\"direction\":\"to_client\",\"flow\":{\"src_ip\":\"203.0.113.10\",\"dest_ip\":\"198.51.100.9\"},\"alert\":{\"signature_id\":2000002,\"rev\":1,\"signature\":\"ET MALWARE test C2\",\"category\":\"A Network Trojan was detected\",\"severity\":1},\"openpicket\":{\"rid\":\"r2\",\"direction\":\"outbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"198.51.100.9\",\"local_ip\":\"192.168.1.60\",\"nat\":{\"type\":\"snat\",\"public_ip\":\"203.0.113.10\",\"public_port\":40123,\"local_port\":51000}},$(meta edge-01 RU)}"
  # Lateral movement: never a decision.
  echo "{\"timestamp\":\"2026-10-20T10:59:03.000000+0900\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.70\",\"dest_ip\":\"192.168.1.71\",\"dest_port\":445,\"proto\":\"TCP\",\"alert\":{\"signature_id\":2000003,\"signature\":\"ET EXPLOIT lateral\",\"category\":\"Attempted Administrator Privilege Gain\",\"severity\":1},\"openpicket\":{\"rid\":\"r3\",\"direction\":\"internal\",\"direction_confidence\":\"high\"},$(meta edge-01 '')}"
  # Refused WAN connections: 10 distinct closed ports -> ban 198.51.100.77.
  for p in 21 22 23 25 80 110 135 139 445 3389; do
    echo "{\"timestamp\":\"2026-10-20T10:59:04.000000+0900\",\"event_type\":\"nflog\",\"prefix\":\"WAN-REJECT\",\"group\":100,\"in_iface\":\"wan\",\"ip_version\":4,\"proto\":\"TCP\",\"src_ip\":\"198.51.100.77\",\"src_port\":40000,\"dest_ip\":\"203.0.113.10\",\"dest_port\":$p,\"tcp_flags\":\"S\",\"ttl\":50,\"pkt_len\":60,\"openpicket\":{\"rid\":\"n$p\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"198.51.100.77\",\"local_ip\":\"203.0.113.10\"},$(meta edge-02 US)}"
  done
} > "$records"
docker cp "$records" "$name:/tmp/records.ndjson" >/dev/null
rm -f "$records"
ex wget -q -O /dev/null --header "X-OpenPicket-Token: test-token" --header "Content-Type: application/x-ndjson" --post-file /tmp/records.ndjson http://127.0.0.1:8081/openpicket
# A wrong token must be refused.
if ex wget -q -O /dev/null --header "X-OpenPicket-Token: wrong" --post-data '{}' http://127.0.0.1:8081/openpicket 2>/dev/null; then
  echo "FAIL: datasource accepted a wrong token"; exit 1
fi

decisions='[]'
for _ in $(seq 1 30); do
  decisions="$(ex cscli decisions list -o json 2>/dev/null || echo '[]')"
  [ "$(echo "$decisions" | jq '[.[]?.decisions[]?] | length')" -ge 3 ] && break
  sleep 1
done
alerts="$(ex cscli alerts list -o json -l 0)"
d='[.[]?.decisions[]?]'
check "inbound attacker banned 4h" "$decisions" "$d | map(select(.value==\"198.51.100.4\")) | .[0].scenario" "openpicket/suricata-inbound-major"
check "C2 server banned 24h" "$decisions" "$d | map(select(.value==\"198.51.100.9\")) | .[0].duration | test(\"^2[34]h\")" "true"
check "C2 decision scenario" "$decisions" "$d | map(select(.value==\"198.51.100.9\")) | .[0].scenario" "openpicket/suricata-outbound-c2"
check "port scanner banned" "$decisions" "$d | map(select(.value==\"198.51.100.77\")) | .[0].scenario" "openpicket/wan-reject-portscan"
check "no decision on inside hosts" "$decisions" "$d | map(select(.value | startswith(\"192.168.\"))) | length" "0"
check "compromised host alerted" "$alerts" "map(select(.scenario==\"openpicket/compromised-host\")) | .[0].source.value" "192.168.1.60"
check "compromised host scope" "$alerts" "map(select(.scenario==\"openpicket/compromised-host\")) | .[0].source.scope" "openpicket_host"
# The C2 alert was captured on the WAN, after SNAT: the inside host comes
# from the agent's NAT lookup.
check "alert context has dst_ip" "$alerts" "map(select(.scenario==\"openpicket/suricata-outbound-c2\")) | .[0].meta | map(select(.key==\"dst_ip\")) | .[0].value" '["203.0.113.10"]'
check "alert context has the inside host" "$alerts" "map(select(.scenario==\"openpicket/suricata-outbound-c2\")) | .[0].meta | map(select(.key==\"local_ip\")) | .[0].value" '["192.168.1.60"]'
check "alert context has the NAT" "$alerts" "map(select(.scenario==\"openpicket/suricata-outbound-c2\")) | .[0].meta | map(select(.key==\"public_port\" or .key==\"nat_type\")) | map(.value) | sort | join(\",\")" '["40123"],["snat"]'
check "alert context has node_id" "$alerts" "map(select(.scenario==\"openpicket/wan-reject-portscan\")) | .[0].meta | map(select(.key==\"node_id\")) | .[0].value" '["edge-02"]'
check "remote geo on alert source" "$alerts" "map(select(.scenario==\"openpicket/suricata-outbound-c2\")) | .[0].source.cn" "RU"
check "no alert from lateral traffic" "$alerts" "map(select(.source.value==\"192.168.1.70\")) | length" "0"

# Revision 2: the sensitive-port scenario disabled, the inbound major one
# in simulation (alert, no decision). CrowdSec reloads.
jq '.revision = 2
  | .items |= map(select(.path != "scenarios/openpicket-wan-reject-sensitive-port.yaml"))
  | .simulation = ["openpicket/suricata-inbound-major"]' "$bundle" | push >/dev/null || { echo "FAIL: revision 2 refused"; fail=1; }
check "revision 2 applied" "$(status)" ".revision" "2"
{
  echo "{\"timestamp\":\"2026-10-20T11:00:01.000000+0900\",\"event_type\":\"alert\",\"src_ip\":\"198.51.100.5\",\"src_port\":40000,\"dest_ip\":\"192.168.1.50\",\"dest_port\":443,\"proto\":\"TCP\",\"direction\":\"to_server\",\"alert\":{\"signature_id\":2000001,\"rev\":1,\"signature\":\"ET EXPLOIT test\",\"category\":\"Attempted Administrator Privilege Gain\",\"severity\":1},\"openpicket\":{\"rid\":\"s1\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"198.51.100.5\",\"local_ip\":\"192.168.1.50\"},$(meta edge-01 CN)}"
  for i in 1 2 3; do
    echo "{\"timestamp\":\"2026-10-20T11:00:02.000000+0900\",\"event_type\":\"nflog\",\"prefix\":\"WAN-REJECT\",\"group\":100,\"in_iface\":\"wan\",\"ip_version\":4,\"proto\":\"TCP\",\"src_ip\":\"198.51.100.88\",\"src_port\":4000$i,\"dest_ip\":\"203.0.113.10\",\"dest_port\":22,\"tcp_flags\":\"S\",\"ttl\":50,\"pkt_len\":60,\"openpicket\":{\"rid\":\"t$i\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"198.51.100.88\",\"local_ip\":\"203.0.113.10\"},$(meta edge-02 US)}"
  done
} > "$bundle.rec"
docker cp "$bundle.rec" "$name:/tmp/records2.ndjson" >/dev/null
rm -f "$bundle.rec"
ex wget -q -O /dev/null --header "X-OpenPicket-Token: test-token" --header "Content-Type: application/x-ndjson" --post-file /tmp/records2.ndjson http://127.0.0.1:8081/openpicket
alerts2='[]'
for _ in $(seq 1 30); do
  alerts2="$(ex cscli alerts list -o json -l 0 --origin '' 2>/dev/null || echo '[]')"
  [ "$(echo "$alerts2" | jq '[.[] | select(.source.value=="198.51.100.5")] | length')" -ge 1 ] && break
  sleep 1
done
decisions="$(ex cscli decisions list -o json 2>/dev/null || echo '[]')"
check "simulation: alert raised" "$alerts2" "[.[] | select(.source.value==\"198.51.100.5\")] | .[0].simulated" "true"
check "simulation: decision marked simulated" "$decisions" "$d | map(select(.value==\"198.51.100.5\")) | .[0].simulated" "true"
# What the relay reads: the bouncer stream leaves simulated decisions out.
ex cscli bouncers add sim-check -k sim-check-key >/dev/null
stream="$(ex wget -q -O - --header "X-Api-Key: sim-check-key" 'http://127.0.0.1:8080/v1/decisions/stream?startup=true&scopes=ip,range')"
check "simulation: not in the bouncer stream" "$stream" "[.new[]? | select(.value==\"198.51.100.5\")] | length" "0"
check "bouncer stream has the real bans" "$stream" "[.new[]? | select(.value==\"198.51.100.4\")] | length" "1"
check "disabled scenario: no alert" "$alerts2" "[.[] | select(.source.value==\"198.51.100.88\")] | length" "0"

# A bundle CrowdSec refuses (crowdsec -t) leaves revision 2 running.
jq '.revision = 3 | .items += [{"path": "scenarios/u-bad.yaml", "content": ("type: leaky\nname: u/bad\nfilter: \"evt.Meta.x ==\"\ngroupby: evt.Meta.source_ip\ncapacity: 1\nleakspeed: 1s\n" | @base64)}]' "$bundle" | push >/dev/null 2>&1 && { echo "FAIL: a broken bundle was accepted"; fail=1; }
st="$(status)"
check "broken bundle: revision kept" "$st" ".revision" "2"
check "broken bundle: error reported" "$st" ".error_revision" "3"
check "broken bundle: crowdsec runs" "$st" ".running" "true"

if [ "$fail" != 0 ]; then
  echo "--- alerts"; echo "$alerts" | jq -c '.[] | {scenario, source, meta}'
  docker logs "$name" 2>&1 | grep -iE 'error|warn' | tail -20
  exit 1
fi
echo "PASS"
