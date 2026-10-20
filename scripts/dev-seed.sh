#!/usr/bin/env bash
# Feeds sample records (the agent's format) to the dev CrowdSec datasource:
# inbound exploits and port scans (inbound bans), C2 conversations of inside
# hosts over TCP and UDP (two-way bans of the servers), and adds a manual
# two-way ban with cscli when the dev compose stack is running.
set -euo pipefail
cd "$(dirname "$0")/.."
URL="${ACQUIS_URL:-http://127.0.0.1:18081/openpicket}"
now="$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"
meta() { echo "\"openpicket_meta\":{\"ts\":\"$now\",\"node_id\":\"$1\",\"site\":\"$2\",\"remote_geo\":{\"cc\":\"$3\",\"asn\":$4,\"as_org\":\"$5\"}}"; }
{
  i=0
  for src in "198.51.100.4 CN 4134 CHINANET" "203.0.113.50 RU 12389 ROSTELECOM" "192.0.2.77 US 14061 DIGITALOCEAN"; do
    set -- $src
    i=$((i + 1))
    echo "{\"timestamp\":\"$now\",\"event_type\":\"alert\",\"src_ip\":\"$1\",\"src_port\":40000,\"dest_ip\":\"192.168.1.50\",\"dest_port\":443,\"proto\":\"TCP\",\"direction\":\"to_server\",\"alert\":{\"signature_id\":200000$i,\"rev\":1,\"signature\":\"ET EXPLOIT sample $i\",\"category\":\"Attempted Administrator Privilege Gain\",\"severity\":1},\"openpicket\":{\"rid\":\"s$i\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"$1\",\"local_ip\":\"192.168.1.50\"},$(meta edge-01 seoul "$2" "$3" "$4")}"
  done
  # Outbound: inside hosts reach C2 / malware servers. Suricata reports the
  # server's reply (to_client); flow.src_ip is the inside host.
  sid=2000100
  c2() { # server inside_host proto category severity rid signature cc asn as_org
    sid=$((sid + 1))
    echo "{\"timestamp\":\"$now\",\"event_type\":\"alert\",\"src_ip\":\"$1\",\"src_port\":443,\"dest_ip\":\"$2\",\"dest_port\":51000,\"proto\":\"$3\",\"direction\":\"to_client\",\"flow\":{\"src_ip\":\"$2\",\"dest_ip\":\"$1\"},\"alert\":{\"signature_id\":$sid,\"rev\":1,\"signature\":\"$7\",\"category\":\"$4\",\"severity\":$5},\"openpicket\":{\"rid\":\"$6\",\"direction\":\"outbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"$1\",\"local_ip\":\"$2\"},$(meta edge-01 seoul "$8" "$9" "${10}")}"
  }
  c2 198.51.100.9 192.168.1.60 TCP "A Network Trojan was detected" 1 c2-1 "ET MALWARE sample C2" NL 60781 LEASEWEB
  c2 203.0.113.140 192.168.1.61 TCP "Malware Command and Control Activity Detected" 2 c2-2 "ET MALWARE CobaltStrike beacon" US 16509 AMAZON-02
  c2 192.0.2.201 192.168.1.62 TCP "Crypto Currency Mining Activity Detected" 2 c2-3 "ET COINMINER stratum login" SG 45102 ALIBABA
  # UDP beacons trigger after 3 events.
  for n in 1 2 3; do
    c2 198.51.100.66 192.168.1.63 UDP "Domain Observed Used for C2 Detected" 2 "c2-udp-$n" "ET MALWARE UDP beacon" RU 197695 REG-RU
  done
  for src in "203.0.113.77 KR 4766 KORNET" "192.0.2.150 BR 28573 CLARO" "198.51.100.200 DE 24940 HETZNER"; do
    set -- $src
    for p in 21 22 23 25 80 110 135 139 445 3389; do
      echo "{\"timestamp\":\"$now\",\"event_type\":\"nflog\",\"prefix\":\"DNAT-MISS\",\"group\":100,\"in_iface\":\"wan\",\"ip_version\":4,\"proto\":\"TCP\",\"src_ip\":\"$1\",\"src_port\":40000,\"dest_ip\":\"203.0.113.10\",\"dest_port\":$p,\"tcp_flags\":\"S\",\"ttl\":50,\"pkt_len\":60,\"openpicket\":{\"rid\":\"n$1$p\",\"direction\":\"inbound\",\"direction_confidence\":\"high\",\"remote_ip\":\"$1\",\"local_ip\":\"203.0.113.10\"},$(meta edge-02 busan "$2" "$3" "$4")}"
    done
  done
} | curl -fsS -o /dev/null -H "X-OpenPicket-Token: dev-token" -H "Content-Type: application/x-ndjson" --data-binary @- "$URL"
echo "seeded records"

# A manual two-way ban, as operators add for phishing or C2 hosts.
compose=(docker compose -f deploy/dev/docker-compose.yml)
if "${compose[@]}" ps -q crowdsec 2>/dev/null | grep -q .; then
  "${compose[@]}" exec -T crowdsec cscli decisions add --ip 203.0.113.250 --duration 24h --reason openpicket/manual-both >/dev/null
  echo "added a manual two-way ban (203.0.113.250)"
fi
