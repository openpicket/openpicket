# Installing openpicket-agent on a server

On a server, openpicket-agent runs without Suricata: it ships the server's logs (nginx, PostgreSQL, sshd...) to openpicket-manager. CrowdSec reads them there with the parsers and scenarios of the **CrowdSec content** page, and its bans reach the OpenPicket routers like any other decision.

## Requirements

- Linux with systemd, x86_64 or arm64.
- The server can reach the manager's public URL (`wss://.../agent/data/v1/connect`). The agent only opens outbound connections.

## 1. Binary

Download `openpicket-agent_<version>_linux_<arch>.tar.gz` from the release and install the binary:

```sh
tar xzf openpicket-agent_*_linux_amd64.tar.gz
install -m 0755 openpicket-agent_*/openpicket-agent /usr/local/bin/openpicket-agent
```

## 2. Configuration and key

```sh
install -d -m 0750 /etc/openpicket-agent
cp agent-server.yaml.example /etc/openpicket-agent/agent.yaml
# edit node_id, url, host_key and log_sources
openpicket-agent keygen -config /etc/openpicket-agent/agent.yaml
```

`keygen` prints the public key line. Register it under **Nodes > Register node** with the same node id.

- `program` is the program that writes the lines: it selects the CrowdSec parser (`nginx`, `postgres`, `apache2`...).
- `program: syslog` is for files in syslog format, such as `/var/log/auth.log`: each line names its program (`sshd`, `sudo`). CrowdSec splits the lines as its own syslog parser does (built-in parser `openpicket/syslog-logs`), so the hub's parsers for that program apply.
- A glob (`/var/log/nginx/*access.log`) takes every match, including files created later. Files present at the first start are read from their end, so their backlog is not sent; files created later are read from their start.
- Rotation (rename and create, or copytruncate) is followed. A line is acknowledged by the manager before its position is saved: after a restart, unacknowledged lines are sent again.
- `journal: {}` follows the systemd journal with `journalctl` (servers without `/var/log/auth.log`, such as Debian 12 without rsyslog). Entries become syslog lines named after their `SYSLOG_IDENTIFIER` (`sshd`, `sudo`). `matches` narrow it down (`_SYSTEMD_UNIT=ssh.service`, `+` between alternatives). The first start reads new entries only; later the agent resumes after the last entry the manager acknowledged. The agent's user needs to read the journal (root, or the `systemd-journal` group).
- `listen: "127.0.0.1:5140"` receives syslog datagrams from a local daemon (rsyslog `*.* @127.0.0.1:5140`). Nothing replays them.

## 3. Service

```sh
cp openpicket-agent.service /etc/systemd/system/
systemctl daemon-reload
openpicket-agent check -config /etc/openpicket-agent/agent.yaml
systemctl enable --now openpicket-agent
```

`check` reports the files each log source matches (journalctl for the journal), the key, and the manager connection.

## 4. CrowdSec parsers

In **CrowdSec content**, the **Log programs** panel lists the programs your servers send. A program no enabled parser selects is flagged ("no parser"); its suggestions open the hub entry to install (for nginx, the `crowdsecurity/nginx` collection). New scenarios start in simulation: they raise alerts without decisions until you turn them on.

High volume access logs can be kept out of Loki in the same panel; CrowdSec still reads them.

## Blocking on the server itself (optional)

With `openpicket.wan_interfaces` set (for example `[eth0]`), the agent also applies the CrowdSec bans and port policies on this host with nftables, as on a router. Without it, bans only apply on the routers.
