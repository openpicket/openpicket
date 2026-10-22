# Installing openpicket-agent on OpenWrt

This guide covers the docker installation. A native mode for low-end OpenWrt devices (NFLOG, bans and port policies without Suricata) is planned.

## Requirements

- **OpenWrt**: a release with fw4 (nftables). iptables (legacy or iptables-nft) is not supported.
- **Architecture**: x86_64 or aarch64. The docker image (`ghcr.io/openpicket/openpicket-agent`) is based on Alpine.
- **Storage**: storage beyond the overlay, such as USB or eMMC, for the docker image, Suricata rules and logs.
- **Memory**: 1 GB or more is recommended. The actual need depends on the ruleset size.
  - The full ET Open ruleset takes a few hundred MB per IDS instance.
  - Mixing IDS and IPS interfaces runs two instances, roughly doubling that.
  - Trimming rules with per-node `sources.yaml` or `disable.conf` saves memory.
- **Manager**: OpenPicket (Helm chart) is installed and the router can reach the manager's public URL. The agent only opens outbound connections.

## 1. Packages

### docker

```sh
opkg update
opkg install dockerd docker docker-compose luci-app-dockerman   # luci-app-dockerman is optional
/etc/init.d/dockerd enable && /etc/init.d/dockerd start
```

- On releases that use apk (OpenWrt 25.12 and later), install the same packages with `apk update && apk add ...`. The same goes for the kernel modules below.
- Putting the docker data-root on external storage is recommended (`data_root` in `/etc/config/dockerd`).

### NFLOG kernel module (required)

Connections refused on the WAN (port scans and the like) reach the agent through NFLOG and feed CrowdSec detection. The default OpenWrt image does not include this module.

```sh
opkg install kmod-nfnetlink-log
```

- Without it the agent logs `cannot open NFLOG group (kmod-nfnetlink-log missing, ...)` and retries every 30 seconds. Once the module is installed it starts receiving without a restart.
- To go without NFLOG, set `openpicket.nflog.enabled: false`.

### For IPS: NFQUEUE kernel modules

IPS hands traffic to Suricata through NFQUEUE. IDS (af-packet) alone does not need these modules.

```sh
opkg install kmod-nft-queue kmod-nfnetlink-queue
```

- Without the modules nft prints a misleading message: `Error: No such file or directory; did you mean table 'fw4' in family inet?`
- At startup the agent checks queue support with `nft -c` (checked down to the kernel, nothing applied). Without support it:
  - reports the `nfqueue_unsupported` warning with the packages to install;
  - reports the interfaces as not IPS-capable, so IPS cannot be selected in the UI;
  - rejects IPS requests at the POLICY stage, before touching the firewall.
- After the modules are installed, the agent re-checks within 5 minutes and allows IPS. Restart the agent to apply it at once.

## 2. Connection details

The agent needs the manager's URL and host key (the `openpicket` section):

- **URL**: `wss://<public host>/agent/data/v1/connect`
- **host_key**: web UI **Nodes > Connection info**, or `kubectl -n <ns> exec deploy/<release>-manager -- openpicket-manager pubkey`

**Nodes > Connection info** shows the section ready to copy, and the NOTES printed after the Helm install show the same values.

The agent also connects to openpicket-suricontroller (Suricata management) with the same key. The manager hands out that endpoint, so agent.yaml needs no `controller` section:

- The URL defaults to `/agent/v1/connect` on the host in `openpicket.url`. The Helm chart's ingress routes it there. If agents reach suricontroller through another host, set `manager.agentControllerURL` in the chart.
- The agent trusts this endpoint because it comes from the manager, whose key the agent pins. It saves the endpoint under `data` and uses it at the next start, before the manager answers.
- When the controller's host key or address changes, only the Suricata management connection reconnects.
- To pin the controller yourself, add a `controller` section with both `url` and `host_key` (`kubectl -n <ns> exec sts/<release>-suricontroller -- openpicket-suricontroller hostkey`).

With an ingress without TLS, use `ws://` instead of `wss://`. Both connections are encrypted with Noise IK, so TLS can terminate anywhere.

## 3. Agent configuration

```sh
mkdir -p /opt/openpicket-agent/etc /opt/openpicket-agent/suricata /opt/openpicket-agent/data /mnt/data/suricata-log
cd /opt/openpicket-agent
# Copy deploy/images/agent/agent.yaml.example to etc/agent.yaml and
# deploy/images/agent/docker-compose.yml to docker-compose.yml, then edit them.
```

If `/opt/openpicket-agent/suricata` is empty, the first run fills it with the image's default `suricata.yaml`.

The key settings in `agent.yaml`:

```yaml
node_id: gw-home                         # must match the comment of the registered public key
key_file: /etc/suri-agent/agent_ed25519
platform:
  profile: docker
  host_root: /host
  firewall: nftables    # the host's nft (fw4) through chroot; auto also means nftables, iptables is rejected
interfaces:
  - name: br-lan
  - name: wan           # pppoe-wan for PPPoE
ips:
  enabled: false        # true once the NFQUEUE modules are installed
  queues: "0-1"         # match the number of CPU cores
suricata:
  instances:
    ids: { log_dir: /var/log/suricata/ids }
    # ips: { log_dir: /var/log/suricata/ips }
logs:
  queue_max_bytes: 16MiB
  rotation:
    enabled: true       # keep the flash/disk from filling up
    max_size: 32MiB
    keep: 2
openpicket:
  url: wss://openpicket.example.com/agent/data/v1/connect
  host_key: "ssh-ed25519 AAAA... openpicket-manager"
  fw4_zones: [wan]      # the devices of these fw4 zones are the WAN (follows a second uplink, PPPoE)
  allowlist: [controller]   # never blocked; "controller" is the manager and suricontroller hosts
  nflog:
    enabled: true
    install_rule: auto  # installed as an fw4 snippet on OpenWrt
  enforcer:
    enabled: true       # apply CrowdSec ban decisions in nftables
  policy:
    enabled: true       # port policies (blocked before DNAT)
```

- **WAN**: NFLOG, bans and port policies apply to the WAN only. To treat devices outside the `fw4_zones` zones (WireGuard, for example) as WAN, add them to `wan_interfaces` (a trailing `*` matches a prefix, e.g. `wg*`).
- **allowlist**: adding the management networks is strongly recommended (e.g. `192.168.0.0/16`). It takes precedence over ban decisions and port policies.
- See `deploy/images/agent/agent.yaml.example` for every setting.

## 4. Key generation and registration

```sh
docker run --rm -v /opt/openpicket-agent/etc:/etc/suri-agent ghcr.io/openpicket/openpicket-agent:latest keygen
# Output: ssh-ed25519 AAAA... gw-home  → paste it in the web UI under Nodes > Register node
```

- `keygen` reads `node_id` and `key_file` from `agent.yaml`. To create the key without a configuration file, add `-node-id gw-home -key-file /etc/suri-agent/agent_ed25519`.
- If the key already exists, it is kept and its public key is printed. Use `pubkey` to print it again.

## 5. Running

Point the log volume (`/var/log/suricata`) in `docker-compose.yml` at external storage, then start the agent. `/var` on OpenWrt is RAM (tmpfs).

```yaml
    volumes:
      - /:/host:ro                            # host tools (nft, uci, fw4) run via chroot
      - /usr/share/nftables.d:/host/usr/share/nftables.d  # fw4 WAN-REJECT snippet
      - ./etc:/etc/suri-agent
      - ./suricata:/etc/suricata
      - ./data:/var/lib/suri-agent
      - /mnt/data/suricata-log:/var/log/suricata
```

```sh
docker compose up -d
docker logs -f openpicket-agent
docker exec openpicket-agent openpicket-agent check
```

- `check` verifies the configuration, the key, the manager connection and the controller endpoint the manager hands out.
  ```
  [ok  ] config         /etc/suri-agent/agent.yaml
  [ok  ] key            ssh-ed25519 AAAA... gw-home
  [ok  ] manager        wss://openpicket.example.com/agent/data/v1/connect (manager ...)
  [ok  ] controller     /agent/v1/connect (from the manager)
  ```
- Once connected, the node's status changes in the web UI node list. The agent saves the last ban list and port policies it received in `data` and restores them after a reboot, before connecting to the manager.

## Working with fw4

The agent does not change the fw4 configuration (`/etc/config/firewall`). It keeps its own tables and adds only the WAN-REJECT logging as an fw4 snippet.

- **Bans and port policies** live in tables independent of fw4.
  - `table inet openpicket_ban`: CrowdSec bans. Chains at prerouting `raw - 10` and `mangle - 10`, forward/output `filter - 10`.
  - `table inet openpicket_policy`: port policies. A prerouting `mangle` chain, so they apply before DNAT (port forwards).
  - Precedence is `allowlist > bans > port policies > DNAT`.
- **WAN-REJECT logging**: for each zone in `fw4_zones` the agent writes `/usr/share/nftables.d/chain-post/input_<zone>/90-openpicket-wan-reject.nft` and runs `fw4 reload`.
  - fw4 places the snippet in the zone's input chain after its allow rules, right before `jump reject_from_<zone>`. Only connections fw4 is about to refuse are logged; services open on the WAN (SSH, VPN, ...) and port-forwarded connections are not.
  - If a zone's input policy is ACCEPT, the snippet is not installed there and the agent warns.
  - Connections an fw4 rule explicitly drops or rejects end at that rule and are not logged.
- **WAN devices** are read every 15 seconds from the `iifname ... jump input_<zone>` rules of the fw4 `input` chain, so a second uplink or a changed PPPoE device name is followed.
- **fw4 restarts**: fw4 rewrites only its own table (`inet fw4`). If the agent's tables or snippet disappear anyway, the agent notices on its periodic check and applies them again.
- **IPS path**: traffic of interfaces in IPS mode goes to NFQUEUE from `table inet suricontroller`.
  - Forward/input/output chains at priority `filter + 10`.
  - Only traffic fw4 accepted reaches Suricata.
  - With `ips.fail_open: true` (the default) the queue has the `bypass` flag: traffic passes if Suricata stops.
- **Flow offloading**: with software/hardware flow offloading on, established flows bypass netfilter and Suricata does not see them.
  - The agent detects it and reports a warning (it does not turn it off).
  - Turning it off while IDS/IPS is in use is recommended:

```sh
uci set firewall.@defaults[0].flow_offloading='0'
uci set firewall.@defaults[0].flow_offloading_hw='0'
uci commit firewall && /etc/init.d/firewall restart
```

## Removing the agent

Stop the container, delete the tables and the snippet the agent created, and reload fw4.

```sh
docker compose down
nft delete table inet openpicket_ban 2>/dev/null
nft delete table inet openpicket_policy 2>/dev/null
nft delete table inet suricontroller 2>/dev/null
rm -f /usr/share/nftables.d/chain-post/input_*/90-openpicket-wan-reject.nft
fw4 reload
```

Deleting the node in the web UI stops that key from connecting.

## Using the logs with another collector

- Suricata logs (eve) and NFLOG records are sent to the manager, which forwards them to Loki and CrowdSec. While disconnected, the agent queues up to `logs.queue_max_bytes` and resends them.
- The `outputs` and `logging` sections of `/opt/openpicket-agent/suricata/suricata.yaml` set the log files and formats. This file belongs to you.
- `suricata.instances.*.log_dir` in `agent.yaml` sets the per-instance directories.
- Collectors such as Elastic Agent or Vector can read the log directory mounted on the host as well. The agent only reads the files.
- With an external logrotate, set `logs.rotation.enabled: false` and, after rotating, run `docker kill -s HUP openpicket-agent` so Suricata reopens its files.
  - The signal goes through tini to the agent, which sends SIGHUP to each running Suricata instance.
