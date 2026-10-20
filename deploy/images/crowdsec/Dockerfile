# OpenPicket CrowdSec image (docs/ARCHITECTURE.md §8): everything is
# installed at build time, nothing is downloaded at runtime.
#
# Build from the repository root:
#   docker build -f deploy/images/crowdsec/Dockerfile -t openpicket-crowdsec .
ARG CROWDSEC_VERSION=v1.8.1
FROM crowdsecurity/crowdsec:${CROWDSEC_VERSION}

# The base image keeps its configuration in /staging and copies it to
# /etc/crowdsec on first start. Install into /etc/crowdsec, then copy the
# result back so both places agree.
RUN set -eux; \
    cp -a /staging/etc/crowdsec /etc/; \
    mkdir -p /var/lib/crowdsec/data; \
    cp -a /staging/var/lib/crowdsec/data/. /var/lib/crowdsec/data/; \
    cscli hub update; \
    # Pin the hub branch used now: without it every cscli install asks
    # version.crowdsec.net for the latest release, which fails offline.
    yq -i '.cscli.hub_branch = "master"' /etc/crowdsec/config.yaml; \
    # The SSH and Linux defaults do not apply to OpenPicket log processors.
    # Remove them first: removing a collection also removes its parsers.
    cscli collections remove crowdsecurity/linux crowdsecurity/sshd crowdsecurity/whitelist-good-actors --force || true; \
    # syslog-logs carries the non-syslog node (program = acquisition type).
    # docker-logs and cri-logs are installed by the entrypoint on every
    # start; having them already makes that a no-op.
    cscli parsers install crowdsecurity/syslog-logs crowdsecurity/dateparse-enrich crowdsecurity/whitelists \
        crowdsecurity/docker-logs crowdsecurity/cri-logs; \
    # AppSec (WAF) content; only active when an appsec acquisition is added.
    cscli collections install crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules; \
    # Geo comes from the MaxMind databases uploaded to OpenPicket: the
    # manager sends the remote party's country and AS with every record.
    cscli parsers remove crowdsecurity/geoip-enrich --force || true; \
    rm -f /var/lib/crowdsec/data/GeoLite2-*.mmdb /staging/var/lib/crowdsec/data/GeoLite2-*.mmdb

COPY hub/parsers/s01-parse/ /etc/crowdsec/parsers/s01-parse/
COPY hub/parsers/s02-enrich/ /etc/crowdsec/parsers/s02-enrich/
COPY hub/scenarios/ /etc/crowdsec/scenarios/
COPY hub/profiles.yaml /etc/crowdsec/profiles.yaml
COPY hub/console-context.yaml /etc/crowdsec/console/context.yaml
COPY hub/acquis.d/ /etc/crowdsec/acquis.d/

RUN set -eux; \
    echo '# Acquisition is in acquis.d (OpenPicket records over HTTP).' > /etc/crowdsec/acquis.yaml; \
    rm -rf /staging/etc/crowdsec; \
    cp -a /etc/crowdsec /staging/etc/crowdsec; \
    cp -a /var/lib/crowdsec/data/. /staging/var/lib/crowdsec/data/; \
    rm -f /staging/var/lib/crowdsec/data/crowdsec.db*; \
    cscli parsers list; cscli scenarios list

# No CAPI registration, no console; LAPIs share PostgreSQL (configured by
# the Helm chart), so the local database volume check does not apply.
ENV DISABLE_ONLINE_API=true \
    NO_HUB_UPGRADE=true \
    CROWDSEC_BYPASS_DB_VOLUME_CHECK=true

COPY deploy/images/crowdsec/start.sh /usr/local/bin/openpicket-crowdsec-start
ENTRYPOINT ["/usr/local/bin/openpicket-crowdsec-start"]
