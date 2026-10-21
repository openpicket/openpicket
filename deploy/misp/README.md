# MISP integration

`taxonomies/openpicket/machinetag.json` is the taxonomy OpenPicket uses to
store approval states in MISP. Install it into MISP's taxonomies directory
(`app/files/taxonomies/openpicket/`), then *Administration > Taxonomies >
Update taxonomies* and enable `openpicket` (the Helm chart's built-in MISP
does this at start).

Flow (docs/ARCHITECTURE.md §5.5):

1. Repeated attackers (`OPENPICKET_MISP_PROPOSE_MIN_ALERTS` alerts in
   `OPENPICKET_MISP_PROPOSE_WINDOW`) and addresses proposed from the UI are
   added to the monthly event "OpenPicket sightings YYYY-MM" with
   `openpicket:state="proposed"` and `to_ids` off.
2. An analyst approves them in MISP or on the OpenPicket Approvals page:
   `openpicket:state="approved"`, `openpicket:ttl="30d"`, `to_ids` on.
   Analysts may also tag any existing ip-src/ip-dst attribute this way.
3. openpicket-manager keeps a CrowdSec decision (`openpicket/misp-ip-src`
   inbound, `openpicket/misp-ip-dst` both ways, origin `misp`) on every
   approved attribute, renewing it before it expires.
4. Revoked, rejected, `to_ids` off, deleted or past their TTL: the decision is
   deleted. If MISP is unreachable nothing is deleted; decisions run out
   within twice the renew interval.
