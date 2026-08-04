DOMAIN = "localthings"

PLATFORMS = [
    "sensor",
    "binary_sensor",
    "switch",
    "number",
    "select",
    "button",
    "time",
    "climate",
    "fan",
    "water_heater",
]

CONF_HOST = "host"
CONF_PORT = "port"
CONF_CA_CERT_PEM = "ca_cert_pem"
CONF_CA_KEY_PEM = "ca_key_pem"
CONF_LEAF_CERT_PEM = "leaf_cert_pem"
CONF_LEAF_KEY_PEM = "leaf_key_pem"

# Device identity, resolved once by the config flow's probe and persisted on
# the entry (issue #236). These are what the coordinator mints registry keys
# from at __init__ time, before any poll has happened -- see
# LocalThingsCoordinator.__init__. Without them the coordinator had to seed
# `device_serial` with the host and rebuild its DeviceInfo after the first
# successful poll, so anything that registered in between (the connection-mode
# sensor, which is added unconditionally rather than from `bound`) was written
# into the entity/device registry keyed on the IP address permanently.
#
# CONF_SERIAL is the *resolved* serial -- registry.identity.resolve_serial's
# output, i.e. the host itself for a board that reports a placeholder serial
# (issues #83/#189) -- so it matches what _run_discovery computes on the first
# poll exactly, and the device identity never changes underneath the registry.
CONF_SERIAL = "serial"
CONF_MODEL = "model"
CONF_MANUFACTURER = "manufacturer"
CONF_DEVICE_TYPE = "device_type"

# Options-flow key (entry.options, not entry.data): lets a user override the
# device-wide remote-control-off write block for a specific device (issue
# #54). Some devices report remote control off yet still accept certain
# writes (e.g. default detergent/softener dosing on a washer, applied even
# to the built-in programs) -- the block exists to give a clear error
# instead of a silent device-side rejection, but that assumption doesn't
# hold for every model. Defaults to False (block stays on) everywhere it's
# read, so devices this doesn't apply to see no behavior change.
CONF_BYPASS_REMOTE_CONTROL = "bypass_remote_control_lock"

# Options-flow key: minimum change (in minutes) required before a
# hysteresis-gated timestamp sensor (currently just finish_time) is allowed
# to report a new value. Devices commonly revise their own remaining-time
# estimate by a minute or two throughout a cycle, and finish_time = now() +
# remaining drifts by the poll interval between those revisions -- both push
# a fresh state (and a recorder/logbook entry) far more often than the
# estimate is meaningfully different. 0 disables the gate (every computed
# change is reported, today's behavior).
CONF_FINISH_TIME_HYSTERESIS_MINUTES = "finish_time_hysteresis_minutes"
DEFAULT_FINISH_TIME_HYSTERESIS_MINUTES = 3

# Legacy appliances bind the DTLS/CoAP local API somewhere in this ephemeral
# range. Newer OCF appliances can advertise a secure port outside it, so the
# config flow first asks the device's public discovery endpoint and merges any
# validated advertised port into this bounded fallback range.
PROBE_PORT_RANGE = list(range(49152, 49161))

# Public OCF discovery endpoint used to locate a device-advertised secure
# DOXM port. Samsung firmware can answer a request sent to 5683 from a
# different ephemeral source port, so callers must validate the response IP
# and CoAP token rather than requiring the source port to remain 5683.
OCF_DISCOVERY_PORT = 5683
OCF_DISCOVERY_TIMEOUT_S = 1.0
OCF_DISCOVERY_RETRIES = 2

# Ports we've historically seen complete a DTLS handshake. When more than one
# port in the range looks live, these are tried first.
PREFERRED_PROBE_PORTS = [49154, 49155]

# Per-port timeout for the cheap UDP liveness sweep. Closed ports return an
# ICMP port-unreachable almost immediately; a live-but-silent port is only
# detected by this timeout elapsing, so keep it short. Only reached now as the
# fallback for when the ClientHello probe below confirms nothing.
LIVENESS_PROBE_TIMEOUT_S = 1.5

# Per-port budget for the DTLS ClientHello probe (smartthings-local >= 0.1.2),
# the primary port-detection gate. A real DTLS server answers with a
# HelloVerifyRequest in ~1 RTT, so a live port resolves well inside this; the
# budget only bounds how long a *silent* port takes to give up, since the
# probe services OpenSSL's retransmit timer rather than reading one dropped
# ClientHello as dead. 3s covers two retransmits on a slow LAN.
CLIENTHELLO_PROBE_TIMEOUT_S = 3.0
CLIENTHELLO_PROBE_RETRIES = 2

# The whole port range is probed at once: each stateless probe is bounded by
# CLIENTHELLO_PROBE_TIMEOUT_S (unlike a full handshake's 12s), so the sweep
# costs one probe's wall clock rather than the sum of the range. Capped so a
# widened PROBE_PORT_RANGE can't spawn an unbounded thread pool.
PROBE_MAX_WORKERS = 12

# Deadline for the blockwise /device/0 GET during the config-flow probe. The
# slowest device observed returns a full dump in ~8s, so 10s leaves headroom
# without stalling setup; it matches the per-resource read timeout elsewhere.
PROBE_GET_TIMEOUT_S = 10.0

# Base for the local (client-side) DTLS source port, distinct from the
# destination probe ports above. See coordinator._local_source_port for why a
# fixed per-device source port matters and how the per-device offset is
# derived. Base mirrors the upstream smartthings-local reference bridge.
# Requires smartthings-local >= 0.1.1.
DTLS_LOCAL_PORT_BASE = 49700

SUMMARY_INTERVAL_S = 30.0

DEVICE_SUPPORT_ISSUE_URL = (
    "https://github.com/mbillow/localthings/issues/new?template=device-support.yml"
)
