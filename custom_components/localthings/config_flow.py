"""Config flow for Local Things integration."""

from __future__ import annotations

import contextlib
import datetime
import errno
import json
import logging
import re
import secrets
import selectors
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    ObjectSelector,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    CLIENTHELLO_PROBE_RETRIES,
    CLIENTHELLO_PROBE_TIMEOUT_S,
    CONF_BYPASS_REMOTE_CONTROL,
    CONF_CA_CERT_PEM,
    CONF_CA_KEY_PEM,
    CONF_DEVICE_TYPE,
    CONF_FINISH_TIME_HYSTERESIS_MINUTES,
    CONF_HOST,
    CONF_LEAF_CERT_PEM,
    CONF_LEAF_KEY_PEM,
    CONF_MANUFACTURER,
    CONF_MODEL,
    CONF_PORT,
    CONF_SERIAL,
    DEFAULT_FINISH_TIME_HYSTERESIS_MINUTES,
    DOMAIN,
    LIVENESS_PROBE_TIMEOUT_S,
    OCF_DISCOVERY_PORT,
    OCF_DISCOVERY_RETRIES,
    OCF_DISCOVERY_TIMEOUT_S,
    PREFERRED_PROBE_PORTS,
    PROBE_GET_TIMEOUT_S,
    PROBE_MAX_WORKERS,
    PROBE_PORT_RANGE,
)

_TEXT = TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT))
_MULTILINE = TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT, multiline=True))
_HYSTERESIS_MINUTES = NumberSelector(
    NumberSelectorConfig(
        min=0,
        max=30,
        step=1,
        mode=NumberSelectorMode.BOX,
    )
)

_LOGGER = logging.getLogger(__name__)

_SAMSUNG_CLOUD_HOST = "connect-v2.samsungiotcloud.com"
_OCF_DISCOVERY_MAX_DATAGRAM_BYTES = 8192
_OCF_DISCOVERY_MAX_PORTS = 8


class CannotConnect(Exception):
    """Base for every probe failure.

    `error_key` selects which message the user sees. The subclasses below
    exist because "cannot connect" covered wildly different situations -- an
    IP with nothing on it, an appliance on cloud-only firmware, a device
    that's simply still holding a session from the last attempt, and a device
    that answered and rejected our certificate all told the user the same
    thing ("check the IP and the CA credentials"), which is only actionable
    advice for one of them.

    Raising this base class directly is still valid for a failure we can't
    narrow down; it maps to that same generic message.
    """

    error_key = "cannot_connect"


class NoResponse(CannotConnect):
    """Nothing at that address answered anything at all."""

    error_key = "no_response"


class PortsClosed(CannotConnect):
    """The host is up and actively refused every port in the range."""

    error_key = "ports_closed"


class NoDtlsServer(CannotConnect):
    """Ports are reachable, but nothing there speaks DTLS."""

    error_key = "no_dtls_server"


class HandshakeTimeout(CannotConnect):
    """A DTLS server is confirmed present but never finished the handshake."""

    error_key = "handshake_timeout"


class CertRejected(CannotConnect):
    """The appliance broke off the handshake over our certificate."""

    error_key = "cert_rejected"


class HandshakeFailed(CannotConnect):
    """The appliance broke off the handshake for a non-certificate reason."""

    error_key = "handshake_failed"


class CloudUnreachable(CannotConnect):
    """Samsung's cloud gateway, which mints the UUID, was unreachable."""

    error_key = "cloud_unreachable"


class UnexpectedResponse(CannotConnect):
    """We authenticated, but the device didn't return a usable description."""

    error_key = "unexpected_response"


class InvalidCA(Exception):
    error_key = "invalid_ca"


def _fetch_samsung_uuid() -> str:
    """Connect to Samsung's cloud gateway and extract the UUID from its TLS cert.

    Verification is disabled because Samsung's chain contains a self-signed cert.
    We only need to read the UUID from the cert subject, not verify its trust.
    """
    from cryptography import x509 as _x509

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((_SAMSUNG_CLOUD_HOST, 443), timeout=15) as raw,
        ctx.wrap_socket(raw, server_hostname=_SAMSUNG_CLOUD_HOST) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if der is None:
        raise RuntimeError(f"No certificate received from {_SAMSUNG_CLOUD_HOST}")
    cert = _x509.load_der_x509_certificate(der)
    for attr in cert.subject:
        if attr.oid == _x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME and isinstance(attr.value, str):
            m = re.search(r"uuid:([0-9a-f-]+)", attr.value, re.IGNORECASE)
            if m:
                return m.group(1)
    raise RuntimeError(f"UUID not found in {_SAMSUNG_CLOUD_HOST} certificate subject")


def _mint_leaf_cert(ca_cert_pem: str, ca_key_pem: str, uuid: str) -> tuple[str, str]:
    """Mint a fresh RSA-2048 leaf cert signed by the CA.

    Returns (fullchain_pem, leaf_key_pem) where fullchain_pem is the leaf cert
    followed by the full CA PEM, suitable for use_certificate_chain_file.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID

    m = re.search(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        ca_cert_pem,
        re.DOTALL,
    )
    if not m:
        raise InvalidCA("No certificate found in CA cert PEM")
    try:
        ca_cert = x509.load_pem_x509_certificate(m.group(1).encode())
        ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    except Exception as exc:
        raise InvalidCA(f"Failed to load CA credentials: {exc}") from exc
    if not isinstance(
        ca_key,
        (
            _rsa.RSAPrivateKey,
            ec.EllipticCurvePrivateKey,
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            dsa.DSAPrivateKey,
        ),
    ):
        raise InvalidCA(f"CA key is not a signing key (got {type(ca_key).__name__})")

    leaf_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.datetime.now(datetime.UTC)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Samsung Electronics"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"uuid:{uuid}"),
                    x509.NameAttribute(NameOID.COMMON_NAME, f"urn:uuid:{uuid}"),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10 * 365))
        .sign(ca_key, hashes.SHA256())
    )

    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode()
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    # Ensure a newline separates the leaf and CA blocks regardless of
    # whether the user's pasted CA PEM had a trailing newline.
    fullchain_pem = leaf_cert_pem.rstrip("\n") + "\n" + ca_cert_pem
    if not fullchain_pem.endswith("\n"):
        fullchain_pem += "\n"
    return fullchain_pem, leaf_key_pem


def _order_candidates(ports: list[int]) -> list[int]:
    """Order live ports so the historically known DTLS ports are tried first."""
    preferred = [p for p in PREFERRED_PROBE_PORTS if p in ports]
    rest = sorted(p for p in ports if p not in PREFERRED_PROBE_PORTS)
    return preferred + rest


# The kernel's way of saying the datagram never had anywhere to go: no route
# to the network, or the host never answered ARP on our own LAN. Distinct from
# ECONNREFUSED, which is a *response* -- the host is there and told us the port
# is closed. Both leave a port "not live", but they mean opposite things about
# whether anything exists at that address, which is the difference between
# telling a user to check the IP and telling them their appliance is on
# cloud-only firmware.
_UNREACHABLE_ERRNOS = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN})


@dataclass(frozen=True)
class _SweepResult:
    """What the UDP sweep observed, kept as three separate verdicts."""

    live: list[int]  # silent -> open|filtered, worth a handshake
    refused: list[int]  # ICMP port-unreachable -> host is up, port closed
    unreachable: list[int]  # no route / no ARP -> nothing is at that address


def _find_live_ports(host: str, ports: list[int], timeout: float) -> _SweepResult:
    """Fast UDP liveness sweep -- the sweep's own verdict, nothing added.

    UDP is connectionless, but a *connected* UDP socket surfaces the ICMP
    port-unreachable that a closed port returns as ECONNREFUSED on its next
    recv. So we send one probe datagram per port and watch for that error:

      * ECONNREFUSED       -> port is closed (device actively rejected it)
      * silence / any data -> port may be live (open|filtered); a candidate

    This is the in-process equivalent of ``nmap -sU``: it lets us take a
    nine-port range down to the one or two ports actually worth a full DTLS
    handshake + /device/0 GET, and bounds the total wait to ``timeout``
    instead of stalling on every dead port when a firewall swallows the ICMP
    replies.

    The result is deliberately the raw verdict, with no preferred-port rescue
    folded in (that's `_sweep_ports`): its *shape* is evidence about the host,
    and mixing a rescue into it would destroy that. Which is also why a
    refusal and an unreachable are counted apart rather than both just being
    "not live" -- see _SweepResult.
    """
    sockets: dict[int, socket.socket] = {}
    sel = selectors.DefaultSelector()
    refused: list[int] = []
    unreachable: list[int] = []
    # A single byte is enough to provoke an ICMP port-unreach from a closed
    # port; a real DTLS ClientHello is unnecessary just to test for life.
    probe = b"\x00"

    def _rule_out(port: int, exc: OSError) -> None:
        (unreachable if exc.errno in _UNREACHABLE_ERRNOS else refused).append(port)

    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                sock.connect((host, port))
                sock.send(probe)
            except OSError as exc:
                # Failing on the way out means the kernel already knows the
                # datagram can't get there (no route, ARP never resolved).
                _rule_out(port, exc)
                sock.close()
                continue
            sockets[port] = sock
            sel.register(sock, selectors.EVENT_READ, port)

        # Ports drop out of the selector as they refuse; whatever is still
        # registered when the deadline passes is silent-but-live (a candidate).
        deadline = time.monotonic() + timeout
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for key, _ in sel.select(timeout=remaining):
                sock = sockets[key.data]
                try:
                    # Data back means live; an error means the port is
                    # closed or the host isn't there — either way, rule it out.
                    sock.recv(1)
                except OSError as exc:
                    _rule_out(key.data, exc)
                    sel.unregister(sock)
        live = [key.data for key in sel.get_map().values()]
    finally:
        sel.close()
        for sock in sockets.values():
            with contextlib.suppress(OSError):
                sock.close()

    return _SweepResult(_order_candidates(live), sorted(refused), sorted(unreachable))


def _sweep_ports(host: str, ports: list[int], timeout: float) -> tuple[_SweepResult, list[int]]:
    """`(sweep, candidates)` -- what the host said, and what to actually try.

    The sweep's ICMP-based verdict isn't reliable on every network path --
    issue #192 captured a segregated-VLAN device where it called three ports
    live that a concurrent nmap scan showed as closed, while the port nmap
    found genuinely open|filtered (49154, one of our historically confirmed
    ports) never showed up as live at all. Rather than trust a wrong "not
    live" verdict on a port we already have strong prior evidence for, always
    give the historically-confirmed ports a real handshake attempt too.
    Bounded cost: at most len(PREFERRED_PROBE_PORTS) extra handshakes, only
    when the sweep disagrees with the prior.

    Both halves are returned rather than just the union because they answer
    different questions: `candidates` is what to hand a handshake, `sweep` is
    what the host actually told us about itself.
    """
    sweep = _find_live_ports(host, ports, timeout)
    rescued = [p for p in PREFERRED_PROBE_PORTS if p in ports and p not in sweep.live]
    return sweep, _order_candidates(sweep.live + rescued)


@dataclass(frozen=True)
class _PortScan:
    """What port detection learned about a host.

    `candidates` is what gets a full DTLS handshake. The other fields are kept
    because they're the evidence behind a failure message: `confirmed` names
    ports a DTLS server was *proven* on, `advertised` names secure ports the
    target's public OCF directory reported, and `swept` is the UDP sweep's own
    verdict (None when the sweep never had to run).
    """

    candidates: list[int]
    confirmed: list[int]
    swept: _SweepResult | None = None
    advertised: tuple[int, ...] = ()


def _advertised_secure_ports(payload: bytes) -> list[int]:
    """Extract validated secure DOXM ports from an OCF discovery payload."""
    import cbor2

    try:
        body = cbor2.loads(payload)
    except (cbor2.CBORDecodeError, TypeError, ValueError):
        return []

    items = body if isinstance(body, list) else [body]
    ports: set[int] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        links = item.get("links")
        if not isinstance(links, list):
            continue
        for link in links:
            if not isinstance(link, dict) or link.get("href") != "/oic/sec/doxm":
                continue
            resource_types = link.get("rt")
            if isinstance(resource_types, str):
                resource_types = [resource_types]
            if not isinstance(resource_types, list) or "oic.r.doxm" not in resource_types:
                continue
            policy = link.get("p")
            if not isinstance(policy, dict) or policy.get("sec") is not True:
                continue
            port = policy.get("port")
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                continue
            ports.add(port)
            if len(ports) >= _OCF_DISCOVERY_MAX_PORTS:
                return sorted(ports)
    return sorted(ports)


def _discover_advertised_secure_ports(host: str) -> list[int]:
    """Ask ``host`` for secure OCF ports advertised by its DOXM resource.

    The request is unicast and read-only. Responses are accepted only when
    they come from the resolved target IPv4 address, carry our unpredictable
    CoAP token, return 2.05 Content, and contain a validated secure DOXM link.
    The UDP source port is deliberately not checked: newer Samsung firmware
    receives discovery on 5683 but sends its response from an ephemeral port.
    """
    from smartthings_local.protocol.coap import (
        ACCEPT,
        BLOCK2,
        CF_CBOR,
        METHOD_GET,
        TYPE_NON,
        URI_PATH,
        URI_QUERY,
        build_coap,
        parse_coap,
    )

    addresses = {
        info[4][0]
        for info in socket.getaddrinfo(
            host,
            OCF_DISCOVERY_PORT,
            family=socket.AF_INET,
            type=socket.SOCK_DGRAM,
        )
    }
    if not addresses:
        return []

    token = secrets.token_bytes(4)
    per_attempt_timeout = OCF_DISCOVERY_TIMEOUT_S / max(OCF_DISCOVERY_RETRIES, 1)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(per_attempt_timeout)
        for _ in range(max(OCF_DISCOVERY_RETRIES, 1)):
            # Keep the token stable so a delayed response to either attempt
            # remains correlated, but give each NON request a fresh MID so a
            # peer's duplicate suppression cannot discard the retry.
            request = build_coap(
                TYPE_NON,
                METHOD_GET,
                secrets.randbits(16),
                token,
                [
                    (URI_PATH, b"oic"),
                    (URI_PATH, b"res"),
                    (URI_QUERY, b"rt=oic.r.doxm"),
                    (ACCEPT, CF_CBOR),
                ],
            )
            for address in addresses:
                sock.sendto(request, (address, OCF_DISCOVERY_PORT))

            deadline = time.monotonic() + per_attempt_timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    datagram, peer = sock.recvfrom(65535)
                except TimeoutError:
                    break
                if (
                    peer[0] not in addresses
                    or len(datagram) > _OCF_DISCOVERY_MAX_DATAGRAM_BYTES
                    or not datagram
                    or datagram[0] >> 6 != 1
                ):
                    continue
                try:
                    _mtype, code, _mid, response_token, options, payload = parse_coap(datagram)
                except (IndexError, TypeError, ValueError):
                    continue
                if code != 0x45 or response_token != token or not payload:
                    continue
                # Do not try to decode a partial Block2 body. The filtered
                # DOXM response is normally one small datagram; falling back
                # to the legacy scan is safer than assembling unbounded data
                # during config flow discovery.
                if any(
                    number == BLOCK2 and value and int.from_bytes(value, "big") & 0x08
                    for number, value in options
                ):
                    continue
                if ports := _advertised_secure_ports(payload):
                    return ports
    return []


def _clienthello_probe(host: str, port: int):
    """One stateless DTLS ClientHello against `host:port`.

    Imported lazily so an install whose smartthings-local predates the probe
    (< 0.1.2) degrades to the UDP sweep at scan time rather than failing to
    load the config flow at all.
    """
    from smartthings_local.protocol.dtls_probe import probe

    return probe(
        host,
        port,
        stateless=True,
        timeout=CLIENTHELLO_PROBE_TIMEOUT_S,
        retries=CLIENTHELLO_PROBE_RETRIES,
    )


def _clienthello_scan(host: str, ports: list[int]) -> list[int]:
    """Ports on `host` that answered a DTLS ClientHello -- i.e. ports a real
    DTLS server is listening on (issue #211).

    smartthings-local's stateless probe sends one ClientHello and stops the
    moment the server proves itself with a HelloVerifyRequest, which per RFC
    6347 §4.2.1 the server answers *without* allocating association state. So
    this identifies the device's real port in ~1 RTT, leaves nothing behind on
    the appliance, and costs it far less than the alternative of throwing N
    full certificate handshakes at it to find out.

    The whole range goes out at once. That's safe in a way racing real
    handshakes is not: each probe is bounded by CLIENTHELLO_PROBE_TIMEOUT_S
    rather than DtlsCoapSession's 12s handshake timeout, so the pool's
    shutdown-and-wait on exit costs one probe's budget, not the sum of the
    range -- no `shutdown(wait=False)` and no losing threads left running
    behind us.
    """
    with ThreadPoolExecutor(max_workers=min(len(ports), PROBE_MAX_WORKERS)) as ex:
        results = list(ex.map(lambda port: _clienthello_probe(host, port), ports))

    live = []
    for result in results:
        if result.is_dtls_server:
            live.append(result.port)
            _LOGGER.debug("DTLS server on %s:%d (%s)", host, result.port, result)
    return _order_candidates(live)


def _scan_ports(host: str) -> _PortScan:
    """Find the device's DTLS port, preferring proof over absence of evidence.

    The ClientHello probe is authoritative when it finds something: a port
    that answered one is running a DTLS server, so exactly one port gets the
    expensive certificate handshake instead of every port the old UDP sweep
    couldn't rule out (each of which cost a full 12s handshake timeout --
    issue #211's 30-40s adds).

    It stays a *gate*, not a replacement: when it confirms nothing we fall
    back to the ICMP-based sweep, which is wrong in the opposite direction
    (it reports everything it can't rule out) and so still surfaces a device
    the probe couldn't reach -- e.g. a network path that drops our
    ClientHello outright, or an install still on smartthings-local < 0.1.2.
    Issue #192's segregated-VLAN device is the reason that fallback keeps its
    own preferred-port rescue.
    """
    try:
        advertised = _discover_advertised_secure_ports(host)
    except Exception as exc:
        _LOGGER.debug("OCF secure-port discovery unavailable (%s); using fallback range", exc)
        advertised = []

    probe_ports = list(dict.fromkeys([*PROBE_PORT_RANGE, *advertised]))
    if advertised:
        _LOGGER.debug("OCF secure port(s) advertised by %s: %s", host, advertised)

    try:
        confirmed = _clienthello_scan(host, probe_ports)
    except Exception as exc:
        _LOGGER.debug("ClientHello probe unavailable (%s); falling back to UDP sweep", exc)
        confirmed = []
    if confirmed:
        _LOGGER.debug("DTLS port(s) confirmed on %s: %s", host, confirmed)
        return _PortScan(confirmed, confirmed, advertised=tuple(advertised))

    sweep, candidates = _sweep_ports(host, PROBE_PORT_RANGE, LIVENESS_PROBE_TIMEOUT_S)
    # A same-host, token-matched OCF advertisement is stronger evidence than
    # the ICMP sweep, whose false negatives motivated the preferred-port
    # rescue in the first place. Keep advertised ports as candidates even if
    # that fallback sweep rules them out.
    candidates = list(dict.fromkeys([*advertised, *candidates]))
    # No early "nothing here" fast-fail on an empty sweep: the rescue always
    # keeps PREFERRED_PROBE_PORTS as candidates (issue #192), so a real
    # handshake attempt still happens. What the sweep saw is carried along
    # instead, and _classify_handshake_failure turns it into a message once
    # those attempts have actually failed.
    _LOGGER.debug(
        "No DTLS server confirmed on %s; sweep saw live=%s refused=%s unreachable=%s, trying %s",
        host,
        sweep.live,
        sweep.refused,
        sweep.unreachable,
        candidates,
    )
    return _PortScan(candidates, [], sweep, tuple(advertised))


# TLS alerts (RFC 5246 §7.2) that mean "I looked at your certificate and said
# no", as opposed to a protocol/cipher disagreement. decrypt_error belongs
# here: it's what a peer sends when CertificateVerify fails. These are the
# alerts an appliance sends when the CA behind the leaf isn't one it trusts --
# the single most common real setup mistake, and the one the old blanket
# "check the IP and the CA credentials" message could never call out.
_CERT_ALERTS = frozenset(
    {
        "bad_certificate",
        "unsupported_certificate",
        "certificate_revoked",
        "certificate_expired",
        "certificate_unknown",
        "unknown_ca",
        "access_denied",
        "decrypt_error",
        "certificate_required",
    }
)

# OpenSSL renders a received fatal alert into its error text as e.g.
# "tlsv1 alert unknown ca" / "sslv3 alert bad certificate", which
# DtlsCoapSession.connect() wraps in a ConnectionError. Reading it back out
# tells us what the appliance actually objected to.
#
# Deliberately not the library's diagnostic probe (stateless=False), which
# would report the alert authoritatively: that mode drives the handshake far
# enough to commit association state on the device, and an orphaned
# association is exactly what makes the *next* attempt time out (RFC 6347
# §4.2.8) -- a bad trade on a path the user is about to retry.
_ALERT_RE = re.compile(r"alert ([a-z0-9 ]+)")


def _alert_name(exc: Exception) -> str | None:
    """The TLS alert an appliance sent, if this failure carried one."""
    match = _ALERT_RE.search(str(exc).lower())
    return match.group(1).strip().replace(" ", "_") if match else None


def _classify_handshake_failure(
    host: str,
    scan: _PortScan,
    failures: list[tuple[int, Exception]],
) -> CannotConnect:
    """Turn "no port worked" into the most specific thing we can honestly say.

    In rough order of how much the evidence tells us:

    * An alert means the appliance is there, speaks DTLS, and refused us on
      purpose -- and the alert says whether it was about our certificate.
    * A confirmed DTLS port that then timed out is a device that is present
      and healthy but wouldn't finish. Usually it's still holding the session
      from a previous attempt, which clears on its own.
    * An advertised secure OCF port proves the legacy range is not the whole
      story, even if that endpoint stays silent for our handshake profile.
    * Otherwise the sweep's own shape is the evidence -- see the rules below.
    """
    alerts = [name for name in (_alert_name(exc) for _, exc in failures) if name]
    cert_alerts = [name for name in alerts if name in _CERT_ALERTS]
    if cert_alerts:
        return CertRejected(f"{host} rejected our certificate (alert {cert_alerts[0]})")
    if alerts:
        return HandshakeFailed(f"{host} refused the DTLS handshake (alert {alerts[0]})")
    if scan.confirmed:
        return HandshakeTimeout(
            f"DTLS server confirmed on {host}:{scan.confirmed} but the handshake never completed"
        )
    if scan.advertised:
        return NoDtlsServer(
            f"{host} advertised secure OCF port(s) {scan.advertised}, "
            "but none answered a DTLS handshake"
        )

    sweep = scan.swept
    if sweep is None:
        return CannotConnect(f"no port on {host} completed a handshake")
    if sweep.unreachable and not sweep.refused:
        # The kernel never got the datagrams off the host, so nothing was
        # ever asked. Reporting "ports closed" here would be exactly wrong.
        return NoResponse(f"{host} is unreachable (ports {sweep.unreachable})")
    if not sweep.live:
        # Every port answered ICMP port-unreachable: something is at that
        # address and it is not exposing the local API.
        return PortsClosed(
            f"{host} refused every port in {PROBE_PORT_RANGE[0]}-{PROBE_PORT_RANGE[-1]}"
        )
    if len(sweep.live) == len(PROBE_PORT_RANGE):
        # Not one refusal came back across a nine-port ephemeral range. A host
        # that is actually there answers for at least some of it.
        return NoResponse(f"nothing at {host} responded on any probed port")
    return NoDtlsServer(f"ports on {host} are reachable but none answered a DTLS handshake")


def _mint_credentials(ca_cert_pem: str, ca_key_pem: str) -> tuple[str, str]:
    """Fetch the current UUID from Samsung's cloud and mint a leaf cert for it."""
    _LOGGER.debug("Fetching Samsung cloud UUID from %s", _SAMSUNG_CLOUD_HOST)
    try:
        uuid = _fetch_samsung_uuid()
    except Exception as exc:
        _LOGGER.debug("UUID fetch failed: %s", exc, exc_info=True)
        raise CloudUnreachable(f"Failed to fetch Samsung UUID: {exc}") from exc
    _LOGGER.debug("Got UUID: %s", uuid)

    _LOGGER.debug("Minting leaf cert for UUID %s", uuid)
    try:
        fullchain_pem, leaf_key_pem = _mint_leaf_cert(ca_cert_pem, ca_key_pem, uuid)
    except InvalidCA:
        _LOGGER.debug("CA credentials invalid", exc_info=True)
        raise
    except Exception as exc:
        _LOGGER.debug("Leaf cert minting failed: %s", exc, exc_info=True)
        raise CannotConnect(f"Failed to mint leaf cert: {exc}") from exc
    _LOGGER.debug("Leaf cert minted successfully")
    return fullchain_pem, leaf_key_pem


def _read_device(sess, host: str, port: int) -> dict:
    """Resolve this device's identity over an already-connected session.

    /oic/d before /device/0, deliberately: the device's own OCF device-type
    declaration is the primary detection signal when a board populates it
    (see registry/by_type's resolve()), and read_identity's three small GETs
    settle it long before the blockwise /device/0 dump lands. read_identity is
    defensive on every GET it makes, so a device that answers neither /oic/p
    nor /oic/d just yields an empty device_types tuple and detection falls
    through to the model-string/resource-signature path.

    Everything the entry needs to name and key the device comes from here --
    resolved serial, model, manufacturer, device type -- so the coordinator
    never has to mint a registry key from a placeholder (issue #236).
    """
    import cbor2

    from .registry.batch import parse_device0_batch
    from .registry.by_type import resolve as resolve_registry
    from .registry.identity import read_identity, resolve_model, resolve_serial

    identity = read_identity(sess, None)

    code, payload = sess.get(["device", "0"], timeout=PROBE_GET_TIMEOUT_S)
    if code != 0x45 or not payload:
        # Authenticated fine, so this isn't a connectivity or credentials
        # problem -- whatever is on this port just isn't an appliance whose
        # /device/0 we understand.
        raise UnexpectedResponse(
            f"{host}:{port} answered /device/0 with {code >> 5}.{code & 0x1F:02d} "
            f"({code:#04x}), payload {len(payload or b'')} bytes"
        )
    body = cbor2.loads(payload)
    resources = parse_device0_batch(body) if isinstance(body, list) else {}

    info = resources.get("/information/vs/0", {})
    registry = resolve_registry(resources, device_types=identity.device_types)
    return {
        "port": port,
        # Resolved through the same helpers _run_discovery uses, so the device
        # the coordinator registers up front is the one discovery would have
        # produced -- no rename, and no re-key, once the first poll lands.
        "serial": resolve_serial(info.get("x.com.samsung.da.serialNum"), host),
        "model": resolve_model(info.get("x.com.samsung.da.modelNum", ""), identity),
        "manufacturer": identity.manufacturer or "Samsung",
        "device_type_name": registry.name if registry is not None else None,
        "device_type_recognized": registry is not None,
    }


def _handshake_and_read(host: str, scan: _PortScan, cert_pem: str, key_pem: str) -> dict:
    """Handshake each candidate in turn, returning the first device that answers."""
    from smartthings_local.protocol.dtls_session import DtlsCoapSession

    failures: list[tuple[int, Exception]] = []
    for port in scan.candidates:
        sess = None
        try:
            sess = DtlsCoapSession(host, port, cert_pem=cert_pem, key_pem=key_pem)
            sess.connect()
            sess.start_reader()
            return _read_device(sess, host, port)
        except CannotConnect:
            # The device answered, just not with something we can use --
            # trying the remaining ports can't improve on that.
            raise
        except Exception as exc:
            failures.append((port, exc))
            _LOGGER.debug("port %d failed: %s", port, exc)
        finally:
            if sess is not None:
                with contextlib.suppress(Exception):
                    sess.close()
    raise _classify_handshake_failure(host, scan, failures)


def _probe_and_validate(
    host: str,
    ca_cert_pem: str,
    ca_key_pem: str,
    existing_leaf: tuple[str, str] | None = None,
) -> dict:
    """Find the device's port, authenticate to it, and resolve its identity.

    Port detection runs first and needs no credentials at all, so an
    unreachable host fails here rather than after a round trip to Samsung's
    cloud.

    `existing_leaf` is another entry's already-minted leaf (issue #211).
    Every appliance accepts the same leaf -- CA `AC14K_M` plus the UUID from
    Samsung's cloud cert -- so adding a second device can skip the fetch and
    mint entirely, which makes it independent of Samsung-cloud reachability
    rather than merely faster. If that reused leaf turns out to be stale (the
    UUID does rotate), a confirmed-live device rejecting it is unambiguous
    enough to re-mint and try once more, so the reuse stays self-correcting.
    """
    scan = _scan_ports(host)

    if existing_leaf is not None:
        cert_pem, key_pem = existing_leaf
        _LOGGER.debug("Reusing the leaf certificate from an existing entry")
    else:
        cert_pem, key_pem = _mint_credentials(ca_cert_pem, ca_key_pem)

    try:
        info = _handshake_and_read(host, scan, cert_pem, key_pem)
    except CertRejected:
        # The only failure a fresh certificate can fix, and only worth a
        # second pass when the certificate wasn't freshly minted already.
        if existing_leaf is None:
            raise
        _LOGGER.debug("Reused leaf rejected by %s; re-minting and retrying", host)
        cert_pem, key_pem = _mint_credentials(ca_cert_pem, ca_key_pem)
        info = _handshake_and_read(host, scan, cert_pem, key_pem)

    return {**info, "leaf_cert_pem": cert_pem, "leaf_key_pem": key_pem}


class LocalThingsConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 2

    def __init__(self) -> None:
        self._host: str = ""
        self._ca_cert_pem: str = ""
        self._ca_key_pem: str = ""
        self._pending_info: dict | None = None

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> LocalThingsOptionsFlow:
        return LocalThingsOptionsFlow()

    def _create_entry(self, info: dict) -> ConfigFlowResult:
        """Persist everything the probe resolved, identity included.

        The identity fields are not decoration: the coordinator seeds
        `device_serial` and its DeviceInfo from them at construction time, so
        entity unique_ids and device identifiers are correct from the very
        first entity that registers -- even if the first poll is slow, or
        fails outright (issue #236).
        """
        from .registry.identity import device_display_name

        return self.async_create_entry(
            title=f"{device_display_name(info['device_type_name'], '')} ({self._host})",
            data={
                CONF_HOST: self._host,
                CONF_PORT: info["port"],
                CONF_CA_CERT_PEM: self._ca_cert_pem,
                CONF_CA_KEY_PEM: self._ca_key_pem,
                CONF_LEAF_CERT_PEM: info["leaf_cert_pem"],
                CONF_LEAF_KEY_PEM: info["leaf_key_pem"],
                CONF_SERIAL: info["serial"],
                CONF_MODEL: info["model"],
                CONF_MANUFACTURER: info["manufacturer"],
                CONF_DEVICE_TYPE: info["device_type_name"],
            },
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        existing = self.hass.config_entries.async_entries(DOMAIN)
        has_creds = bool(existing)

        errors: dict[str, str] = {}

        if user_input is not None:
            self._host = user_input[CONF_HOST].strip()
            existing_leaf = None
            if has_creds:
                self._ca_cert_pem = existing[0].data[CONF_CA_CERT_PEM]
                self._ca_key_pem = existing[0].data[CONF_CA_KEY_PEM]
                leaf_cert = existing[0].data.get(CONF_LEAF_CERT_PEM)
                leaf_key = existing[0].data.get(CONF_LEAF_KEY_PEM)
                if leaf_cert and leaf_key:
                    existing_leaf = (leaf_cert, leaf_key)
            else:
                self._ca_cert_pem = user_input[CONF_CA_CERT_PEM].strip()
                self._ca_key_pem = user_input[CONF_CA_KEY_PEM].strip()

            try:
                info = await self.hass.async_add_executor_job(
                    _probe_and_validate,
                    self._host,
                    self._ca_cert_pem,
                    self._ca_key_pem,
                    existing_leaf,
                )
            except (CannotConnect, InvalidCA) as exc:
                # Every probe failure carries the message that fits it (see
                # CannotConnect); the log line is where the specifics live,
                # since the messages point users at it.
                _LOGGER.warning("Probe of %s failed [%s]: %s", self._host, exc.error_key, exc)
                errors["base"] = exc.error_key
            except Exception:
                _LOGGER.exception("Unexpected error during device probe")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(f"localthings_{info['serial']}")
                self._abort_if_unique_id_configured()
                if info["device_type_recognized"]:
                    return self._create_entry(info)
                self._pending_info = info
                return await self.async_step_confirm_unknown_type()

        if has_creds:
            schema = vol.Schema({vol.Required(CONF_HOST): _TEXT})
            step_id = "user_reuse"
        else:
            schema = vol.Schema(
                {
                    vol.Required(CONF_HOST): _TEXT,
                    vol.Required(CONF_CA_CERT_PEM): _MULTILINE,
                    vol.Required(CONF_CA_KEY_PEM): _MULTILINE,
                }
            )
            step_id = "user"

        return self.async_show_form(
            step_id=step_id,
            data_schema=schema,
            errors=errors,
        )

    async def async_step_user_reuse(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the localized host-only form for additional appliances."""
        return await self.async_step_user(user_input)

    async def async_step_confirm_unknown_type(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Shown only when the probe already knows the device type is unrecognized."""
        info = self._pending_info or {}
        if user_input is not None:
            assert self._pending_info is not None
            return self._create_entry(self._pending_info)
        return self.async_show_form(
            step_id="confirm_unknown_type",
            data_schema=vol.Schema({}),
            # The probe already knows the board string detection failed on;
            # showing it here means a user filing the device-support issue
            # this step asks for can quote it without digging through logs.
            description_placeholders={"model": info.get("model") or "unknown"},
        )


class LocalThingsOptionsFlow(config_entries.OptionsFlow):
    """Per-device options: the remote-control-off write-block override
    (issue #54) plus a debug panel for writing an arbitrary body to an
    arbitrary resource href, so a user can pin down device-specific write
    behavior without waiting on a new release.

    The remote-control override exists because most devices reject writes
    outright while remote control is off and a clear error beats a silent
    device-side rejection -- but not every model actually enforces that,
    so this lets a user who's confirmed their device accepts writes anyway
    turn the block off for just that device rather than it being
    hardcoded on for everyone. The debug panel goes further: it bypasses
    that block (and every write_fn/validate_fn) entirely, sending exactly
    the body the user types to whatever href they pick.
    """

    def __init__(self) -> None:
        self._debug_href: str = ""
        self._debug_result: tuple[int, dict] | None = None

    def _coordinator(self):
        return self.hass.data.get(DOMAIN, {}).get(self.config_entry.entry_id)

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        return self.async_show_menu(
            step_id="init",
            menu_options=["settings", "debug_write"],
        )

    async def async_step_settings(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        return self.async_show_form(
            step_id="settings",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_BYPASS_REMOTE_CONTROL,
                        default=self.config_entry.options.get(CONF_BYPASS_REMOTE_CONTROL, False),
                    ): bool,
                    vol.Required(
                        CONF_FINISH_TIME_HYSTERESIS_MINUTES,
                        default=self.config_entry.options.get(
                            CONF_FINISH_TIME_HYSTERESIS_MINUTES,
                            DEFAULT_FINISH_TIME_HYSTERESIS_MINUTES,
                        ),
                    ): _HYSTERESIS_MINUTES,
                }
            ),
        )

    async def async_step_debug_write(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        coord = self._coordinator()
        if coord is None:
            return self.async_abort(reason="not_loaded")

        if user_input is not None:
            self._debug_href = user_input["href"]
            return await self.async_step_debug_edit()

        hrefs = sorted(coord.last_resources.keys())
        return self.async_show_form(
            step_id="debug_write",
            data_schema=vol.Schema(
                {
                    vol.Required("href"): SelectSelector(
                        SelectSelectorConfig(
                            options=hrefs,
                            custom_value=True,
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    ),
                }
            ),
        )

    def _show_debug_edit_form(
        self,
        href: str,
        current: dict,
        errors: dict[str, str],
        payload,
    ) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="debug_edit",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "payload",
                        default=(payload if payload is not None else {}),
                    ): ObjectSelector(),
                }
            ),
            errors=errors,
            description_placeholders={
                "href": href,
                "current_value": (
                    json.dumps(current, indent=2, ensure_ascii=False) if current else "{}"
                ),
            },
        )

    async def async_step_debug_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        coord = self._coordinator()
        if coord is None:
            return self.async_abort(reason="not_loaded")

        href = self._debug_href
        current = coord.resource(href)

        if user_input is not None:
            payload = user_input.get("payload") or {}
            if not isinstance(payload, dict) or not payload:
                return self._show_debug_edit_form(
                    href, current, {"payload": "empty_payload"}, payload
                )
            try:
                code, new_rep = await coord.async_raw_write(href, payload)
            except Exception:
                _LOGGER.exception("debug raw write failed for %s", href)
                return self._show_debug_edit_form(href, current, {"base": "write_failed"}, payload)
            self._debug_result = (code, new_rep)
            return await self.async_step_debug_result()

        return self._show_debug_edit_form(href, current, {}, None)

    async def async_step_debug_result(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        code, new_rep = self._debug_result or (0, {})
        return self.async_show_menu(
            step_id="debug_result",
            menu_options=["debug_write", "finish"],
            description_placeholders={
                "code": f"{code >> 5}.{code & 0x1F:02d} ({code:#04x})",
                "new_value": (
                    json.dumps(new_rep, indent=2, ensure_ascii=False) if new_rep else "{}"
                ),
            },
        )

    async def async_step_finish(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        # Close the flow without altering saved options.
        return self.async_create_entry(data=dict(self.config_entry.options))
