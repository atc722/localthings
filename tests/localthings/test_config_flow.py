"""Tests for the localthings config flow."""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar, cast
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.localthings.const import (
    CONF_BYPASS_REMOTE_CONTROL,
    CONF_CA_CERT_PEM,
    CONF_CA_KEY_PEM,
    CONF_HOST,
    CONF_LEAF_CERT_PEM,
    CONF_PORT,
    DOMAIN,
)

from .conftest import (
    ENTRY_DATA,
    MOCK_CA_CERT_PEM,
    MOCK_CA_KEY_PEM,
    MOCK_HOST,
    MOCK_LEAF_CERT_PEM,
    MOCK_MODEL,
    MOCK_PORT,
    MOCK_SERIAL,
)


async def test_form_first_device(hass: HomeAssistant) -> None:
    """First device: form asks for host, CA cert, and CA key."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    data_schema = result["data_schema"]
    assert data_schema is not None
    assert CONF_CA_CERT_PEM in data_schema.schema
    assert CONF_CA_KEY_PEM in data_schema.schema


async def test_form_second_device_reuses_creds(hass: HomeAssistant) -> None:
    """Second device: form only asks for host; CA cert/key schema fields absent."""
    existing = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA)
    existing.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user_reuse"
    data_schema = result["data_schema"]
    assert data_schema is not None
    assert CONF_CA_CERT_PEM not in data_schema.schema
    assert CONF_CA_KEY_PEM not in data_schema.schema


async def test_successful_setup(hass: HomeAssistant, mock_probe) -> None:
    """Happy path: valid IP connects, entry created with discovered port."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_HOST] == MOCK_HOST
    assert result["data"][CONF_PORT] == MOCK_PORT
    assert result["data"][CONF_CA_CERT_PEM] == MOCK_CA_CERT_PEM


def test_order_candidates_prefers_known_ports() -> None:
    """Live ports are ordered with the historically known DTLS ports first,
    then the rest ascending."""
    from custom_components.localthings.config_flow import _order_candidates

    assert _order_candidates([49160, 49153, 49155, 49154]) == [
        49154,
        49155,
        49153,
        49160,
    ]
    assert _order_candidates([49153]) == [49153]


def test_find_live_ports_detects_silent_port(socket_enabled) -> None:
    """The UDP liveness sweep flags a bound-but-silent port as live and drops
    ports that refuse with ICMP port-unreachable.

    A bound, never-recv'd UDP socket stands in for a device that listens but
    stays silent (open|filtered), like the dishwasher in issue #13 on 49153.
    Two sibling ports are reserved then closed so loopback refuses datagrams
    to them, standing in for the closed ports the scan should discard.

    `socket_enabled` lifts pytest-socket's default block (the HA test harness
    disables real sockets); this test genuinely needs loopback UDP to exercise
    the ICMP-unreachable path.
    """
    import socket

    from custom_components.localthings.config_flow import _find_live_ports

    reserve = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(3)]
    for s in reserve:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in reserve]
    live_sock, live_port = reserve[0], ports[0]
    reserve[1].close()
    reserve[2].close()
    closed_ports = ports[1:]

    try:
        result = _find_live_ports(
            "127.0.0.1",
            [closed_ports[0], live_port, closed_ports[1]],
            0.8,
        )
    finally:
        live_sock.close()

    assert result.live == [live_port]
    # Refused, not unreachable: loopback is up and answered. That distinction
    # is what stops a wrong-but-live IP and an address with nothing on it
    # producing the same message.
    assert result.refused == sorted(closed_ports)
    assert result.unreachable == []


def test_sweep_ports_rescues_preferred_ports_the_sweep_missed(
    socket_enabled,
    monkeypatch,
) -> None:
    """Issue #192: a segregated VLAN made the ICMP-based sweep call three
    closed ports live while missing the one port (a historically confirmed
    DTLS port) that nmap showed as genuinely open|filtered. The sweep's
    verdict on a preferred port shouldn't be trusted blindly -- it must
    always come back as a candidate even if the sweep marked it dead, so the
    config flow gets a real handshake attempt against it.

    Uses an OS-assigned port monkeypatched into PREFERRED_PROBE_PORTS rather
    than the real 49154/49155, so this doesn't depend on those specific
    system ports being free on whatever machine runs the suite.
    """
    import socket

    from custom_components.localthings import config_flow
    from custom_components.localthings.config_flow import _sweep_ports

    # Bind an OS-assigned port and immediately close it, same technique
    # test_find_live_ports_detects_silent_port uses for its "closed" ports --
    # once closed, loopback refuses datagrams to it, standing in for the
    # sweep wrongly ruling out a port we have strong prior evidence for.
    reserved = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reserved.bind(("127.0.0.1", 0))
    preferred_port = reserved.getsockname()[1]
    reserved.close()
    monkeypatch.setattr(config_flow, "PREFERRED_PROBE_PORTS", [preferred_port])

    live_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    live_sock.bind(("127.0.0.1", 0))
    live_port = live_sock.getsockname()[1]

    try:
        sweep, candidates = _sweep_ports("127.0.0.1", [preferred_port, live_port], 0.8)
    finally:
        live_sock.close()

    # The sweep's own verdict stays honest -- it really didn't see the
    # preferred port -- and the rescue shows up only in the candidate list.
    assert sweep.live == [live_port]
    assert set(candidates) == {preferred_port, live_port}


def test_advertised_secure_ports_accepts_only_secure_doxm_links() -> None:
    """Discovery data must explicitly describe a secure DOXM endpoint."""
    import cbor2

    from custom_components.localthings.config_flow import _advertised_secure_ports

    payload = cbor2.dumps(
        [
            {
                "links": [
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": 49872},
                    },
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": 49872},
                    },
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": False, "port": 49901},
                    },
                    {
                        "href": "/oic/sec/pstat",
                        "rt": ["oic.r.pstat"],
                        "p": {"sec": True, "port": 49902},
                    },
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": True},
                    },
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": 65536},
                    },
                ]
            }
        ]
    )

    assert _advertised_secure_ports(payload) == [49872]
    assert _advertised_secure_ports(b"not-cbor") == []


def test_ocf_discovery_accepts_dynamic_response_source_port(
    socket_enabled,
    monkeypatch,
) -> None:
    """Samsung can receive discovery on 5683 and reply from another port."""
    import socket
    import threading

    import cbor2
    from smartthings_local.protocol.coap import TYPE_NON, build_coap, parse_coap

    from custom_components.localthings import config_flow

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listener.settimeout(1.0)
    discovery_port = listener.getsockname()[1]

    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    assert responder.getsockname()[1] != discovery_port

    monkeypatch.setattr(config_flow, "OCF_DISCOVERY_PORT", discovery_port)
    monkeypatch.setattr(config_flow, "OCF_DISCOVERY_TIMEOUT_S", 0.4)
    monkeypatch.setattr(config_flow, "OCF_DISCOVERY_RETRIES", 2)
    mids = iter((0x1001, 0x1002))
    monkeypatch.setattr(config_flow.secrets, "randbits", lambda bits: next(mids))

    payload = cbor2.dumps(
        [
            {
                "links": [
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": 49872},
                    }
                ]
            }
        ]
    )
    errors: list[Exception] = []

    def _respond() -> None:
        try:
            first_request, peer = listener.recvfrom(65535)
            _mtype, _code, first_mid, token, _options, _payload = parse_coap(first_request)
            second_request, second_peer = listener.recvfrom(65535)
            _mtype, _code, mid, second_token, _options, _payload = parse_coap(second_request)
            assert second_peer == peer
            assert first_mid != mid
            assert second_token == token

            # A response from the target host with the wrong token is ignored.
            wrong_token = bytes([token[0] ^ 0xFF, *token[1:]])
            stray = build_coap(TYPE_NON, 0x45, mid, wrong_token, [], payload)
            responder.sendto(stray, peer)

            # The valid response comes from the target host, but deliberately
            # not from the request's discovery port.
            response = build_coap(TYPE_NON, 0x45, mid, token, [], payload)
            responder.sendto(response, peer)
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=_respond)
    thread.start()
    try:
        ports = config_flow._discover_advertised_secure_ports("127.0.0.1")
    finally:
        thread.join(timeout=2.0)
        listener.close()
        responder.close()

    assert not thread.is_alive()
    assert errors == []
    assert ports == [49872]


def test_ocf_discovery_rejects_response_from_another_host(monkeypatch) -> None:
    """A valid token and payload cannot redirect scans from another IP."""
    import cbor2
    from smartthings_local.protocol.coap import TYPE_NON, build_coap

    from custom_components.localthings import config_flow

    token = b"test"
    payload = cbor2.dumps(
        [
            {
                "links": [
                    {
                        "href": "/oic/sec/doxm",
                        "rt": ["oic.r.doxm"],
                        "p": {"sec": True, "port": 49872},
                    }
                ]
            }
        ]
    )
    response = build_coap(TYPE_NON, 0x45, 0x1001, token, [], payload)

    class _FakeSocket:
        def __init__(self, *args, **kwargs):
            self.responses = [
                (response, ("192.0.2.2", 40000)),
                (response, ("192.0.2.1", 40001)),
            ]
            self.sent_to: list[tuple[str, int]] = []

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def settimeout(self, timeout):
            pass

        def sendto(self, datagram, peer):
            self.sent_to.append(peer)

        def recvfrom(self, size):
            return self.responses.pop(0)

    fake_socket = _FakeSocket()
    monkeypatch.setattr(config_flow.secrets, "token_bytes", lambda size: token)
    monkeypatch.setattr(
        config_flow.socket,
        "getaddrinfo",
        lambda host, port, **kwargs: [
            (
                config_flow.socket.AF_INET,
                config_flow.socket.SOCK_DGRAM,
                17,
                "",
                ("192.0.2.1", port),
            )
        ],
    )
    monkeypatch.setattr(config_flow.socket, "socket", lambda *args, **kwargs: fake_socket)
    monkeypatch.setattr(config_flow, "OCF_DISCOVERY_RETRIES", 1)

    ports = config_flow._discover_advertised_secure_ports("192.0.2.1")

    assert ports == [49872]
    assert fake_socket.sent_to == [("192.0.2.1", config_flow.OCF_DISCOVERY_PORT)]


def test_scan_probes_device_advertised_port(monkeypatch) -> None:
    """A secure port outside the legacy range reaches the DTLS probe."""
    from custom_components.localthings import config_flow

    monkeypatch.setattr(
        config_flow,
        "_discover_advertised_secure_ports",
        lambda host: [49872],
    )
    probed = _patch_clienthello(monkeypatch, {49872})

    def _no_sweep(host, ports, timeout):
        raise AssertionError("UDP sweep must not run once a port is confirmed")

    monkeypatch.setattr(config_flow, "_sweep_ports", _no_sweep)

    scan = config_flow._scan_ports("192.0.2.1")

    assert set(probed) == {*config_flow.PROBE_PORT_RANGE, 49872}
    assert scan.confirmed == [49872]
    assert scan.candidates == [49872]


def test_scan_keeps_advertised_port_when_clienthello_is_unavailable(monkeypatch) -> None:
    """A strong OCF advertisement survives the legacy sweep fallback."""
    from custom_components.localthings import config_flow

    monkeypatch.setattr(
        config_flow,
        "_discover_advertised_secure_ports",
        lambda host: [49872],
    )

    def _unavailable(host, ports):
        raise ImportError("probe unavailable")

    monkeypatch.setattr(config_flow, "_clienthello_scan", _unavailable)
    sweep = _sweep_result(refused=config_flow.PROBE_PORT_RANGE)
    monkeypatch.setattr(
        config_flow,
        "_sweep_ports",
        lambda host, ports, timeout: (sweep, [49154, 49155]),
    )

    scan = config_flow._scan_ports("192.0.2.1")

    assert scan.confirmed == []
    assert scan.candidates == [49872, 49154, 49155]
    assert scan.swept is sweep
    assert scan.advertised == (49872,)


WASHER_DEVICE0 = [
    {"rt": ["x.com.samsung.devcol"]},
    {
        "href": "/information/vs/0",
        "rep": {
            "x.com.samsung.da.modelNum": "DA_WM_TP1_21_COMMON|20375141|20010002001811424AA30217008A0000",  # noqa: E501
            "x.com.samsung.da.description": "DA_WM_TP1_21_COMMON_WW5000C/DC92-03495A_B048",
            "x.com.samsung.da.serialNum": "DISHWASHER-49153",
        },
    },
    {"href": "/otninformation/vs/0", "rep": {"otnStatus": "None"}},
]


class FakeSession:
    """Stand-in for DtlsCoapSession that answers /device/0 for any path.

    `reject_certs` models a device whose DTLS stack breaks the handshake off
    itself -- the library raises ConnectionError for that, as opposed to the
    TimeoutError it raises when nothing answers at all.
    """

    instances: ClassVar[list[FakeSession]] = []
    reject_certs: ClassVar[set[str]] = set()

    def __init__(self, host, port, cert_pem=None, key_pem=None, **kwargs):
        self.host, self.port, self.cert_pem = host, port, cert_pem
        FakeSession.instances.append(self)

    def connect(self):
        if self.cert_pem in FakeSession.reject_certs:
            raise ConnectionError(
                "DTLS handshake error: [('SSL routines', '', 'sslv3 alert bad certificate')]"
            )

    def start_reader(self):
        pass

    def get(self, path, timeout=15.0):
        import cbor2

        return 0x45, cbor2.dumps(WASHER_DEVICE0)

    def close(self):
        pass


@pytest.fixture
def fake_dtls(monkeypatch):
    """Wire the probe path up to FakeSession with no real network anywhere."""
    from custom_components.localthings import config_flow

    FakeSession.instances = []
    FakeSession.reject_certs = set()
    monkeypatch.setattr(config_flow, "_discover_advertised_secure_ports", lambda host: [])
    monkeypatch.setattr(config_flow, "_fetch_samsung_uuid", lambda: "test-uuid")
    monkeypatch.setattr(
        config_flow,
        "_mint_leaf_cert",
        lambda ca_cert, ca_key, uuid: ("FULLCHAIN", "LEAFKEY"),
    )
    monkeypatch.setattr(
        "smartthings_local.protocol.dtls_session.DtlsCoapSession",
        FakeSession,
    )
    return FakeSession


class _FakeProbeResult:
    def __init__(self, port, live):
        self.port, self.outcome = port, "live" if live else "dead"
        self.is_dtls_server = live

    def __repr__(self):
        return f"<ProbeResult {self.port} {self.outcome}>"


def _patch_clienthello(monkeypatch, live_ports):
    """Patch the library's ClientHello probe to report `live_ports` as DTLS."""
    from custom_components.localthings import config_flow

    calls: list[int] = []

    def _probe(host, port, **kwargs):
        calls.append(port)
        return _FakeProbeResult(port, port in live_ports)

    monkeypatch.setattr(config_flow, "_clienthello_probe", _probe)
    return calls


async def test_clienthello_probe_picks_the_confirmed_port(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """Issue #211: the stateless ClientHello probe identifies the real DTLS
    port, so exactly one port gets a full certificate handshake -- not every
    port the UDP sweep couldn't rule out, each costing 12s to time out."""
    from custom_components.localthings import config_flow

    probed = _patch_clienthello(monkeypatch, {49153})

    def _no_sweep(host, ports, timeout):
        raise AssertionError("UDP sweep must not run once a port is confirmed")

    monkeypatch.setattr(config_flow, "_find_live_ports", _no_sweep)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORT] == 49153
    # The whole range is probed (cheaply, in parallel) but only the confirmed
    # port is handed a handshake.
    assert set(probed) == set(config_flow.PROBE_PORT_RANGE)
    assert [s.port for s in FakeSession.instances] == [49153]


async def test_probe_uses_discovered_low_port(hass: HomeAssistant, monkeypatch, fake_dtls) -> None:
    """A device that only answers on 49153 — outside the historical
    49154/49155 pair — is found by the liveness sweep and its port is stored
    on the config entry (issue #13).

    The sweep is the fallback now: it runs when the ClientHello probe confirms
    nothing, which covers both a path that eats our ClientHello and an install
    still on smartthings-local < 0.1.2.
    """
    from custom_components.localthings import config_flow

    _patch_clienthello(monkeypatch, set())
    monkeypatch.setattr(
        config_flow,
        "_sweep_ports",
        lambda host, ports, timeout: (_sweep_result(live=[49153]), [49153]),
    )

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORT] == 49153


async def test_probe_falls_back_when_library_lacks_the_clienthello_probe(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """An install whose smartthings-local predates the probe still adds
    devices -- port detection degrades to the UDP sweep rather than failing."""
    from custom_components.localthings import config_flow

    def _missing(host, port, **kwargs):
        raise ImportError("no module named dtls_probe")

    monkeypatch.setattr(config_flow, "_clienthello_probe", _missing)
    monkeypatch.setattr(
        config_flow,
        "_sweep_ports",
        lambda host, ports, timeout: (_sweep_result(live=[49154]), [49154]),
    )

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_PORT] == 49154


async def test_entry_stores_resolved_identity(hass: HomeAssistant, monkeypatch, fake_dtls) -> None:
    """The probe's identity lands on the entry (issue #236), so the
    coordinator can key its device and entities before the first poll."""
    from custom_components.localthings import config_flow
    from custom_components.localthings.const import (
        CONF_DEVICE_TYPE,
        CONF_MANUFACTURER,
        CONF_MODEL,
        CONF_SERIAL,
    )

    _patch_clienthello(monkeypatch, {49154})

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_SERIAL] == "DISHWASHER-49153"
    assert result["data"][CONF_MODEL] == "DA_WM_TP1_21_COMMON"
    assert result["data"][CONF_MANUFACTURER] == "Samsung"
    assert result["data"][CONF_DEVICE_TYPE] == "washer"
    assert result["title"] == f"Samsung Washer ({MOCK_HOST})"
    assert result["result"].version == config_flow.LocalThingsConfigFlow.VERSION


async def test_second_device_reuses_the_existing_leaf(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """Adding a second appliance skips the Samsung-cloud round trip: every
    device accepts the same leaf, and the existing entry already has one
    (issue #211). That makes the add independent of cloud reachability, not
    just faster."""
    from custom_components.localthings import config_flow

    existing = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id="localthings_other")
    existing.add_to_hass(hass)
    _patch_clienthello(monkeypatch, {49154})

    def _no_cloud():
        raise AssertionError("must not contact Samsung's cloud when a leaf is available")

    monkeypatch.setattr(config_flow, "_fetch_samsung_uuid", _no_cloud)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: MOCK_HOST}
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_LEAF_CERT_PEM] == MOCK_LEAF_CERT_PEM
    assert FakeSession.instances[0].cert_pem == MOCK_LEAF_CERT_PEM


async def test_rejected_reused_leaf_is_reminted(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """The UUID behind the shared leaf does rotate. A confirmed-live device
    rejecting the reused one is unambiguous enough to mint a fresh cert and
    try again, so credential reuse stays self-correcting."""
    existing = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id="localthings_other")
    existing.add_to_hass(hass)
    _patch_clienthello(monkeypatch, {49154})
    FakeSession.reject_certs = {MOCK_LEAF_CERT_PEM}

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: MOCK_HOST}
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    # Freshly minted, and it's the fresh one that got stored.
    assert result["data"][CONF_LEAF_CERT_PEM] == "FULLCHAIN"
    assert [s.cert_pem for s in FakeSession.instances] == [MOCK_LEAF_CERT_PEM, "FULLCHAIN"]


async def test_unconfirmed_port_failure_is_not_reminted(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """A timeout means nothing answered, which a fresh certificate can't fix
    -- so the re-mint retry stays scoped to a device that proved it is there
    and broke the handshake off itself."""
    from custom_components.localthings import config_flow

    existing = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id="localthings_other")
    existing.add_to_hass(hass)
    _patch_clienthello(monkeypatch, set())
    monkeypatch.setattr(
        config_flow,
        "_sweep_ports",
        lambda host, ports, timeout: (_sweep_result(live=[49154]), [49154]),
    )

    def _timeout(self):
        raise TimeoutError("DTLS handshake timeout")

    monkeypatch.setattr(FakeSession, "connect", _timeout)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: MOCK_HOST}
    )

    assert result["type"] == FlowResultType.FORM
    errors = result["errors"]
    assert errors is not None
    assert errors["base"] == "no_dtls_server"
    assert len(FakeSession.instances) == 1


# ---------------------------------------------------------------------------
# Failure classification: one "cannot connect" used to cover all of these
# ---------------------------------------------------------------------------


def _sweep_result(live=(), refused=(), unreachable=()):
    from custom_components.localthings.config_flow import _SweepResult

    return _SweepResult(list(live), list(refused), list(unreachable))


def _scan(confirmed=(), swept=None, candidates=(49154,), advertised=()):
    from custom_components.localthings.config_flow import _PortScan

    return _PortScan(list(candidates), list(confirmed), swept, tuple(advertised))


def _openssl_alert(name: str) -> ConnectionError:
    """How the library surfaces a fatal alert received from the appliance."""
    return ConnectionError(f"DTLS handshake error: [('SSL routines', '', '{name}')]")


def test_cert_alert_is_reported_as_a_certificate_problem() -> None:
    """The single most common real setup mistake -- CA credentials that
    aren't the AC14K_M CA the appliance trusts -- used to render as "check
    the IP address is reachable and the CA credentials are correct", which
    is half wrong and gives no way to tell which half."""
    from custom_components.localthings.config_flow import (
        CertRejected,
        _classify_handshake_failure,
    )

    for alert in ("tlsv1 alert unknown ca", "sslv3 alert bad certificate"):
        err = _classify_handshake_failure(
            MOCK_HOST, _scan(confirmed=[49154]), [(49154, _openssl_alert(alert))]
        )
        assert isinstance(err, CertRejected), alert
        assert err.error_key == "cert_rejected"


def test_non_cert_alert_is_kept_distinct_from_a_cert_problem() -> None:
    """A cipher or version mismatch is also a deliberate refusal, but no
    amount of fiddling with CA credentials will fix it."""
    from custom_components.localthings.config_flow import (
        HandshakeFailed,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(confirmed=[49154]),
        [(49154, _openssl_alert("tlsv1 alert protocol version"))],
    )
    assert isinstance(err, HandshakeFailed)
    assert err.error_key == "handshake_failed"


def test_confirmed_port_that_times_out_is_reported_as_a_stuck_session() -> None:
    """The ClientHello probe proved a DTLS server is right there, so this is
    not a connectivity or credentials problem -- it's the appliance still
    holding the association from the last attempt, which clears itself."""
    from custom_components.localthings.config_flow import (
        HandshakeTimeout,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST, _scan(confirmed=[49154]), [(49154, TimeoutError("handshake timeout"))]
    )
    assert isinstance(err, HandshakeTimeout)
    assert err.error_key == "handshake_timeout"


def test_every_port_refused_is_reported_as_closed_ports() -> None:
    """ICMP port-unreachable on the whole range means the host is up and
    answering -- it just isn't exposing a local API. Cloud-only firmware and
    a wrong-but-live IP both land here."""
    from custom_components.localthings.config_flow import (
        PROBE_PORT_RANGE,
        PortsClosed,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(swept=_sweep_result(refused=PROBE_PORT_RANGE)),
        [(49154, TimeoutError("handshake timeout"))],
    )
    assert isinstance(err, PortsClosed)
    assert err.error_key == "ports_closed"


def test_advertised_port_is_not_misreported_as_legacy_ports_closed() -> None:
    """Public OCF evidence survives when its secure port stays silent."""
    from custom_components.localthings.config_flow import (
        PROBE_PORT_RANGE,
        NoDtlsServer,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(
            candidates=[49872],
            advertised=[49872],
            swept=_sweep_result(refused=PROBE_PORT_RANGE),
        ),
        [(49872, TimeoutError("handshake timeout"))],
    )

    assert isinstance(err, NoDtlsServer)
    assert err.error_key == "no_dtls_server"


def test_unreachable_host_is_not_reported_as_closed_ports() -> None:
    """A wrong IP on the local subnet never answers ARP, so the kernel fails
    every send with EHOSTUNREACH -- no port is "live", but nothing refused
    us either. Lumping that in with a genuine refusal would tell the user
    their appliance is on cloud-only firmware when in fact there is nothing
    at that address at all."""
    from custom_components.localthings.config_flow import (
        PROBE_PORT_RANGE,
        NoResponse,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(swept=_sweep_result(unreachable=PROBE_PORT_RANGE)),
        [(49154, TimeoutError("handshake timeout"))],
    )
    assert isinstance(err, NoResponse)
    assert err.error_key == "no_response"


def test_total_silence_is_reported_as_no_response() -> None:
    """Not one ICMP refusal across a nine-port ephemeral range: a host that
    is really there answers for at least some of it, so this reads as
    nothing at that address rather than as a device that won't talk."""
    from custom_components.localthings.config_flow import (
        PROBE_PORT_RANGE,
        NoResponse,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(swept=_sweep_result(live=PROBE_PORT_RANGE)),
        [(49154, TimeoutError("handshake timeout"))],
    )
    assert isinstance(err, NoResponse)
    assert err.error_key == "no_response"


def test_partially_open_range_is_reported_as_no_dtls_server() -> None:
    """Some ports answered, some refused -- something is listening at that
    address, it just isn't a DTLS appliance."""
    from custom_components.localthings.config_flow import (
        NoDtlsServer,
        _classify_handshake_failure,
    )

    err = _classify_handshake_failure(
        MOCK_HOST,
        _scan(swept=_sweep_result(live=[49154, 49155], refused=[49153])),
        [(49154, TimeoutError("timeout"))],
    )
    assert isinstance(err, NoDtlsServer)
    assert err.error_key == "no_dtls_server"


async def test_cert_rejection_surfaces_its_own_error_in_the_form(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """End to end: an appliance that rejects the certificate tells the user
    that, rather than the blanket connectivity message."""
    _patch_clienthello(monkeypatch, {49154})
    FakeSession.reject_certs = {"FULLCHAIN"}

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )

    assert result["type"] == FlowResultType.FORM
    errors = result["errors"]
    assert errors is not None
    assert errors["base"] == "cert_rejected"


async def test_unreachable_cloud_gateway_is_reported_separately(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """Minting a certificate needs Samsung's cloud once, for the UUID. Losing
    that is an internet problem on Home Assistant's side, not anything about
    the appliance or the CA credentials the old message pointed at."""
    from custom_components.localthings import config_flow

    _patch_clienthello(monkeypatch, {49154})

    def _no_cloud():
        raise OSError("Name or service not known")

    monkeypatch.setattr(config_flow, "_fetch_samsung_uuid", _no_cloud)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )

    assert result["type"] == FlowResultType.FORM
    errors = result["errors"]
    assert errors is not None
    assert errors["base"] == "cloud_unreachable"


async def test_unusable_device0_is_reported_separately(
    hass: HomeAssistant, monkeypatch, fake_dtls
) -> None:
    """Authenticating fine and then getting something we can't read is
    neither a connectivity nor a credentials problem, and saying so saves a
    user checking both."""
    _patch_clienthello(monkeypatch, {49154})
    monkeypatch.setattr(FakeSession, "get", lambda self, path, timeout=15.0: (0x84, b""))

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )

    assert result["type"] == FlowResultType.FORM
    errors = result["errors"]
    assert errors is not None
    assert errors["base"] == "unexpected_response"


def test_every_error_key_the_flow_can_raise_has_a_message() -> None:
    """A key with no catalog entry renders as the bare key in the UI, so the
    taxonomy and the strings have to stay in step."""
    import json
    from pathlib import Path

    from custom_components.localthings import config_flow

    keys = {
        cls.error_key
        for cls in vars(config_flow).values()
        if isinstance(cls, type)
        and issubclass(cls, (config_flow.CannotConnect, config_flow.InvalidCA))
    }
    keys.add("unknown")

    catalog = json.loads(
        (
            Path(__file__).parents[2]
            / "custom_components"
            / "localthings"
            / "translations"
            / "en.json"
        ).read_text()
    )["config"]["error"]

    assert keys <= set(catalog)
    # And nothing unreachable left behind in the catalog either.
    assert set(catalog) == keys


async def test_cannot_connect(hass: HomeAssistant) -> None:
    """Failed probe: form re-shown with cannot_connect error."""
    from custom_components.localthings.config_flow import CannotConnect

    with patch(
        "custom_components.localthings.config_flow._probe_and_validate",
        side_effect=CannotConnect("no port"),
    ):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_HOST: MOCK_HOST,
                CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
                CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
            },
        )
    assert result["type"] == FlowResultType.FORM
    errors = result["errors"]
    assert errors is not None
    assert errors["base"] == "cannot_connect"


async def test_recognized_type_skips_confirmation_step(hass: HomeAssistant, mock_probe) -> None:
    """A recognized device type creates the entry with no extra step."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY


async def test_unknown_type_shows_confirmation_step(
    hass: HomeAssistant, mock_probe_unknown_type
) -> None:
    """An unrecognized device type shows a confirmation step before creating the entry."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "confirm_unknown_type"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {},
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_HOST] == MOCK_HOST


async def test_unknown_type_step_description_makes_no_version_claim(
    hass: HomeAssistant, mock_probe_unknown_type
) -> None:
    """One confirmation step covers every unrecognized device. It used to be
    two, differing only in whether they blamed a missing oneUiVersion -- a
    distinction that stopped existing when detection stopped reading it."""
    import json
    import re
    from pathlib import Path

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_HOST: MOCK_HOST,
            CONF_CA_CERT_PEM: MOCK_CA_CERT_PEM,
            CONF_CA_KEY_PEM: MOCK_CA_KEY_PEM,
        },
    )
    assert result["step_id"] == "confirm_unknown_type"

    steps = json.loads(
        (
            Path(__file__).parents[2]
            / "custom_components"
            / "localthings"
            / "translations"
            / "en.json"
        ).read_text()
    )["config"]["step"]

    assert "confirm_unknown_type_no_version" not in steps
    description = steps["confirm_unknown_type"]["description"]
    assert "oneUiVersion" not in description
    # {model} is the only placeholder, and the step must supply it -- an
    # unfilled one renders as literal braces to the user.
    placeholders = re.findall(r"{(\w+)}", description)
    assert placeholders == ["model"]
    supplied = result["description_placeholders"]
    assert supplied is not None
    assert supplied["model"] == MOCK_MODEL


async def test_duplicate_device_aborted(hass: HomeAssistant, mock_probe) -> None:
    """Second add of same serial: flow aborts.

    When a device already exists the form only asks for host (CA creds are
    reused), so we only submit CONF_HOST in the second configure call.
    """
    existing = MockConfigEntry(
        domain=DOMAIN,
        data=ENTRY_DATA,
        unique_id=f"localthings_{MOCK_SERIAL}",
    )
    existing.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    # Second-device form only has CONF_HOST; CA creds are reused from existing.
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_HOST: MOCK_HOST},
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


def test_probe_marks_washer_as_recognized(monkeypatch):
    """A washer reports no oneUiVersion at all -- its consumer-model code
    must still resolve so setup doesn't warn about an unrecognized type."""

    device0 = [
        {"rt": ["x.com.samsung.devcol"]},
        {
            "href": "/information/vs/0",
            "rep": {
                "x.com.samsung.da.modelNum": "DA_WM_TP1_21_COMMON|20375141|20010002001811424AA30217008A0000",  # noqa: E501
                "x.com.samsung.da.description": "DA_WM_TP1_21_COMMON_WW5000C/DC92-03495A_B048",
                "x.com.samsung.da.serialNum": "TEST-SERIAL",
            },
        },
        {"href": "/otninformation/vs/0", "rep": {"otnStatus": "None"}},
    ]
    from custom_components.localthings.registry.batch import parse_device0_batch

    resources = parse_device0_batch(device0)

    from custom_components.localthings.registry.by_type import resolve

    assert resolve(resources) is not None


async def test_options_flow_init_shows_menu(hass: HomeAssistant) -> None:
    """The options flow's entry point is now a menu (issue #54's debug
    panel lives alongside the remote-control settings), not the settings
    form directly."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)

    assert result["type"] == FlowResultType.MENU
    assert result["step_id"] == "init"
    assert set(cast(Iterable[str], result["menu_options"])) == {"settings", "debug_write"}


async def test_options_flow_default_is_off(hass: HomeAssistant) -> None:
    """The bypass defaults to False, so devices that never touch this
    option see no change in the remote-control write block."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "settings"}
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "settings"
    data_schema = result["data_schema"]
    assert data_schema is not None
    assert data_schema({})[CONF_BYPASS_REMOTE_CONTROL] is False


async def test_options_flow_can_enable_bypass(hass: HomeAssistant) -> None:
    """Submitting the form with the toggle on stores it in entry.options,
    where coordinator.async_send_command reads it (issue #54)."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "settings"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={CONF_BYPASS_REMOTE_CONTROL: True}
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_BYPASS_REMOTE_CONTROL] is True


async def test_options_flow_reflects_previously_saved_value(hass: HomeAssistant) -> None:
    """Reopening the form shows the currently-saved choice as the default,
    not always False."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=ENTRY_DATA,
        unique_id=f"localthings_{MOCK_SERIAL}",
        options={CONF_BYPASS_REMOTE_CONTROL: True},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "settings"}
    )

    data_schema = result["data_schema"]
    assert data_schema is not None
    assert data_schema({})[CONF_BYPASS_REMOTE_CONTROL] is True


async def test_options_flow_debug_write_shows_hrefs_from_coordinator(
    hass: HomeAssistant,
    mock_coordinator_session,
) -> None:
    """The debug panel's href dropdown is populated from the live
    coordinator's cached resources, not a static list."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "debug_write"}
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "debug_write"


async def test_options_flow_debug_write_aborts_when_device_not_loaded(
    hass: HomeAssistant,
) -> None:
    """No coordinator in hass.data (device never finished loading) means
    the debug panel has nothing to write to or read from."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "debug_write"}
    )

    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "not_loaded"


async def test_options_flow_debug_edit_writes_and_shows_result(
    hass: HomeAssistant,
    mock_coordinator_session,
) -> None:
    """Picking an href, then submitting a payload, drives
    coordinator.async_raw_write and lands on the result menu with the
    device's response."""
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "debug_write"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"href": "/washer/vs/0"},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "debug_edit"

    with patch(
        "custom_components.localthings.coordinator.LocalThingsCoordinator.async_raw_write",
        return_value=(0x44, {"a": 1}),
    ):
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input={"payload": {"a": 1}},
        )

    assert result["type"] == FlowResultType.MENU
    assert result["step_id"] == "debug_result"
    description_placeholders = result["description_placeholders"]
    assert description_placeholders is not None
    assert description_placeholders["code"] == "2.04 (0x44)"


async def test_options_flow_debug_edit_rejects_empty_payload(
    hass: HomeAssistant,
    mock_coordinator_session,
) -> None:
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=f"localthings_{MOCK_SERIAL}")
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "debug_write"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"href": "/washer/vs/0"},
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"payload": {}},
    )

    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "debug_edit"
    assert result["errors"] == {"payload": "empty_payload"}


async def test_options_flow_finish_preserves_existing_options(
    hass: HomeAssistant,
    mock_coordinator_session,
) -> None:
    """Finishing from the debug-result menu must not clobber a previously
    saved remote-control bypass setting."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=ENTRY_DATA,
        unique_id=f"localthings_{MOCK_SERIAL}",
        options={CONF_BYPASS_REMOTE_CONTROL: True},
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "debug_write"}
    )
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"href": "/washer/vs/0"},
    )
    with patch(
        "custom_components.localthings.coordinator.LocalThingsCoordinator.async_raw_write",
        return_value=(0x44, {"a": 1}),
    ):
        result = await hass.config_entries.options.async_configure(
            result["flow_id"],
            user_input={"payload": {"a": 1}},
        )
    assert result["type"] == FlowResultType.MENU
    assert result["step_id"] == "debug_result"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"next_step_id": "finish"}
    )

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_BYPASS_REMOTE_CONTROL] is True


def test_is_placeholder_serial_catches_nothing_svc():
    """Issue #83: the ARTIK051_DONGLE_REF firmware family reports the
    literal string 'Nothing(SVC)' as serialNum on every unit -- non-empty,
    so it must be caught by name, not by the plain `if not serial` check."""
    from custom_components.localthings.registry.identity import is_placeholder_serial

    assert is_placeholder_serial("Nothing(SVC)") is True
    assert is_placeholder_serial("nothing(svc)") is True
    assert is_placeholder_serial("  Nothing(SVC)  ") is True


def test_is_placeholder_serial_accepts_real_serials():
    from custom_components.localthings.registry.identity import is_placeholder_serial

    assert is_placeholder_serial("0A1B2C3D4E5F") is False
    assert is_placeholder_serial("") is False


def test_is_placeholder_serial_catches_all_same_hex_digit():
    """Issue #189: the DA_WM_A51_20_COMMON (ARTIK051) laundry board family
    reports a flash-unset sentinel instead of 'Nothing(SVC)' -- every
    character the same repeated hex digit. A washer and a dryer, two
    different physical units, both reported the literal serialNum
    'FFFFFFFFFFFFFFF', colliding on the config-entry unique_id."""
    from custom_components.localthings.registry.identity import is_placeholder_serial

    assert is_placeholder_serial("FFFFFFFFFFFFFFF") is True
    assert is_placeholder_serial("ffffffffffffffff") is True
    assert is_placeholder_serial("00000000") is True
    # Too short to be the flash-unset sentinel -- a real serial could
    # plausibly repeat one hex digit seven times by chance.
    assert is_placeholder_serial("FFFFFFF") is False


def test_resolve_serial_falls_back_to_host():
    """Both sides of the identity -- the config flow's probe and the
    coordinator's first poll -- now resolve a serial through one function, so
    they cannot disagree about what a device is called. They used to: the
    flow fell back to `host:port` and the coordinator to `host`."""
    from custom_components.localthings.registry.identity import resolve_serial

    assert resolve_serial("REAL-SERIAL", "10.0.0.5") == "REAL-SERIAL"
    assert resolve_serial("  REAL-SERIAL  ", "10.0.0.5") == "REAL-SERIAL"
    assert resolve_serial("Nothing(SVC)", "10.0.0.5") == "10.0.0.5"
    assert resolve_serial("", "10.0.0.5") == "10.0.0.5"
    assert resolve_serial(None, "10.0.0.5") == "10.0.0.5"
