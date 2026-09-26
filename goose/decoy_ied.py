#!/usr/bin/env python3
"""GridSnare — decoy IED: an IEC 61850 GOOSE protection relay (SPEC.md Section 20.2).

SPEC.md 20.2 asks for a "fake protection relay publishing/subscribing GOOSE
messages, built on libiec61850". This module is that device. It speaks GOOSE
through the library's own ``GoosePublisher`` API rather than a hand-rolled frame
generator, so the frames on the wire are the library's encoding of a real control
block — the same bytes a MZ Automation-based relay would emit.

What it does
------------
1. **Publishes** one GOOSE control block on the lab segment, following the
   IEC 61850-8-1 publication pattern: a fast retransmission burst after a state
   change that decays to a steady heartbeat. StNum advances on every state change
   and SqNum increments within a state, which is the sequence GR-1 (Section 20.3)
   later validates.
2. **Subscribes** to a *peer* control block, the way a relay's other half waits for
   its neighbour's trip message. Nothing in this lab publishes that control block,
   which is the point: the subscriber is bait, and any frame that arrives for it
   did not come from a legitimate relay.
3. **Simulates the protection element operating** on a configurable cycle, so the
   state actually changes. A relay stuck in one state publishes a single StNum
   forever — unrealistic, and useless as bait, because StNum is the field an
   attacker has to forge to inject a trip.

Why this is the bait (and why GR-4 reads the way it does)
--------------------------------------------------------
The published identity — GoCB reference, GoID, APPID, destination MAC — is what an
attacker on the segment learns by watching, and then tries to impersonate. GR-4 in
Section 20.3 fires on "any GOOSE traffic referencing the decoy IED's GoCB", with the
rationale "decoy has no legitimate subscribers/publishers": no real device on this
segment may publish under this identity, because no real device here *is* this
relay. The decoy's own frames are the legitimate ones — they are the reference the
rest is judged against — so GR-4/GR-2 must treat this container's MAC as the known
publisher for this GoCB and everything else as an impostor.

Scope boundary — this module implements no detection logic
----------------------------------------------------------
GR-1..GR-5 live in engine/goose_rules.py and engine/correlator.py (SPEC.md 20.3),
applied by the engine against what the GOOSE traffic monitor captured. This is the
*publisher* end of Section 9's flow, not the observer. It also writes nothing to the
data store: capturing and storing GOOSE events is the traffic monitor's job (20.2),
and a decoy that wrote its own event rows would be marking its own homework.
Consequently it is deliberately NOT in ``dashboard.expected_sources`` — it publishes
no events for the dashboard to be healthy about.

What it logs about received frames is a *sighting*, not an alert. If the decoy
notices a frame claiming its own control block, that is defence-in-depth telemetry;
raising GR-4 is the engine's decision, made from the monitor's capture.

Deployment notes (see docker-compose.yml)
-----------------------------------------
* Needs its own address and MAC on ``scada_net`` — unlike the Modbus monitor, which
  borrows the honeypot's namespace. It injects raw Ethernet frames, and a container
  sharing another's namespace cannot be given its own MAC. The MAC is fixed in
  compose because GR-2's known-publisher allow-list is keyed on it; an auto-assigned
  MAC would silently change what "the legitimate publisher" means on every boot.
* Needs ``NET_RAW`` (and ``NET_ADMIN`` for the promiscuous receive path).

Publishing is the library's; receiving is ours
----------------------------------------------
The publisher goes through libiec61850. The **subscriber does not**: the library's
``GooseReceiver`` delivers nothing on this build, including for frames published by
libiec61850's own publisher in the same container, while a plain AF_PACKET socket in
the same image sees the decoy's frames.

The receive path therefore uses ``goose/goose_frame.py``: a raw AF_PACKET socket plus
this project's own BER decoder, the same code the GOOSE traffic monitor uses. It joins
the GOOSE multicast group with ``PACKET_MR_PROMISC``, which needs ``NET_RAW`` but not
``NET_ADMIN`` (the library's HAL sets interface-level ``IFF_PROMISC`` through an ioctl
whose failure is silent). SPEC.md 20.2's "publishing/subscribing" is met; the library
provides the publish half, this module the receive half.

A plain-Python receive path also avoids a shutdown crash: with the library's SWIG
director registered, CPython segfaulted during finalisation, which had forced an
``os._exit`` call. The process here exits normally.
"""

from __future__ import annotations

import argparse
import logging
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

import yaml

# The wire format lives beside this file so the decoy, the lab tooling and the GOOSE
# monitor share one implementation. Resolved from __file__ because the container runs
# `python -u goose/decoy_ied.py` from /app, which puts /app/goose — not /app — on
# sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from goose.goose_frame import (  # noqa: E402
    DecodeError,
    apply_stripped_vlan,
    decode_goose_frame,
    interface_mac,
    open_capture_socket,
    recv_frame,
)

LOG = logging.getLogger("gridsnare.goose.decoy")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# IEC 61850-8-1: GOOSE destination addresses live in 01-0C-CD-01-00-00 to
# 01-0C-CD-01-01-FF, and the GOOSE APPID range is 0x0000-0x3FFF.
GOOSE_MULTICAST_PREFIX = (0x01, 0x0C, 0xCD, 0x01)
GOOSE_APPID_MAX = 0x3FFF


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe the decoy IED."""


# ---------------------------------------------------------------------------
# config parsing (SPEC.md Section 8: thresholds are configuration, not code)
# ---------------------------------------------------------------------------


def _require_text(section: Dict[str, Any], key: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"goose.{key} must be a non-empty string")
    return value.strip()


def _positive_int(section: Dict[str, Any], key: str, default: Optional[int] = None) -> int:
    raw = section.get(key, default)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose.{key} must be an integer, got {raw!r}") from None
    if parsed <= 0:
        raise ConfigError(f"goose.{key} must be positive, got {parsed}")
    return parsed


def _non_negative_int(section: Dict[str, Any], key: str, default: int) -> int:
    raw = section.get(key, default)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose.{key} must be an integer, got {raw!r}") from None
    if parsed < 0:
        raise ConfigError(f"goose.{key} must not be negative, got {parsed}")
    return parsed


def _positive_float(section: Dict[str, Any], key: str, default: float) -> float:
    raw = section.get(key, default)
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose.{key} must be a number, got {raw!r}") from None
    if parsed <= 0:
        raise ConfigError(f"goose.{key} must be positive, got {parsed}")
    return parsed


def parse_mac(value: Any) -> Tuple[int, int, int, int, int, int]:
    """Parse a MAC from any of the shapes config.yaml or a human might use."""
    if isinstance(value, (list, tuple)):
        octets = tuple(int(part) for part in value)
    elif isinstance(value, str):
        cleaned = value.strip().replace("-", ":").replace(".", ":")
        try:
            octets = tuple(int(part, 16) for part in cleaned.split(":"))
        except ValueError:
            raise ConfigError(f"goose.dst_mac is not a valid MAC: {value!r}") from None
    else:
        raise ConfigError(f"goose.dst_mac must be a string or list, got {value!r}")

    if len(octets) != 6 or any(not 0 <= octet <= 0xFF for octet in octets):
        raise ConfigError(f"goose.dst_mac must be six octets, got {value!r}")
    return octets  # type: ignore[return-value]


def format_mac(octets: Sequence[int]) -> str:
    return ":".join(f"{octet:02x}" for octet in octets)


def _ms_profile(section: Dict[str, Any]) -> Tuple[int, ...]:
    raw = section.get("retransmission_profile_ms")
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ConfigError("goose.retransmission_profile_ms must be a non-empty list")
    try:
        profile = tuple(int(value) for value in raw)
    except (TypeError, ValueError):
        raise ConfigError(
            f"goose.retransmission_profile_ms must be whole milliseconds, got {raw!r}"
        ) from None
    if any(value <= 0 for value in profile):
        raise ConfigError("goose.retransmission_profile_ms entries must all be positive")
    return profile


@dataclass(frozen=True)
class GooseConfig:
    """Decoy IED settings (SPEC.md Section 8: tunable without touching code)."""

    interface: str
    goid: str
    gocb_ref: str
    dataset_ref: str
    subscribed_gocb_ref: str
    conf_rev: int
    app_id: int
    dst_mac: Tuple[int, int, int, int, int, int]
    vlan_id: int
    vlan_priority: int
    retransmission_profile_ms: Tuple[int, ...]
    heartbeat_seconds: float
    time_allowed_to_live_ms: int
    trip_cycle_seconds: float
    trip_hold_seconds: float
    log_level: str

    @property
    def heartbeat_ms(self) -> int:
        return int(round(self.heartbeat_seconds * 1000))

    @classmethod
    def load(cls, path: str) -> "GooseConfig":
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("goose")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'goose:' mapping (SPEC.md Section 20.2)"
            )

        dst_mac = parse_mac(section.get("dst_mac"))
        app_id = _positive_int(section, "app_id")
        vlan_id = _non_negative_int(section, "vlan_id", 0)
        vlan_priority = _non_negative_int(section, "vlan_priority", 4)
        profile = _ms_profile(section)
        heartbeat = _positive_float(section, "heartbeat_seconds", 2.0)
        time_allowed_to_live = _positive_int(section, "time_allowed_to_live_ms")

        # These four checks are the difference between a decoy that looks like a
        # relay and one that looks broken to every conforming subscriber. They are
        # validated up front because each failure is silent on the wire.
        if dst_mac[:4] != GOOSE_MULTICAST_PREFIX:
            raise ConfigError(
                f"goose.dst_mac {format_mac(dst_mac)} is not a GOOSE multicast address "
                f"(must start {format_mac(GOOSE_MULTICAST_PREFIX)}; IEC 61850-8-1)"
            )
        if app_id > GOOSE_APPID_MAX:
            raise ConfigError(
                f"goose.app_id {app_id} (0x{app_id:04x}) is outside the GOOSE APPID "
                f"range 0x0000-0x{GOOSE_APPID_MAX:04x}"
            )
        if vlan_priority > 7:
            raise ConfigError(f"goose.vlan_priority must be 0-7, got {vlan_priority}")
        if vlan_id > 4095:
            raise ConfigError(f"goose.vlan_id must be 0-4095, got {vlan_id}")

        # A subscriber times a publisher out if it hears nothing for
        # timeAllowedToLive. A heartbeat slower than that would make the decoy's own
        # legitimate frames look like a dead relay, which would then look like an
        # attack to GR-3 — so this is a correctness check, not a style preference.
        if heartbeat * 1000 >= time_allowed_to_live:
            raise ConfigError(
                f"goose.heartbeat_seconds ({heartbeat}s) must be shorter than "
                f"goose.time_allowed_to_live_ms ({time_allowed_to_live}ms), or a "
                "conforming subscriber times the publisher out between heartbeats"
            )

        trip_cycle = _positive_float(section, "trip_cycle_seconds", 30.0)
        trip_hold = _positive_float(section, "trip_hold_seconds", 4.0)
        if trip_hold >= trip_cycle:
            raise ConfigError(
                f"goose.trip_hold_seconds ({trip_hold}s) must be shorter than "
                f"goose.trip_cycle_seconds ({trip_cycle}s), or the element never resets"
            )

        return cls(
            interface=_require_text(section, "interface"),
            goid=_require_text(section, "goid"),
            gocb_ref=_require_text(section, "gocb_ref"),
            dataset_ref=_require_text(section, "dataset_ref"),
            subscribed_gocb_ref=_require_text(section, "subscribed_gocb_ref"),
            conf_rev=_positive_int(section, "conf_rev"),
            app_id=app_id,
            dst_mac=dst_mac,  # type: ignore[arg-type]
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
            retransmission_profile_ms=profile,
            heartbeat_seconds=heartbeat,
            time_allowed_to_live_ms=time_allowed_to_live,
            trip_cycle_seconds=trip_cycle,
            trip_hold_seconds=trip_hold,
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


# ---------------------------------------------------------------------------
# the library, loaded once so a missing binding is a clear error
# ---------------------------------------------------------------------------

try:
    import pyiec61850 as iec
except ImportError as exc:  # pragma: no cover - the image asserts this at build time
    iec = None  # type: ignore[assignment]
    _IMPORT_ERROR: Optional[BaseException] = exc
else:
    _IMPORT_ERROR = None


# ---------------------------------------------------------------------------
# the decoy
# ---------------------------------------------------------------------------


class DecoyIed:
    """The fake relay: one published control block, one subscribed control block."""

    def __init__(self, config: GooseConfig) -> None:
        self.config = config
        self.publisher: Any = None
        # Replaced by run(); present from construction so a state change can never
        # be published before the loop has installed its stop flag.
        self._stop = threading.Event()
        self._dataset: Any = None
        self._values: list = []          # keeps the MmsValues alive: the list holds pointers

        # Receive side: our own raw socket, not the library's (see the module
        # docstring for the measurement behind that).
        self._subscriber_socket: Optional[socket.socket] = None
        self._subscriber_thread: Optional[threading.Thread] = None
        self.own_mac: Optional[str] = None

        self.trip_position = False
        self.operation_count = 0
        self.frames_published = 0
        self.frames_heard = 0
        self.frames_echoed = 0
        self.sightings = 0
        self.subscriber_active = False
        self.last_sighting: Optional[Dict[str, Any]] = None
        self._log_failures = 0

    # -- startup ----------------------------------------------------------

    def start(self) -> None:
        """Create the publisher (fatal on failure), then the subscriber (reported)."""
        self._create_publisher()
        self._create_subscriber()

    def _create_publisher(self) -> None:
        config = self.config
        parameters = iec.CommParameters()
        parameters.appId = config.app_id
        parameters.vlanId = config.vlan_id
        parameters.vlanPriority = config.vlan_priority
        # dstAddress is a C array, so it is set through the bindings' helper rather
        # than field-by-field.
        iec.CommParameters_setDstAddress(parameters, *config.dst_mac)

        self.publisher = iec.GoosePublisher_create(parameters, config.interface)
        if self.publisher is None:
            # The library's usual reason for returning NULL here is that it could
            # not open the raw socket, so say so instead of failing later on a
            # silent no-op publish.
            raise RuntimeError(
                f"libiec61850 could not create a GOOSE publisher on {config.interface}. "
                "This needs CAP_NET_RAW (see cap_add in docker-compose.yml) and an "
                "interface that exists inside the container."
            )

        iec.GoosePublisher_setGoID(self.publisher, config.goid)
        iec.GoosePublisher_setGoCbRef(self.publisher, config.gocb_ref)
        iec.GoosePublisher_setDataSetRef(self.publisher, config.dataset_ref)
        iec.GoosePublisher_setConfRev(self.publisher, config.conf_rev)
        iec.GoosePublisher_setTimeAllowedToLive(self.publisher, config.time_allowed_to_live_ms)

        # A protection trip control block's dataset: the trip position, how many
        # times the element has operated, and the time of the last state change.
        # These are the fields a peer relay (or an attacker forging a trip) would
        # have to supply, so they are what makes the published block worth spoofing.
        trip = iec.MmsValue_newBoolean(self.trip_position)
        operations = iec.MmsValue_newIntegerFromInt32(self.operation_count)
        changed_at = iec.MmsValue_newUtcTimeByMsTime(self._now_ms())
        self._values = [trip, operations, changed_at]

        dataset = iec.LinkedList_create()
        for value in self._values:
            iec.LinkedList_add(dataset, value)
        self._dataset = dataset

        LOG.info(
            "publisher created on %s: gocb=%s goid=%s appId=%d (0x%04x) dstMac=%s "
            "vlan=%s/%s confRev=%d TAL=%dms",
            config.interface, config.gocb_ref, config.goid,
            config.app_id, config.app_id, format_mac(config.dst_mac),
            config.vlan_id, config.vlan_priority, config.conf_rev,
            config.time_allowed_to_live_ms,
        )

    def _create_subscriber(self) -> None:
        """Start listening for the peer control block on a raw socket.

        Not fatal if it fails: publishing is this device's primary function, and a
        decoy that cannot also listen is still a decoy. It is logged loudly rather
        than degraded quietly, because "listening" that silently is not listening is
        the exact failure mode this receive path replaced.
        """
        config = self.config
        try:
            sock = open_capture_socket(config.interface)
        except PermissionError:
            LOG.error(
                "GOOSE subscriber cannot open a raw socket on %s (needs CAP_NET_RAW) — "
                "the decoy will keep publishing but is NOT listening",
                config.interface,
            )
            return
        except OSError as exc:
            LOG.error(
                "GOOSE subscriber could not bind %s (%s) — the decoy will keep "
                "publishing but is NOT listening", config.interface, exc,
            )
            return

        sock.settimeout(1.0)
        self._subscriber_socket = sock
        self.own_mac = interface_mac(config.interface)
        self.subscriber_active = True
        self._subscriber_thread = threading.Thread(
            target=self._subscriber_loop, name="goose-subscriber", daemon=True
        )
        self._subscriber_thread.start()
        LOG.info(
            "subscriber listening on %s for gocb=%s as %s (no publisher exists for it "
            "in this lab, which is what makes an arrival noteworthy)",
            config.interface, config.subscribed_gocb_ref, self.own_mac or "unknown-mac",
        )

    # -- publishing -------------------------------------------------------

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    def _publish(self, reason: str) -> None:
        try:
            iec.GoosePublisher_publish(self.publisher, self._dataset)
        except Exception as exc:  # noqa: BLE001
            self._log_failures += 1
            LOG.error("publish failed (%s): %s: %s", reason, type(exc).__name__, exc)
            return
        self.frames_published += 1

    def publish_initial(self) -> None:
        """First frame of the block: StNum 1, SqNum 1 (the library resets to that)."""
        self._publish("initial")
        LOG.info(
            "published initial state: stNum=1 sqNum=1 trip=%s operations=%d",
            self.trip_position, self.operation_count,
        )

    def publish_state_change(self, reason: str) -> None:
        """A state change: StNum increments, SqNum resets, then the burst.

        ``GoosePublisher_increaseStNum`` increments StNum, resets SqNum and stamps
        the PDU's time field with the change time; ``GoosePublisher_publish`` then
        increments SqNum per frame. Both are the library's own semantics, so the
        sequence on the wire is whatever libiec61850 produces, not our re-creation
        of it.
        """
        iec.GoosePublisher_increaseStNum(self.publisher)
        self._publish(reason)
        LOG.info(
            "state change (%s): stNum advanced, trip=%s operations=%d — burst of %d frame(s)",
            reason, self.trip_position, self.operation_count,
            len(self.config.retransmission_profile_ms),
        )
        for delay_ms in self.config.retransmission_profile_ms:
            if self._stop.wait(delay_ms / 1000.0):
                return
            self._publish(f"{reason} burst")

    def publish_heartbeat(self) -> None:
        # No sqNum here on purpose: the publisher API exposes no getter, and the frame
        # this decoy sends is not visible to its own subscriber (own frames are ignored,
        # see _record_sighting), so any number printed here would be the peer's, not ours.
        self._publish("heartbeat")

    def set_trip_position(self, tripped: bool) -> None:
        """Operate or reset the simulated protection element."""
        self.trip_position = tripped
        if tripped:
            self.operation_count += 1
        # The dataset points at these objects, so mutating in place is what changes
        # what the next publish carries.
        iec.MmsValue_setBoolean(self._values[0], tripped)
        iec.MmsValue_setInt32(self._values[1], self.operation_count)
        iec.MmsValue_setUtcTimeMs(self._values[2], self._now_ms())

    # -- subscribing ------------------------------------------------------

    def _subscriber_loop(self) -> None:
        """Receive and decode GOOSE frames until stopped. Runs on its own thread."""
        sock = self._subscriber_socket
        if sock is None:      # pragma: no cover - only reachable if start() was skipped
            return

        while not self._stop.is_set():
            try:
                frame, stripped_tci = recv_frame(sock)
            except socket.timeout:
                continue
            except OSError as exc:
                # A socket closed underneath us during shutdown is expected; anything
                # else is reported and retried, so one bad frame cannot end the watch.
                if self._stop.is_set():
                    break
                LOG.warning("subscriber socket error: %s: %s", type(exc).__name__, exc)
                continue

            try:
                decoded = decode_goose_frame(frame)
            except DecodeError:
                # Not GOOSE, or too malformed to decode. Counted via frames_heard only
                # for decodable traffic; judging malformed traffic is GR-1's job in the
                # engine, working from the monitor's capture, not the decoy's.
                continue

            apply_stripped_vlan(decoded, stripped_tci)

            # Our own published frames are visible to a packet socket on this
            # interface. Filtering them here (not inside _record_sighting) keeps
            # frames_heard meaning "other devices on this segment", which is the
            # number worth watching: a decoy that only ever hears itself is
            # publishing into a void, and that is different from a quiet segment.
            #
            # Each of our frames can arrive twice (once PACKET_OUTGOING and once as
            # the kernel's own copy), so counting them would double the apparent traffic.
            if self.own_mac and decoded.get("src_mac") == self.own_mac:
                self.frames_echoed += 1
                LOG.debug("own frame echoed back (stNum=%s)", decoded.get("pdu", {}).get("st_num"))
                continue

            self.frames_heard += 1
            try:
                self._record_sighting(decoded)
            except Exception as exc:  # noqa: BLE001 - a sighting must not kill the thread
                LOG.warning(
                    "could not record a GOOSE sighting: %s: %s", type(exc).__name__, exc
                )

    def _record_sighting(self, decoded: Dict[str, Any]) -> None:
        """Classify one received GOOSE frame."""
        pdu = decoded.get("pdu", {})
        src_mac = decoded.get("src_mac")
        gocb_ref = pdu.get("gocb_ref")
        st_num = pdu.get("st_num")
        sq_num = pdu.get("sq_num")

        # Callers have already filtered this decoy's own frames (see the loop): every
        # frame reaching here came from another device on the segment, which is why a
        # GOOSE frame bearing our own GoCB is worth a warning and not a false alarm.
        self.sightings += 1
        self.last_sighting = {
            "src_mac": src_mac,
            "gocb_ref": gocb_ref,
            "st_num": st_num,
            "sq_num": sq_num,
            "app_id": decoded.get("app_id_hex"),
            "vlan": decoded.get("vlan"),
        }

        # A frame claiming our own control block means something on this segment is
        # impersonating this relay. Logged as a sighting: raising GR-4 is the engine's
        # call, made from the monitor's capture, not the decoy's own word.
        if gocb_ref == self.config.gocb_ref:
            LOG.warning(
                "SIGHTING: a GOOSE frame claims this decoy's own control block %s from "
                "%s (stNum=%s sqNum=%s) — the decoy did not send it",
                gocb_ref, src_mac, st_num, sq_num,
            )
        elif gocb_ref == self.config.subscribed_gocb_ref:
            LOG.info(
                "sighting: peer control block %s from %s stNum=%s sqNum=%s appId=%s",
                gocb_ref, src_mac, st_num, sq_num, decoded.get("app_id_hex"),
            )
        else:
            # Other relays' traffic on the segment. Not this decoy's business to log
            # loudly, but useful when working out why a subscriber sees nothing.
            LOG.debug(
                "goose traffic not addressed to this decoy: gocb=%s from %s",
                gocb_ref, src_mac,
            )

    # -- main loop --------------------------------------------------------

    def run(self, stop: threading.Event) -> None:
        """Publish until stopped: burst on state change, heartbeat in between."""
        self._stop = stop
        config = self.config

        self.publish_initial()

        next_operation = time.monotonic() + config.trip_cycle_seconds
        reset_at: Optional[float] = None
        next_summary = time.monotonic() + 60.0

        while not stop.is_set():
            now = time.monotonic()

            if reset_at is not None and now >= reset_at:
                # The element resets: a second state change, so a second burst.
                self.set_trip_position(False)
                self.publish_state_change("element reset")
                reset_at = None
                next_operation = now + config.trip_cycle_seconds
            elif reset_at is None and now >= next_operation:
                self.set_trip_position(True)
                self.publish_state_change("element operated")
                reset_at = now + config.trip_hold_seconds
            else:
                self.publish_heartbeat()

            if now >= next_summary:
                next_summary = now + 60.0
                LOG.info(
                    "published %d frame(s) so far (trip=%s operations=%d); heard %d "
                    "frame(s) from other devices (%d sighting(s)), %d publish failure(s)",
                    self.frames_published, self.trip_position, self.operation_count,
                    self.frames_heard, self.sightings, self._log_failures,
                )

            if stop.wait(config.heartbeat_seconds):
                break

    # -- shutdown ---------------------------------------------------------

    def stop(self) -> None:
        """Tear down the subscriber thread and the publisher."""
        if self._subscriber_thread is not None:
            # The thread checks the stop flag between receives, so a 1s socket timeout
            # bounds how long this can take.
            self._subscriber_thread.join(timeout=3.0)
            if self._subscriber_thread.is_alive():  # pragma: no cover - defensive
                LOG.warning("subscriber thread did not stop within 3s")
            self._subscriber_thread = None
        if self._subscriber_socket is not None:
            try:
                self._subscriber_socket.close()
            except OSError as exc:  # noqa: BLE001
                LOG.warning("could not close the subscriber socket cleanly: %s", exc)
            self._subscriber_socket = None
        if self.publisher is not None:
            try:
                iec.GoosePublisher_destroy(self.publisher)
            except Exception as exc:  # noqa: BLE001
                LOG.warning("could not destroy the GOOSE publisher cleanly: %s", exc)
            self.publisher = None


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare decoy IED — IEC 61850 GOOSE (SPEC.md Section 20.2)"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if iec is None:
        print(f"pyiec61850 is not importable: {_IMPORT_ERROR}", file=sys.stderr)
        return 3

    try:
        config = GooseConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "decoy IED starting (SPEC.md 20.2): config=%s iface=%s gocb=%s appId=%d",
        args.config, config.interface, config.gocb_ref, config.app_id,
    )

    decoy = DecoyIed(config)
    try:
        decoy.start()
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 1

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    # The decoy has no heartbeat of its own to report into the store, so a log line
    # is the only way to see it working. A publish failure is the one thing that
    # makes it useless while still looking alive.
    try:
        decoy.run(stop)
    finally:
        decoy.stop()
        LOG.info(
            "decoy stopped: %d frame(s) published (%d own echo(es) ignored), %d GOOSE "
            "frame(s) heard from other devices, %d sighting(s), %d publish failure(s)",
            decoy.frames_published, decoy.frames_echoed, decoy.frames_heard,
            decoy.sightings, decoy._log_failures,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
