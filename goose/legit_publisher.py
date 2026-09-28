#!/usr/bin/env python3
"""GridSnare — legitimate IEC 61850 GOOSE publisher (SPEC.md Section 11).

SPEC.md Section 11 requires a legitimate (non-decoy) publisher alongside the Modbus
PLC simulator, and gives the reason: a decoy has no legitimate traffic by design
(Section 7.1), so baseline traffic aimed at one is traffic the rule set is *supposed*
to flag. It names the consequence directly — "a legitimate GOOSE publisher distinct
from the decoy IED is required for TC-8". This module is that publisher.

What it does
------------
1. **Publishes** one GOOSE control block on the lab segment, following the
   IEC 61850-8-1 publication pattern the standard defines and GR-3 measures against:
   a fast retransmission burst after a state change, decaying to a steady heartbeat.
2. **Advances the sequence correctly**, always: StNum increments on a state change and
   SqNum is reset with it and incremented on every frame within a state. That is the
   whole of GR-1's subject, so this device is the legitimate reference a sequence
   violation is judged against.
3. **Toggles the breaker position it reports** on a configurable cycle, so the state
   changes and the burst profile is exercised on the wire in plain sight. A publisher
   frozen in one state would publish one StNum forever, which would leave the fastest
   part of the timing profile untested — and it is exactly the part GR-3 is tuned
   against, so an untested profile is a false-positive risk, not a gap in coverage.

How it differs from the decoy (goose/decoy_ied.py)
--------------------------------------------------
* Identity: this device publishes its **own** control block (``GSBASE/...``), not the
  decoy's. GR-4 fires on *any* traffic referencing the decoy's GoCB from a MAC other
  than the decoy's, so publishing the decoy's block here would make every baseline
  frame a Critical finding — and a baseline that is supposed to alert measures nothing.
* GR-2's allow-list (``engine.goose.known_publishers``) names this container's MAC as
  the known publisher for this control block, so a spoofing test has something real to
  deviate from.
* No subscriber and no bait: nothing here is meant to attract or detect anything. It is
  an asset under test, not a decoy.
* It links against nothing but the library's publisher API — no receive path at all.

Scope boundary — this module implements no detection logic
----------------------------------------------------------
GR-1..GR-4 live in engine/goose_rules.py and engine/correlator.py (SPEC.md 20.3) and
are applied by the engine to what the GOOSE traffic monitor captured. This is the
*publisher* end of SPEC.md Section 9's flow, not the observer. It writes nothing to the
data store: capturing and storing GOOSE events is the traffic monitor's job (20.2), and
an asset that wrote its own event rows would be marking its own homework. It is
therefore deliberately absent from ``dashboard.expected_sources``.

Deployment notes (see docker-compose.yml)
-----------------------------------------
* Needs its own address and MAC on ``scada_net``: it injects raw Ethernet frames, and a
  container sharing another's namespace cannot be given its own MAC. The MAC is fixed in
  compose because GR-2's allow-list is keyed on it.
* Needs ``NET_RAW``, the one capability raw Ethernet injection requires.
* ``src_mac`` in config.yaml is checked against the interface's actual MAC at startup
  and the process refuses to run if they differ. A publisher that came up under a MAC
  the allow-list does not name would be flagged as a spoofer by its own rule set, and
  the baseline would be measuring the wrong device — a failure worth refusing to start
  over rather than logging.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple

import yaml

# The wire-format helpers live beside this file, so the decoy, the publisher, the GOOSE
# monitor and the lab tooling share one implementation. Resolved from __file__ because
# the container runs `python -u goose/legit_publisher.py` from /app, which puts
# /app/goose — not /app — on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from goose.goose_frame import interface_mac  # noqa: E402  (import after sys.path bootstrap)

LOG = logging.getLogger("gridsnare.goose.publisher")

DEFAULT_CONFIG_PATH = "/app/config.yaml"

# IEC 61850-8-1: GOOSE destination addresses live in 01-0C-CD-01-00-00 to
# 01-0C-CD-01-01-FF, and the GOOSE APPID range is 0x0000-0x3FFF.
GOOSE_MULTICAST_PREFIX = (0x01, 0x0C, 0xCD, 0x01)
GOOSE_APPID_MAX = 0x3FFF


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe this publisher."""


# ---------------------------------------------------------------------------
# config parsing (SPEC.md Section 8: thresholds are configuration, not code)
# ---------------------------------------------------------------------------

def _require_text(section: dict, key: str) -> str:
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"goose_publisher.{key} must be a non-empty string")
    return value.strip()


def _positive_int(section: dict, key: str) -> int:
    raw = section.get(key)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose_publisher.{key} must be an integer, got {raw!r}") from None
    if parsed <= 0:
        raise ConfigError(f"goose_publisher.{key} must be positive, got {parsed}")
    return parsed


def _non_negative_int(section: dict, key: str, default: int) -> int:
    raw = section.get(key, default)
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose_publisher.{key} must be an integer, got {raw!r}") from None
    if parsed < 0:
        raise ConfigError(f"goose_publisher.{key} must not be negative, got {parsed}")
    return parsed


def _positive_float(section: dict, key: str, default: float) -> float:
    raw = section.get(key, default)
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        raise ConfigError(f"goose_publisher.{key} must be a number, got {raw!r}") from None
    if parsed <= 0:
        raise ConfigError(f"goose_publisher.{key} must be positive, got {parsed}")
    return parsed


def parse_mac(value: Any, key: str) -> Tuple[int, int, int, int, int, int]:
    """Parse a MAC from any of the shapes config.yaml or a human might use."""
    if isinstance(value, (list, tuple)):
        octets = tuple(int(part) for part in value)
    elif isinstance(value, str):
        cleaned = value.strip().replace("-", ":").replace(".", ":")
        try:
            octets = tuple(int(part, 16) for part in cleaned.split(":"))
        except ValueError:
            raise ConfigError(f"goose_publisher.{key} is not a valid MAC: {value!r}") from None
    else:
        raise ConfigError(f"goose_publisher.{key} must be a string or list, got {value!r}")

    if len(octets) != 6 or any(not 0 <= octet <= 0xFF for octet in octets):
        raise ConfigError(f"goose_publisher.{key} must be six octets, got {value!r}")
    return octets  # type: ignore[return-value]


def format_mac(octets: Sequence[int]) -> str:
    return ":".join(f"{octet:02x}" for octet in octets)


def normalise_mac(value: str) -> str:
    """One spelling of a MAC, for comparing configuration against the interface."""
    return ":".join(f"{int(part, 16):02x}" for part in value.strip().replace("-", ":").split(":"))


def _ms_profile(section: dict) -> Tuple[int, ...]:
    raw = section.get("retransmission_profile_ms")
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ConfigError("goose_publisher.retransmission_profile_ms must be a non-empty list")
    try:
        profile = tuple(int(value) for value in raw)
    except (TypeError, ValueError):
        raise ConfigError(
            f"goose_publisher.retransmission_profile_ms must be whole milliseconds, got {raw!r}"
        ) from None
    if any(value <= 0 for value in profile):
        raise ConfigError(
            "goose_publisher.retransmission_profile_ms entries must all be positive"
        )
    return profile


@dataclass(frozen=True)
class PublisherConfig:
    """Legitimate publisher settings (SPEC.md Section 8: tunable without code changes)."""

    interface: str
    goid: str
    gocb_ref: str
    dataset_ref: str
    src_mac: str
    conf_rev: int
    app_id: int
    dst_mac: Tuple[int, int, int, int, int, int]
    vlan_id: int
    vlan_priority: int
    retransmission_profile_ms: Tuple[int, ...]
    heartbeat_seconds: float
    time_allowed_to_live_ms: int
    state_change_cycle_seconds: float
    state_hold_seconds: float
    log_level: str

    @classmethod
    def load(cls, path: str) -> "PublisherConfig":
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("goose_publisher")
        if not isinstance(section, dict):
            raise ConfigError(
                f"{config_path} must contain a 'goose_publisher:' mapping "
                "(SPEC.md Section 11)"
            )

        dst_mac = parse_mac(section.get("dst_mac"), "dst_mac")
        src_mac = normalise_mac(_require_text(section, "src_mac"))
        app_id = _positive_int(section, "app_id")
        vlan_id = _non_negative_int(section, "vlan_id", 0)
        vlan_priority = _non_negative_int(section, "vlan_priority", 4)
        profile = _ms_profile(section)
        heartbeat = _positive_float(section, "heartbeat_seconds", 2.0)
        time_allowed_to_live = _positive_int(section, "time_allowed_to_live_ms")

        # Each of these failures is silent on the wire, which is why they are checked
        # before a frame is ever sent: a destination outside the GOOSE multicast block
        # is a frame no subscriber would accept, an APPID outside the standard's range
        # is not a GOOSE APPID, and a heartbeat slower than timeAllowedToLive makes a
        # conforming subscriber time this publisher out between its own heartbeats.
        if dst_mac[:4] != GOOSE_MULTICAST_PREFIX:
            raise ConfigError(
                f"goose_publisher.dst_mac {format_mac(dst_mac)} is not a GOOSE multicast "
                f"address (must start {format_mac(GOOSE_MULTICAST_PREFIX)}; IEC 61850-8-1)"
            )
        if app_id > GOOSE_APPID_MAX:
            raise ConfigError(
                f"goose_publisher.app_id {app_id} (0x{app_id:04x}) is outside the GOOSE "
                f"APPID range 0x0000-0x{GOOSE_APPID_MAX:04x}"
            )
        if vlan_priority > 7:
            raise ConfigError(f"goose_publisher.vlan_priority must be 0-7, got {vlan_priority}")
        if vlan_id > 4095:
            raise ConfigError(f"goose_publisher.vlan_id must be 0-4095, got {vlan_id}")
        if heartbeat * 1000 >= time_allowed_to_live:
            raise ConfigError(
                f"goose_publisher.heartbeat_seconds ({heartbeat}s) must be shorter than "
                f"goose_publisher.time_allowed_to_live_ms ({time_allowed_to_live}ms), or a "
                "conforming subscriber times the publisher out between heartbeats"
            )

        cycle = _positive_float(section, "state_change_cycle_seconds", 20.0)
        hold = _positive_float(section, "state_hold_seconds", 3.0)
        if hold >= cycle:
            raise ConfigError(
                f"goose_publisher.state_hold_seconds ({hold}s) must be shorter than "
                f"goose_publisher.state_change_cycle_seconds ({cycle}s), or the breaker "
                "position never returns to where it started"
            )

        return cls(
            interface=_require_text(section, "interface"),
            goid=_require_text(section, "goid"),
            gocb_ref=_require_text(section, "gocb_ref"),
            dataset_ref=_require_text(section, "dataset_ref"),
            src_mac=src_mac,
            conf_rev=_positive_int(section, "conf_rev"),
            app_id=app_id,
            dst_mac=dst_mac,  # type: ignore[arg-type]
            vlan_id=vlan_id,
            vlan_priority=vlan_priority,
            retransmission_profile_ms=profile,
            heartbeat_seconds=heartbeat,
            time_allowed_to_live_ms=time_allowed_to_live,
            state_change_cycle_seconds=cycle,
            state_hold_seconds=hold,
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
# the publisher
# ---------------------------------------------------------------------------


class LegitPublisher:
    """A well-behaved relay: one control block, correctly sequenced, no bait."""

    def __init__(self, config: PublisherConfig) -> None:
        self.config = config
        self.publisher: Any = None
        # Present from construction so a state change can never be published before
        # the loop has installed its stop flag.
        self._stop = threading.Event()
        self._dataset: Any = None
        self._values: list = []       # keeps the MmsValues alive: the list holds pointers

        self.breaker_closed = True
        self.operations = 0
        self.frames_published = 0
        self._log_failures = 0

    # -- startup ----------------------------------------------------------

    def start(self) -> None:
        """Verify the identity, then create the publisher (fatal on failure)."""
        self._verify_identity()
        self._create_publisher()

    def _verify_identity(self) -> None:
        """Refuse to publish under a MAC the allow-list does not name.

        GR-2 identifies a publisher by (control block, source MAC), so a publisher that
        came up under a different MAC would be flagged as a spoofer by its own rule set
        and the GOOSE baseline would silently be measuring the wrong device. The MAC is
        pinned in docker-compose.yml and mirrored in config.yaml; this is the check that
        keeps the two from drifting apart without anyone noticing.
        """
        actual = interface_mac(self.config.interface)
        if actual is None:
            raise RuntimeError(
                f"cannot read the MAC of {self.config.interface} to confirm this "
                f"publisher's identity (config expects {self.config.src_mac}) — refusing "
                "to publish under an unverified source address"
            )
        if normalise_mac(actual) != self.config.src_mac:
            raise RuntimeError(
                f"{self.config.interface} has MAC {actual}, but goose_publisher.src_mac "
                f"says {self.config.src_mac} (pinned in docker-compose.yml). GR-2's "
                f"allow-list is keyed on the configured value, so publishing as {actual} "
                "would be flagged as spoofing by this lab's own rules."
            )
        LOG.info(
            "identity verified: %s is %s, the MAC engine.goose.known_publishers names "
            "for %s", self.config.interface, actual, self.config.gocb_ref,
        )

    def _create_publisher(self) -> None:
        config = self.config
        parameters = iec.CommParameters()
        parameters.appId = config.app_id
        parameters.vlanId = config.vlan_id
        parameters.vlanPriority = config.vlan_priority
        # dstAddress is a C array, so it is set through the bindings' helper rather than
        # field-by-field.
        iec.CommParameters_setDstAddress(parameters, *config.dst_mac)

        self.publisher = iec.GoosePublisher_create(parameters, config.interface)
        if self.publisher is None:
            # The library's usual reason for returning NULL here is that it could not
            # open the raw socket, so say so rather than failing later on a silent no-op
            # publish.
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

        # The dataset of a monitored breaker position: the position itself, how many
        # times it has changed, and when it last changed. Ordinary substation telemetry,
        # which is the point — nothing here is bait, so an alert on it is a genuine
        # false positive.
        closed = iec.MmsValue_newBoolean(self.breaker_closed)
        operations = iec.MmsValue_newIntegerFromInt32(self.operations)
        changed_at = iec.MmsValue_newUtcTimeByMsTime(self._now_ms())
        self._values = [closed, operations, changed_at]

        dataset = iec.LinkedList_create()
        for value in self._values:
            iec.LinkedList_add(dataset, value)
        self._dataset = dataset

        LOG.info(
            "publisher created on %s as %s: gocb=%s goid=%s appId=%d (0x%04x) dstMac=%s "
            "vlan=%s/%s confRev=%d TAL=%dms",
            config.interface, config.src_mac, config.gocb_ref, config.goid,
            config.app_id, config.app_id, format_mac(config.dst_mac),
            config.vlan_id, config.vlan_priority, config.conf_rev,
            config.time_allowed_to_live_ms,
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
            "published initial state: stNum=1 sqNum=1 breaker_closed=%s operations=%d",
            self.breaker_closed, self.operations,
        )

    def publish_state_change(self, reason: str) -> None:
        """A state change: StNum increments, SqNum resets, then the burst.

        ``GoosePublisher_increaseStNum`` increments StNum, resets SqNum and stamps the
        PDU's time field with the change time; ``GoosePublisher_publish`` then increments
        SqNum per frame. Both are the library's own semantics, so the sequence on the
        wire is whatever libiec61850 produces rather than our re-creation of it. That
        matters here more than anywhere else in this lab: this publisher is the reference
        GR-1 judges a sequence violation against, so its sequence should be the library's,
        not ours.
        """
        iec.GoosePublisher_increaseStNum(self.publisher)
        self._publish(reason)
        LOG.info(
            "state change (%s): stNum advanced, breaker_closed=%s operations=%d — burst of "
            "%d frame(s) over the configured profile",
            reason, self.breaker_closed, self.operations,
            len(self.config.retransmission_profile_ms),
        )
        for delay_ms in self.config.retransmission_profile_ms:
            if self._stop.wait(delay_ms / 1000.0):
                return
            self._publish(f"{reason} burst")

    def publish_heartbeat(self) -> None:
        self._publish("heartbeat")

    def set_breaker_closed(self, closed: bool) -> None:
        """Operate the simulated breaker. The dataset points at these objects, so
        mutating them in place is what changes what the next publish carries."""
        self.breaker_closed = closed
        self.operations += 1
        iec.MmsValue_setBoolean(self._values[0], closed)
        iec.MmsValue_setInt32(self._values[1], self.operations)
        iec.MmsValue_setUtcTimeMs(self._values[2], self._now_ms())

    # -- main loop --------------------------------------------------------

    def run(self, stop: threading.Event) -> None:
        """Publish until stopped: burst on a state change, heartbeat in between."""
        self._stop = stop
        config = self.config

        self.publish_initial()

        next_change = time.monotonic() + config.state_change_cycle_seconds
        restore_at: Optional[float] = None
        next_summary = time.monotonic() + 60.0

        while not stop.is_set():
            now = time.monotonic()

            if restore_at is not None and now >= restore_at:
                self.set_breaker_closed(True)
                self.publish_state_change("breaker restored")
                restore_at = None
                next_change = now + config.state_change_cycle_seconds
            elif restore_at is None and now >= next_change:
                self.set_breaker_closed(False)
                self.publish_state_change("breaker opened")
                restore_at = now + config.state_hold_seconds
            else:
                self.publish_heartbeat()

            if now >= next_summary:
                next_summary = now + 60.0
                LOG.info(
                    "published %d frame(s) so far (breaker_closed=%s operations=%d); %d "
                    "publish failure(s)",
                    self.frames_published, self.breaker_closed, self.operations,
                    self._log_failures,
                )

            if stop.wait(config.heartbeat_seconds):
                break

    # -- shutdown ---------------------------------------------------------

    def stop(self) -> None:
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
        description="GridSnare legitimate IEC 61850 GOOSE publisher (SPEC.md Section 11)"
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
        config = PublisherConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    LOG.info(
        "legitimate GOOSE publisher starting (SPEC.md Section 11): config=%s iface=%s "
        "gocb=%s appId=%d", args.config, config.interface, config.gocb_ref, config.app_id,
    )
    LOG.info(
        "this is a real asset for GOOSE baseline traffic to watch — it is not a decoy, it "
        "publishes a compliant sequence on the configured retransmission profile, and it "
        "writes nothing to the shared store, so TC-8's 'GR-1..GR-4 never flag it' measures "
        "the rule set rather than the absence of bait"
    )

    publisher = LegitPublisher(config)
    try:
        publisher.start()
    except RuntimeError as exc:
        LOG.error("%s", exc)
        return 1

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    # It writes no heartbeat of its own into the store — that would make it part of the
    # detection path it is supposed to be judged by — so a log line is the only evidence
    # it is working.
    try:
        publisher.run(stop)
    finally:
        publisher.stop()
        LOG.info(
            "publisher stopped: %d frame(s) published, %d publish failure(s)",
            publisher.frames_published, publisher._log_failures,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
