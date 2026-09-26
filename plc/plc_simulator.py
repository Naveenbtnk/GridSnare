#!/usr/bin/env python3
"""GridSnare — legitimate Modbus PLC simulator (SPEC.md Section 11).

SPEC.md Section 11 makes this a **required** lab component: the honeypot has no
legitimate traffic by design (Section 7.1), so "baseline traffic" sent at the honeypot
instead of a real asset is not a valid no-false-positive test — it is traffic the
honeypot is correctly supposed to flag. Baseline traffic needs a real asset to talk to.

This is a plain, well-behaved Modbus/TCP server: it serves the address space the
baseline reads, accepts writes, answers unsupported function codes with a standard
exception, and records nothing. It is deliberately *not* a decoy — no bait values, no
permissive answers, no logging of who talked to it, and it shares nothing with Conpot
but the Modbus protocol.

What it is not
--------------
It is not part of the detection path. Nothing here writes to the store, and the
engine has no rule that knows this service exists. Its only job is to give the
baseline pattern somewhere legitimate to go, so that "no false positives" means
something. If TC-2 ever alerts while this is running, the alert is a genuine
false positive and not an artefact of traffic aimed at a decoy.

Datastore addressing (a trap in pymodbus 3.x)
---------------------------------------------
``ModbusSequentialDataBlock(address, values)`` stores ``SimData(address - 1, ...)``,
so the block is **1-based**: passing ``0`` raises ``TypeError: 0 <= address < 65535``
from pymodbus's own validation, and ``1`` is what serves our 0-based register 0. With
address 1, a request for holding register 0 returns the first value supplied.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import yaml
from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import ModbusTcpServer

LOG = logging.getLogger("gridsnare.plc")

DEFAULT_CONFIG_PATH = "/app/config.yaml"


class ConfigError(Exception):
    """Raised when config.yaml is missing or does not describe the PLC."""


@dataclass(frozen=True)
class PlcConfig:
    """PLC settings read from config.yaml (SPEC.md Section 8: no hardcoding)."""

    bind: str
    port: int
    address_space: int
    holding_register_base: int
    input_register_base: int
    log_level: str

    @classmethod
    def load(cls, path: str) -> "PlcConfig":
        """Load and validate the 'plc:' section. Fails loudly, never silently.

        A simulator that started on the wrong port would make TC-2 look like a pass
        while measuring nothing.
        """
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"config file not found: {config_path}")
        try:
            document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{config_path} is not valid YAML: {exc}") from exc

        section = document.get("plc")
        if not isinstance(section, dict):
            raise ConfigError(f"{config_path} must contain a 'plc:' mapping (SPEC.md Section 11)")

        def integer(key: str, default: int, low: int, high: int) -> int:
            raw = section.get(key, default)
            try:
                value = int(raw)
            except (TypeError, ValueError) as exc:
                raise ConfigError(f"plc.{key} must be an integer, got {raw!r}") from exc
            if not low <= value <= high:
                raise ConfigError(f"plc.{key} must be between {low} and {high}, got {value}")
            return value

        bind = section.get("bind", "0.0.0.0")
        if not isinstance(bind, str) or not bind.strip():
            raise ConfigError("plc.bind must be a non-empty address")

        return cls(
            bind=bind,
            port=integer("port", 502, 1, 65535),
            address_space=integer("address_space", 100, 1, 65535),
            holding_register_base=integer("holding_register_base", 1000, 0, 65535),
            input_register_base=integer("input_register_base", 2000, 0, 65535),
            log_level=str(section.get("log_level") or "INFO").upper(),
        )


def build_context(config: PlcConfig) -> ModbusServerContext:
    """Build the datastore this PLC serves.

    The values are fixture data, chosen to be obviously simulated rather than
    measurements of anything: a ramp in the holding registers, a different ramp in
    the input registers, alternating coils. They are deterministic so a test can
    assert on what came back without guessing.

    Address space is config-driven and must cover what the baseline pattern reads —
    `plc.address_space` is validated against nothing here, but a baseline read past
    its end gets a standard "illegal data address" exception, which would show up in
    TC-2's output as replies rather than as alerts. TC-2 prints every reply.

    `ModbusSequentialDataBlock` is 1-based (see the module docstring): address 1
    serves our 0-based register 0.
    """
    size = config.address_space
    holding = [config.holding_register_base + index for index in range(size)]
    inputs = [config.input_register_base + index for index in range(size)]
    coils = [index % 2 for index in range(size)]

    device = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(1, [0] * size),
        co=ModbusSequentialDataBlock(1, coils),
        hr=ModbusSequentialDataBlock(1, holding),
        ir=ModbusSequentialDataBlock(1, inputs),
    )
    # single=True: one device answers every unit id, which is what a plain simulator
    # is. Pinning a unit id here would imply the PLC enforces one, and it does not.
    return ModbusServerContext(devices=device, single=True)


async def _serve_until_stopped(config: PlcConfig, stop: threading.Event) -> None:
    """Serve Modbus/TCP until `stop` is set.

    The server object has to be built **inside** a running event loop:
    ``ModbusTcpServer.__init__`` calls ``asyncio.get_running_loop()``, so constructing it
    from plain synchronous code raises ``RuntimeError: no running event loop``. The loop
    is therefore entered in ``serve()`` below rather than the constructor being called
    directly.

    ``background=True`` is what makes a clean shutdown possible: it starts the listener
    and returns, leaving this coroutine free to watch for the stop flag. Without it the
    call blocks for the life of the server and there is nothing left to shut down.
    """
    context = build_context(config)
    server = ModbusTcpServer(context, address=(config.bind, config.port))
    await server.serve_forever(background=True)
    try:
        while not stop.is_set():
            # Polled rather than awaited: a threading.Event cannot be awaited, and keeping
            # the SIGTERM handler a plain signal handler is worth the poll. The interval
            # is idle cost only — four wake-ups a second with no traffic.
            await asyncio.sleep(0.25)
    finally:
        await server.shutdown()
        LOG.info("PLC simulator stopped")


def serve(config: PlcConfig, stop: threading.Event) -> int:
    """Run the Modbus/TCP server until `stop` is set. Returns a process exit code."""
    LOG.info(
        "legitimate PLC simulator starting (SPEC.md Section 11): listening on %s:%d, "
        "serving %d holding register(s) from %d, %d input register(s) from %d, %d coil(s)",
        config.bind, config.port, config.address_space, config.holding_register_base,
        config.address_space, config.input_register_base, config.address_space,
    )
    LOG.info(
        "this is a real asset for baseline traffic to target — it is not a decoy and "
        "writes nothing to the shared store, so TC-2's 'no false positives' measures "
        "the rule set rather than the absence of honeypot rows"
    )

    # `serve_forever` raises RuntimeError("Could not start listen") if the port cannot be
    # bound, so a bind conflict surfaces as a non-zero exit with a traceback rather than
    # as a container that looks alive and refuses every request.
    asyncio.run(_serve_until_stopped(config, stop))
    return 0


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GridSnare legitimate Modbus PLC simulator (SPEC.md Section 11)"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"path to config.yaml (default: {DEFAULT_CONFIG_PATH})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    try:
        config = PlcConfig.load(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    stop = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        LOG.info("received %s, shutting down", signal.Signals(signum).name)
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    return serve(config, stop)


if __name__ == "__main__":
    sys.exit(main())
