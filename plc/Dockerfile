# GridSnare legitimate Modbus PLC simulator — SPEC.md Section 11
#
# A required lab component (Section 11): baseline traffic must target a real asset,
# because the honeypot has no legitimate traffic by design (Section 7.1). This is the
# asset. It runs upstream pymodbus rather than a hand-rolled server so the "expected"
# traffic in TC-2 is answered by a real Modbus implementation, not by more code of ours
# — otherwise a bug in our own server could look like a false positive (or hide one).
#
# Deliberately minimal: no store mount, no network capability, no config beyond its own
# bind/port and fixture data. It is an asset under test, not a component of the
# detection path.
#
# Build context is the repository root (see docker-compose.yml).

FROM python:3.12-slim

#   pymodbus - the Modbus/TCP server itself
#   pyyaml   - reads config.yaml so bind/port stay config-driven (SPEC.md Section 8)
#
# Pinned. Note: pymodbus 3.15 logs a deprecation notice for ModbusServerContext at
# startup ("_will be removed in v4 ... convert to SimData/SimDevice"). The classic
# datastore API is still supported in 3.15 and is what the documentation and every
# example use, so the simulator stays on it and the notice is expected output rather
# than a fault. Moving to SimData/SimDevice is a v4 migration, not a fix.
RUN pip install --no-cache-dir pymodbus==3.15.0 pyyaml==6.0.3

WORKDIR /app

COPY plc/ /app/
COPY config.yaml /app/config.yaml

# -u so the startup line and any shutdown line appear in `docker compose logs` live.
CMD ["python", "-u", "plc_simulator.py"]
