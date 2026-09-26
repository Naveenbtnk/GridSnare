# GridSnare honeypot log ingester — SPEC.md Section 9, step 2
#
# This image does not run Conpot. The decoy is the upstream `honeynet/conpot` image
# (untouched, see docker-compose.yml); this is the component that transcribes Conpot's
# own log into the shared store, which is a different job from being the decoy.
#
# It exists as its own image rather than being folded into the Modbus monitor because
# it shares nothing with it: no Scapy, no raw socket, no network capability. What it
# needs is read access to the decoy's log directory and write access to the store, and
# a separate image keeps that least-privilege property visible in one place.
#
# Build context is the repository root (see docker-compose.yml).

FROM python:3.12-slim

# Pinned, and the only dependency: pyyaml reads config.yaml so the log path, store path
# and decoy identity stay config-driven instead of hardcoded (SPEC.md Section 8).
RUN pip install --no-cache-dir pyyaml==6.0.3

WORKDIR /app

COPY honeypot/ /app/
# Shared with the Modbus monitor image: one raw_events schema (store.py) and one Modbus
# request decoder (modbus_codec.py), so a honeypot row and a monitor row for the same
# exchange cannot describe it differently — see each module for why.
COPY store.py /app/store.py
COPY modbus_codec.py /app/modbus_codec.py
COPY config.yaml /app/config.yaml

# -u so ingested interactions appear in `docker compose logs` as they happen.
CMD ["python", "-u", "log_ingest.py"]
