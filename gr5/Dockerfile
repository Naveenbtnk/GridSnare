# GridSnare GR-5 runner — SWaT autoencoder training, evaluation and replay.
#
# SPEC.md 20.3 (GR-5) and the README's "Real-world validation" section.
#
# Why this image exists, and why it is not one of the lab's services:
#
# GR-5's evaluation is an offline batch job — it reads a ~400 MB CSV pair, trains for
# 40 epochs and then writes a bounded sample of its flagged rows into the shared
# store. It is not part of the running lab, so it lives behind the `gr5` Compose
# profile and is never started by `docker compose up`.
#
# But it does have to run *inside* a container, for a reason this repository learned
# the hard way. The numbers it publishes come from writing rows into the shared
# SQLite store while the stack holds that same database open read-write, and on the
# host the store was reached across the Docker Desktop filesystem share — the
# arrangement that produced the `database is locked` incidents and poisoned the file
# once. Running the script on the host while the stack is up is therefore not allowed;
# inside a container it is just another writer on the same Linux filesystem as every
# other service, which is the case SQLite is built for.
#
# PyTorch comes from the CPU wheel index on purpose: this lab has no GPU and the model
# is 51 -> 32 -> 16 -> 32 -> 51, a few thousand parameters, so the default CUDA build
# would add roughly 2 GB of image for hardware the model cannot use.

FROM python:3.12-slim

# torch first, from the CPU index, then the rest of the pinned requirements. The
# second install honours the same ">=2.0" pin without reinstalling torch, because an
# installed 2.x.x+cpu already satisfies it (PEP 440 ignores the local version tag in
# comparisons) — so numpy comes from PyPI and the CUDA wheels never appear.
COPY requirements-gr5.txt /tmp/requirements-gr5.txt
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install --no-cache-dir -r /tmp/requirements-gr5.txt

# Paths in the runner and in engine/autoencoder.py are relative to the repository root
# (`data/swat/normal.csv`, `data/autoencoder.pt`, `data/events.db`), so the image's
# working directory is what makes the defaults correct rather than what overrides them.
WORKDIR /app

# engine/ is the GR-5 implementation and store.py is part of its import chain:
# persist_flagged imports the alerts schema from engine.correlator and opens the store
# through store.py, so the rows a run writes are the same schema the running engine
# reads. The whole engine package comes along rather than just autoencoder.py, because
# those two imports are how the replay stays in step with the live detection path.
COPY engine/ /app/engine/
COPY store.py /app/store.py
COPY scripts/ /app/scripts/

# The container path is unchanged from config.yaml's `/app/data/...`; docker-compose.yml
# is what decides which host storage backs it (the named volume `data`, with
# data/swat and data/autoencoder.pt bind-mounted back over it from ./data).
#
# The preflight turns the one failure this mount shape can produce into a sentence
# rather than a traceback. `data/autoencoder.pt` is gitignored, so a fresh clone does
# not have it; if the file is missing when Docker sets up the bind mount, Docker
# creates a *directory* at that path instead, and the save at the end of a 20-minute
# training run then dies with IsADirectoryError. Saying so up front costs nothing;
# re-running the whole thing to find out does not.
CMD ["sh", "-c", "if [ -d data/autoencoder.pt ]; then echo 'ERROR: data/autoencoder.pt is a directory, not a file (created by Docker because the host path was missing). It is a gitignored artefact: run `touch data/autoencoder.pt` in the repository root and start this container again.' >&2; exit 2; fi; exec python scripts/train_autoencoder.py"]
