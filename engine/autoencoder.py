#!/usr/bin/env python3
"""GridSnare GR-5 anomaly detector — reconstruction-error autoencoder (SPEC.md 20.3).

GR-5 (SPEC.md 20.3, stretch) scores traffic with an unsupervised PyTorch
autoencoder and flags samples whose reconstruction error exceeds a trained
threshold. This module implements the SWaT-based variant: it trains on the
numeric sensor/actuator columns of the SWaT normal operation capture, calibrates
a threshold on a held-out split of that capture, and scores the attack capture.

Pipeline
--------
1. ``load_swat_csv``   — numeric features, timestamps and labels from a SWaT CSV.
2. ``impute_features`` / ``FeatureScaler`` — fill missing values with training
   column medians and standardise with the training mean/standard deviation.
3. ``train_autoencoder`` — a small fully connected autoencoder.
4. ``calibrate_threshold`` — the score quantile that yields the target false
   positive rate on the held-out normal split.
5. ``reconstruction_errors`` / ``severity_for`` — score new rows and grade them.
6. ``persist_flagged`` — write flagged rows to ``raw_events`` and a matching
   GR-5 ``alerts`` row carrying the graded severity.

The model input is the 51 numeric sensor/actuator columns. ``Timestamp`` and the
``Normal/Attack`` label are dropped. Column scaling, the imputation medians and
the threshold are stored alongside the weights so inference is reproducible.

This module implements no rule-engine logic: it writes its own GR-5 rows and
alerts directly, keyed on ``source='swat_replay'``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

LOG = logging.getLogger("gridsnare.engine.autoencoder")

TIMESTAMP_COLUMN = "Timestamp"
LABEL_COLUMN = "Normal/Attack"
SWAT_TIMESTAMP_FORMAT = "%d/%m/%Y %I:%M:%S %p"

# raw_events identities for the replayed SWaT rows (SPEC.md Section 20.3).
SOURCE = "swat_replay"
PROTOCOL = "modbus"
RULE_ID = "GR-5"

# Severity graded by reconstruction error relative to the calibrated threshold.
CRITICAL_RATIO = 6.0
HIGH_RATIO = 3.0
MEDIUM_RATIO = 1.5

DEFAULT_MODEL_PATH = "data/autoencoder.pt"

# Cap on flagged rows written to the shared store per run. The full flagged set
# can be tens of thousands, and on a bind-mounted store that backlog leaves the
# detection engine hours behind, so only a bounded sample is replayed.
DEFAULT_MAX_STORE_ROWS = 100


class AutoencoderError(Exception):
    """Raised when the model file or the SWaT input is unusable."""


@dataclass
class SwatData:
    """One SWaT capture: features plus the metadata needed to report on them."""

    features: np.ndarray          # (n, n_features) float32, NaN where missing
    timestamps: List[str]         # raw "d/m/Y H:M:S AM" strings
    labels: List[str]             # 'Normal' | 'Attack'
    feature_names: List[str]

    @property
    def n_features(self) -> int:
        return int(self.features.shape[1])


def load_swat_csv(path: str, max_rows: Optional[int] = None) -> SwatData:
    """Load numeric features, timestamps and labels from a SWaT CSV.

    Features are read with ``numpy.genfromtxt`` (blank cells become NaN);
    timestamps and labels come from a single lightweight text pass, so the file
    is not parsed twice at full cost. ``Timestamp`` and ``Normal/Attack`` are
    excluded from the feature matrix.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        raise AutoencoderError(f"SWaT capture not found: {csv_path}")

    with csv_path.open("r", encoding="utf-8") as handle:
        header = [column.strip() for column in handle.readline().split(",")]
    if TIMESTAMP_COLUMN not in header or LABEL_COLUMN not in header:
        raise AutoencoderError(
            f"{csv_path} does not look like a SWaT capture: expected "
            f"{TIMESTAMP_COLUMN!r} and {LABEL_COLUMN!r} columns, got {header}"
        )

    timestamp_index = header.index(TIMESTAMP_COLUMN)
    label_index = header.index(LABEL_COLUMN)
    numeric_indices = [
        index for index in range(len(header))
        if index not in (timestamp_index, label_index)
    ]
    feature_names = [header[index] for index in numeric_indices]

    load_kwargs: Dict[str, Any] = {
        "delimiter": ",",
        "skip_header": 1,
        "usecols": numeric_indices,
        "dtype": np.float32,
        "missing_values": "",
        "filling_values": np.nan,
    }
    if max_rows is not None:
        load_kwargs["max_rows"] = max_rows
    features = np.genfromtxt(csv_path, **load_kwargs)
    if features.ndim == 1:
        features = features.reshape(1, -1)

    timestamps: List[str] = []
    labels: List[str] = []
    with csv_path.open("r", encoding="utf-8") as handle:
        handle.readline()  # header
        for line_number, line in enumerate(handle):
            if max_rows is not None and line_number >= max_rows:
                break
            # The timestamp is the first field and the label the last; neither
            # contains a comma, so a split/rsplit pair is safe.
            timestamp, remainder = line.split(",", 1)
            timestamps.append(timestamp.strip())
            labels.append(remainder.rsplit(",", 1)[-1].strip())

    if len(timestamps) != features.shape[0]:
        raise AutoencoderError(
            f"{csv_path}: parsed {features.shape[0]} feature row(s) but "
            f"{len(timestamps)} metadata row(s)"
        )

    LOG.info(
        "loaded %s: %d row(s), %d numeric column(s)",
        csv_path, features.shape[0], features.shape[1],
    )
    return SwatData(features, timestamps, labels, feature_names)


def column_medians(features: np.ndarray) -> np.ndarray:
    """Per-column median, ignoring NaN. Columns that are entirely NaN map to 0."""
    with np.errstate(all="ignore"):
        medians = np.nanmedian(features, axis=0)
    return np.nan_to_num(medians, nan=0.0).astype(np.float32)


def impute_features(features: np.ndarray, medians: np.ndarray) -> np.ndarray:
    """Replace NaN cells with the corresponding column median."""
    filled = np.array(features, dtype=np.float32, copy=True)
    missing = np.isnan(filled)
    if missing.any():
        filled[missing] = np.take(medians, np.where(missing)[1])
    return filled


@dataclass
class FeatureScaler:
    """Standardisation learned on the training split."""

    mean: np.ndarray
    scale: np.ndarray

    @classmethod
    def fit(cls, train_features: np.ndarray) -> "FeatureScaler":
        mean = train_features.mean(axis=0).astype(np.float32)
        scale = train_features.std(axis=0).astype(np.float32)
        # A constant column has zero scale; dividing by it would produce NaN, so
        # leave it at 1 and let the column standardise to zero offset.
        scale = np.where(scale == 0.0, 1.0, scale).astype(np.float32)
        return cls(mean=mean, scale=scale)

    def transform(self, features: np.ndarray) -> np.ndarray:
        return ((features - self.mean) / self.scale).astype(np.float32)


class Autoencoder(nn.Module):
    """Fully connected 3-layer autoencoder: input -> 32 -> 16 -> 32 -> input."""

    def __init__(self, n_features: int) -> None:
        super().__init__()
        self.n_features = n_features
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, n_features),
        )

    def forward(self, batch: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(batch))


@dataclass
class TrainingHistory:
    """Per-epoch losses, kept for the loss-curve summary."""

    train_losses: List[float] = field(default_factory=list)
    val_losses: List[float] = field(default_factory=list)

    def summary(self) -> str:
        if not self.train_losses:
            return "no epochs recorded"
        best = min(self.val_losses)
        best_epoch = self.val_losses.index(best) + 1
        reduction = (
            100.0 * (self.train_losses[0] - self.train_losses[-1]) / self.train_losses[0]
            if self.train_losses[0]
            else 0.0
        )
        return (
            f"{len(self.train_losses)} epoch(s); train MSE "
            f"{self.train_losses[0]:.6f} -> {self.train_losses[-1]:.6f} "
            f"({reduction:.1f}% reduction); best val MSE {best:.6f} at epoch {best_epoch}"
        )


def train_autoencoder(
    train_features: np.ndarray,
    val_features: np.ndarray,
    epochs: int = 40,
    batch_size: int = 1024,
    learning_rate: float = 1e-3,
    seed: int = 42,
    logger: logging.Logger = LOG,
) -> Tuple[Autoencoder, TrainingHistory]:
    """Train the autoencoder and return it with its loss history.

    Inputs are already imputed and standardised.
    """
    torch.manual_seed(seed)
    model = Autoencoder(train_features.shape[1])
    optimiser = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(train_features))
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    val_tensor = torch.from_numpy(val_features)
    history = TrainingHistory()

    for epoch in range(1, epochs + 1):
        model.train()
        running = 0.0
        seen = 0
        for (batch,) in loader:
            optimiser.zero_grad()
            reconstruction = model(batch)
            loss = loss_fn(reconstruction, batch)
            loss.backward()
            optimiser.step()
            running += float(loss.item()) * batch.shape[0]
            seen += int(batch.shape[0])

        train_loss = running / max(seen, 1)
        val_loss = float(reconstruction_errors(model, val_features).mean())
        history.train_losses.append(train_loss)
        history.val_losses.append(val_loss)
        logger.info(
            "epoch %d/%d train_mse=%.6f val_mse=%.6f", epoch, epochs, train_loss, val_loss
        )

    return model, history


def reconstruction_errors(
    model: Autoencoder, features: np.ndarray, batch_size: int = 8192
) -> np.ndarray:
    """Per-row mean squared reconstruction error (the anomaly score)."""
    model.eval()
    errors = np.empty(features.shape[0], dtype=np.float64)
    with torch.no_grad():
        for start in range(0, features.shape[0], batch_size):
            batch = torch.from_numpy(features[start:start + batch_size])
            reconstruction = model(batch)
            squared = ((reconstruction - batch) ** 2).mean(dim=1)
            errors[start:start + batch.shape[0]] = squared.numpy()
    return errors


def calibrate_threshold(val_errors: np.ndarray, target_fpr: float = 0.05) -> float:
    """Score threshold whose validation false-positive rate is at most ``target_fpr``."""
    if not 0.0 < target_fpr < 1.0:
        raise AutoencoderError(f"target_fpr must be in (0, 1), got {target_fpr}")
    if val_errors.size == 0:
        raise AutoencoderError("cannot calibrate a threshold from zero validation rows")
    return float(np.quantile(val_errors, 1.0 - target_fpr))


def severity_for(ratio: float) -> str:
    """Grade a flagged row by how far its score exceeds the threshold."""
    if ratio >= CRITICAL_RATIO:
        return "Critical"
    if ratio >= HIGH_RATIO:
        return "High"
    if ratio >= MEDIUM_RATIO:
        return "Medium"
    return "Low"


def parse_swat_timestamp(value: str) -> str:
    """Convert a SWaT timestamp to ISO-8601 UTC, or return it unchanged.

    SWaT timestamps carry no timezone; they are treated as UTC so they are
    comparable with the rest of ``raw_events`` (the same basis the lab uses).
    """
    try:
        moment = datetime.strptime(value.strip(), SWAT_TIMESTAMP_FORMAT)
    except ValueError:
        return value.strip()
    return moment.replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_model(
    path: str,
    model: Autoencoder,
    scaler: FeatureScaler,
    medians: np.ndarray,
    threshold: float,
    feature_names: Sequence[str],
    metrics: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist the trained model, scaler, medians and threshold to one file."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle = {
        "state_dict": model.state_dict(),
        "n_features": model.n_features,
        "mean": torch.from_numpy(scaler.mean),
        "scale": torch.from_numpy(scaler.scale),
        "medians": torch.from_numpy(medians),
        "threshold": float(threshold),
        "feature_names": list(feature_names),
        "metrics": metrics or {},
    }
    torch.save(bundle, destination)
    LOG.info("saved model to %s", destination)


def load_model(path: str) -> Tuple[Autoencoder, FeatureScaler, np.ndarray, float, Dict[str, Any]]:
    """Load a model bundle written by :func:`save_model`."""
    model_path = Path(path)
    if not model_path.is_file():
        raise AutoencoderError(f"model file not found: {model_path}")
    bundle = torch.load(model_path, map_location="cpu", weights_only=True)
    model = Autoencoder(int(bundle["n_features"]))
    model.load_state_dict(bundle["state_dict"])
    model.eval()
    scaler = FeatureScaler(
        mean=bundle["mean"].numpy(), scale=bundle["scale"].numpy()
    )
    medians = bundle["medians"].numpy()
    return model, scaler, medians, float(bundle["threshold"]), dict(bundle.get("metrics") or {})


def flagged_records(
    timestamps: Sequence[str],
    errors: np.ndarray,
    threshold: float,
) -> List[Dict[str, Any]]:
    """Build the flagged-row records for every score above ``threshold``.

    The score is stored in the integer ``value`` column as milli-units of
    reconstruction error, since ``raw_events`` has no dedicated score column.
    """
    records: List[Dict[str, Any]] = []
    for index in np.flatnonzero(errors > threshold):
        error = float(errors[index])
        ratio = error / threshold if threshold else 0.0
        records.append(
            {
                "timestamp": parse_swat_timestamp(timestamps[index]),
                "error": error,
                "ratio": ratio,
                "severity": severity_for(ratio),
                "score_milli": int(round(error * 1000.0)),
            }
        )
    return records


def persist_flagged(
    database: str,
    records: Sequence[Dict[str, Any]],
    threshold: float,
    max_rows: Optional[int] = DEFAULT_MAX_STORE_ROWS,
    logger: logging.Logger = LOG,
) -> int:
    """Write flagged rows to ``raw_events`` and GR-5 rows to ``alerts``.

    ``raw_events`` records the replay (source ``swat_replay``, protocol
    ``modbus``); the matched ``alerts`` row carries the graded severity and links
    to it through ``event_id``. Existing SWaT replay rows are removed first, so
    repeated runs replace rather than accumulate. ``max_rows`` bounds the number
    stored (``None`` stores every flagged row); the default keeps the replay small
    enough that the engine can drain it promptly. Returns the number of
    ``raw_events`` rows written.
    """
    # Imported here so the module stays importable without a store present.
    from engine.correlator import SCHEMA as ALERTS_SCHEMA
    from store import open_database as open_shared_store

    connection = open_shared_store(database)
    connection.executescript(ALERTS_SCHEMA)
    connection.execute("DELETE FROM alerts WHERE rule_id = ?", (RULE_ID,))
    connection.execute("DELETE FROM raw_events WHERE source = ?", (SOURCE,))

    insert_event = (
        "INSERT INTO raw_events (timestamp, source, protocol, value) VALUES (?, ?, ?, ?)"
    )
    insert_alert = (
        "INSERT OR IGNORE INTO alerts "
        "(timestamp, rule_id, severity, protocol, description, event_id) "
        "VALUES (?, ?, ?, ?, ?, ?)"
    )

    selected = list(records) if max_rows is None else list(records)[:max_rows]
    written = 0
    for record in selected:
        cursor = connection.execute(
            insert_event,
            (record["timestamp"], SOURCE, PROTOCOL, record["score_milli"]),
        )
        event_id = cursor.lastrowid
        description = (
            f"SWaT replay at {record['timestamp']}: GR-5 reconstruction error "
            f"{record['error']:.6f} exceeds threshold {threshold:.6f} "
            f"({record['ratio']:.2f}x) — statistical anomaly"
        )
        connection.execute(
            insert_alert,
            (
                record["timestamp"], RULE_ID, record["severity"], PROTOCOL,
                description, event_id,
            ),
        )
        written += 1
    connection.commit()
    connection.close()
    logger.info("wrote %d flagged row(s) to %s", written, database)
    return written


def format_curve(values: Sequence[float], width: int = 40) -> str:
    """Render a loss series as a compact ASCII sparkline."""
    if not values:
        return ""
    # ASCII only: the CLI may run on a non-UTF-8 console (e.g. Windows cp1252).
    blocks = " .:-=+*#"
    low, high = min(values), max(values)
    span = high - low
    # Subsample when there are more epochs than columns so the sparkline fits.
    stride = max(1, len(values) // width)
    sampled = list(values)[::stride][:width]
    if span <= 0:
        return blocks[0] * len(sampled)
    return "".join(blocks[min(len(blocks) - 1, int((value - low) / span * (len(blocks) - 1)))]
                   for value in sampled)
