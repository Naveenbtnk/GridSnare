#!/usr/bin/env python3
"""Train the GR-5 SWaT autoencoder and report its measured behaviour.

End-to-end entry point for ``engine/autoencoder.py``:

  * trains on the normal-operation SWaT capture (``data/swat/normal.csv``);
  * calibrates a threshold on a held-out split of that capture, targeting the
    requested false-positive rate;
  * scores the attack capture (``data/swat/attack.csv``) and reports the
    measured detection rate and false-positive rate;
  * saves the model to ``data/autoencoder.pt`` and writes flagged attack rows to
    the shared store (``raw_events`` / ``alerts``), unless ``--no-store`` is
    given.

Run from the repository root:

    python scripts/train_autoencoder.py
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from engine import autoencoder as ae  # noqa: E402

LOG = logging.getLogger("gridsnare.train_autoencoder")

DEFAULT_NORMAL = "data/swat/normal.csv"
DEFAULT_ATTACK = "data/swat/attack.csv"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the GR-5 SWaT autoencoder")
    parser.add_argument("--normal", default=DEFAULT_NORMAL, help="normal-operation SWaT CSV")
    parser.add_argument("--attack", default=DEFAULT_ATTACK, help="attack SWaT CSV")
    parser.add_argument("--model-out", default=ae.DEFAULT_MODEL_PATH, help="model output path")
    parser.add_argument("--database", default="data/events.db", help="shared store for flagged rows")
    parser.add_argument("--no-store", action="store_true", help="do not write flagged rows to the store")
    parser.add_argument("--max-store-rows", type=int, default=ae.DEFAULT_MAX_STORE_ROWS,
                        help="cap on flagged rows written to the store (0 = all)")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--target-fpr", type=float, default=0.05,
                        help="false-positive rate the threshold is calibrated to")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train-ratio", type=float, default=0.70)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--max-normal-rows", type=int, default=0,
                        help="cap rows loaded from the normal capture (0 = all)")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def split_indices(count: int, train_ratio: float, val_ratio: float, seed: int
                  ) -> Dict[str, np.ndarray]:
    """Split row indices into train/validation/test with a fixed seed."""
    order = np.random.default_rng(seed).permutation(count)
    train_end = int(count * train_ratio)
    val_end = train_end + int(count * val_ratio)
    return {
        "train": order[:train_end],
        "val": order[train_end:val_end],
        "test": order[val_end:],
    }


def rate(flags: np.ndarray) -> float:
    return float(np.mean(flags)) if flags.size else 0.0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        stream=sys.stdout,
    )

    max_rows = args.max_normal_rows or None
    normal = ae.load_swat_csv(args.normal, max_rows=max_rows)
    attack = ae.load_swat_csv(args.attack)

    normal_labels = np.array(normal.labels)
    attack_labels = np.array(attack.labels)
    LOG.info(
        "labels: normal capture %s, attack capture %s",
        dict(zip(*np.unique(normal_labels, return_counts=True))),
        dict(zip(*np.unique(attack_labels, return_counts=True))),
    )

    splits = split_indices(normal.features.shape[0], args.train_ratio, args.val_ratio, args.seed)
    medians = ae.column_medians(normal.features[splits["train"]])
    scaler = ae.FeatureScaler.fit(ae.impute_features(normal.features[splits["train"]], medians))

    def prepare(rows: np.ndarray) -> np.ndarray:
        return scaler.transform(ae.impute_features(normal.features[rows], medians))

    train_x = prepare(splits["train"])
    val_x = prepare(splits["val"])
    test_x = prepare(splits["test"])

    LOG.info(
        "split: %d train / %d validation / %d test row(s), %d feature(s)",
        len(splits["train"]), len(splits["val"]), len(splits["test"]), normal.n_features,
    )

    model, history = ae.train_autoencoder(
        train_x, val_x,
        epochs=args.epochs, batch_size=args.batch_size,
        learning_rate=args.learning_rate, seed=args.seed,
    )

    val_errors = ae.reconstruction_errors(model, val_x)
    threshold = ae.calibrate_threshold(val_errors, target_fpr=args.target_fpr)

    test_errors = ae.reconstruction_errors(model, test_x)
    attack_x = scaler.transform(ae.impute_features(attack.features, medians))
    attack_errors = ae.reconstruction_errors(model, attack_x)

    val_flags = val_errors > threshold
    test_flags = test_errors > threshold
    attack_flags = attack_errors > threshold

    # attack.csv may contain only Attack-labelled rows; the false-positive rate
    # is therefore measured on the held-out normal split, which is what
    # "labelled normal rows flagged" means for this dataset.
    attack_normal_mask = np.array([label.lower() != "attack" for label in attack.labels])
    attack_rows = ~attack_normal_mask
    detection_rate = rate(attack_flags[attack_rows]) if attack_rows.any() else 0.0
    attack_fpr = rate(attack_flags[attack_normal_mask]) if attack_normal_mask.any() else None

    metrics: Dict[str, Any] = {
        "rows_normal": int(normal.features.shape[0]),
        "rows_attack": int(attack.features.shape[0]),
        "features": normal.n_features,
        "epochs": args.epochs,
        "threshold": threshold,
        "target_fpr": args.target_fpr,
        "validation_fpr": rate(val_flags),
        "false_positive_rate": rate(test_flags),
        "detection_rate": detection_rate,
        "attack_fpr_in_file": attack_fpr,
        "flagged_attack_rows": int(attack_flags.sum()),
        "attack_rows_labelled_attack": int(attack_rows.sum()),
        "normal_rows_labelled_normal_in_attack_file": int(attack_normal_mask.sum()),
        "final_train_mse": history.train_losses[-1],
        "final_val_mse": history.val_losses[-1],
    }

    print("\n=== loss curve ===")
    print(f"train MSE: {ae.format_curve(history.train_losses)}")
    print(f"val   MSE: {ae.format_curve(history.val_losses)}")
    print(history.summary())

    print("\n=== measured results ===")
    print(f"threshold (error MSE):          {threshold:.6f}  (calibrated to target FPR {args.target_fpr:.0%})")
    print(f"validation false-positive rate: {metrics['validation_fpr']:.4%}")
    print(f"false-positive rate (held-out normal split): {metrics['false_positive_rate']:.4%}")
    print(f"detection rate (attack rows flagged):        {detection_rate:.4%} "
          f"({int(attack_flags.sum())}/{attack.features.shape[0]})")

    # Severity distribution of the flagged attack rows, so the run's grading is visible.
    records = ae.flagged_records(attack.timestamps, attack_errors, threshold)
    severity_counts: Dict[str, int] = {}
    for record in records:
        severity_counts[record["severity"]] = severity_counts.get(record["severity"], 0) + 1
    print(f"flagged-row severity: {severity_counts}")

    saved_metrics = {key: value for key, value in metrics.items()}
    ae.save_model(
        args.model_out, model, scaler, medians, threshold, normal.feature_names,
        metrics=saved_metrics,
    )

    if args.no_store:
        print("flagged rows not written (--no-store)")
    else:
        max_store = args.max_store_rows or None
        written = ae.persist_flagged(args.database, records, threshold, max_rows=max_store)
        print(f"wrote {written} of {len(records)} flagged row(s) to {args.database} "
              f"(source='{ae.SOURCE}', protocol='{ae.PROTOCOL}', cap {max_store})")

    print("\n=== metrics json ===")
    print(json.dumps(metrics, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
