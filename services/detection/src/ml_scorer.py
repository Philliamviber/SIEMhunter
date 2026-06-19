"""
ML advisory scorer — Isolation Forest + z-score baselines.
Spec: instructions/05-detection-and-anomaly.md §8

Rules:
- Advisory only; never creates incidents or blocks Sigma detection.
- Model artifacts are hash-verified before loading (NFR-08).
- No pickle from untrusted paths; no network model loading.
- On hash mismatch: log Warning to SIEMHunterHealth_CL, skip scoring.
"""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

_MODEL_PATH = os.environ.get("SIEMHUNTER_MODEL_PATH", "/app/models")
_HASH_FILE = os.environ.get("SIEMHUNTER_MODEL_HASH_FILE", "/app/models/model_hashes.sha256")

_models: dict[str, object] = {}   # entity_type → loaded sklearn model
_scoring_available = False


def _verify_artifact_hash(model_path: str, expected_hashes: dict[str, str]) -> bool:
    """Return True if the file at model_path matches the expected SHA-256."""
    filename = pathlib.Path(model_path).name
    expected = expected_hashes.get(filename)
    if not expected:
        log.warning("model_no_hash_entry", filename=filename)
        return False
    actual = hashlib.sha256(pathlib.Path(model_path).read_bytes()).hexdigest()
    if actual != expected:
        log.warning("model_hash_mismatch", filename=filename,
                    expected=expected, actual=actual)
        return False
    return True


def load_models() -> None:
    """Load ML model artifacts if present. Skips gracefully if models aren't deployed yet."""
    global _scoring_available, _models

    model_dir = pathlib.Path(_MODEL_PATH)
    hash_file = pathlib.Path(_HASH_FILE)

    if not model_dir.exists() or not hash_file.exists():
        log.info("ml_models_not_deployed_skipping_scoring")
        return

    try:
        expected_hashes = {}
        for line in hash_file.read_text().splitlines():
            line = line.strip()
            if line and " " in line:
                hash_val, fname = line.split(" ", 1)
                expected_hashes[fname.strip().lstrip("*")] = hash_val.strip()
    except Exception as exc:
        log.error("model_hash_file_read_error", error=str(exc))
        return

    import joblib

    loaded = {}
    for model_file in model_dir.glob("*.joblib"):
        model_path = str(model_file)
        # Reject paths outside the trusted model directory (path traversal guard)
        if not str(model_file.resolve()).startswith(str(model_dir.resolve())):
            log.error("model_path_traversal_rejected", path=model_path)
            continue

        if not _verify_artifact_hash(model_path, expected_hashes):
            return   # Halt model loading; write health event in caller

        try:
            model = joblib.load(model_path)
            entity_type = model_file.stem    # e.g., "user_model", "host_model"
            loaded[entity_type] = model
            log.info("model_loaded", entity_type=entity_type)
        except Exception as exc:
            log.error("model_load_error", path=model_path, error=str(exc))
            return

    _models = loaded
    _scoring_available = bool(_models)
    log.info("ml_scoring_ready", models=list(_models.keys()))


def score_entities(entity_features: list[dict]) -> dict[str, float]:
    """Return {entity_key: anomaly_score} for each entity.

    Returns empty dict if models are not available (advisory; never blocks).
    anomaly_score is in [0.0, 1.0]; higher = more anomalous.
    """
    if not _scoring_available or not _models:
        return {}

    import numpy as np

    scores: dict[str, float] = {}
    for rec in entity_features:
        entity_type = rec.get("entity_type", "user")
        entity_key = rec.get("entity_key", "")
        model = _models.get(f"{entity_type}_model")
        if model is None:
            continue

        features = rec.get("features", [])
        if not features:
            continue

        try:
            X = np.array([features], dtype=float)
            # IsolationForest.decision_function returns negative scores for anomalies;
            # invert and normalise to [0,1] range.
            raw_score = float(model.decision_function(X)[0])
            # Typical range: [-0.5, 0.5]; map to [0, 1]
            normalised = max(0.0, min(1.0, 0.5 - raw_score))
            scores[entity_key] = round(normalised, 4)
        except Exception as exc:
            log.warning("scoring_error", entity_key=entity_key, error=str(exc))

    return scores
