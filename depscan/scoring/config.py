"""Load config/scoring.yaml. Defaults are the file itself, so there is one source of truth."""
from __future__ import annotations

from pathlib import Path

import yaml

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent.parent / "config" / "scoring.yaml"


def load_config(path: Path | None = None) -> dict:
    cfg = yaml.safe_load((path or DEFAULT_CONFIG).read_text("utf-8"))
    weights = cfg["risk"]["weights"]
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"risk weights must sum to 1, got {total:.3f} in {path or DEFAULT_CONFIG}")
    if any(w < 0 for w in weights.values()):
        raise ValueError("risk weights cannot be negative")
    return cfg
