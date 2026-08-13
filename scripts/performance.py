"""Performance instrumentation utilities for SIARC experimental evaluation."""
from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Deque, Dict, Any

_METRICS_PATH = Path("data/performance_metrics.jsonl")
_LOCK = threading.Lock()
_RECENT: Deque[Dict[str, Any]] = deque(maxlen=5000)


def now() -> float:
    return time.perf_counter()


def elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


def record_metric(metric: Dict[str, Any]) -> None:
    metric = dict(metric)
    _RECENT.append(metric)
    _METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with _METRICS_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(metric, ensure_ascii=False) + "\n")


def recent_metrics(limit: int = 100) -> list[Dict[str, Any]]:
    if limit <= 0:
        return []
    return list(_RECENT)[-limit:]
