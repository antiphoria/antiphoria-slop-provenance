"""Render a consolidated view of worker metric snapshots."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def _load_snapshot(path: Path) -> dict[str, Any]:
    """Load one JSON snapshot file."""

    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise RuntimeError(f"Invalid metrics snapshot object: {path}")
    metrics = loaded.get("metrics")
    if not isinstance(metrics, dict):
        raise RuntimeError(f"Missing metrics object in snapshot: {path}")
    return loaded


def _build_report(metrics_dir: Path) -> dict[str, Any]:
    """Build aggregated report from all service snapshots."""

    snapshots = sorted(metrics_dir.glob("*.json"))
    services: dict[str, dict[str, int]] = {}
    aggregate: dict[str, int] = {}
    for snapshot_path in snapshots:
        loaded = _load_snapshot(snapshot_path)
        service_name = str(loaded.get("consumerGroup", snapshot_path.stem))
        raw_metrics = loaded["metrics"]
        service_metrics = {str(k): int(v) for k, v in raw_metrics.items()}
        services[service_name] = service_metrics
        for metric_key, value in service_metrics.items():
            aggregate[metric_key] = aggregate.get(metric_key, 0) + value
    return {
        "metricsDir": str(metrics_dir),
        "serviceCount": len(services),
        "services": services,
        "aggregate": aggregate,
    }


def main() -> int:
    """CLI entrypoint for metrics report rendering."""

    parser = argparse.ArgumentParser(prog="slop-metrics")
    parser.add_argument(
        "--metrics-dir",
        default=os.getenv("KAFKA_METRICS_DIR", ".metrics"),
        help="Directory containing per-service metrics snapshots.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output.",
    )
    args = parser.parse_args()
    metrics_dir = Path(args.metrics_dir).resolve()
    if not metrics_dir.exists():
        raise RuntimeError(f"Metrics directory not found: {metrics_dir}")
    report = _build_report(metrics_dir)
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    print(f"Metrics directory: {report['metricsDir']}")
    print(f"Services reporting: {report['serviceCount']}")
    for service_name, metrics in report["services"].items():
        print(f"\n[{service_name}]")
        for metric_key in sorted(metrics):
            print(f"  {metric_key}={metrics[metric_key]}")
    if report["aggregate"]:
        print("\n[aggregate]")
        for metric_key in sorted(report["aggregate"]):
            print(f"  {metric_key}={report['aggregate'][metric_key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
