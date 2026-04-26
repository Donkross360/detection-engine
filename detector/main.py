import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from baseline import BaselineSnapshot, RollingBaselineEngine
from detector import AnomalyEvaluator, AnomalySignal, SlidingWindowEngine, SlidingWindowSnapshot
from monitor import NginxLogMonitor


def load_config(config_path: Path) -> Dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def print_window_stats(snapshot: SlidingWindowSnapshot) -> None:
    print(
        "[window]"
        f" {snapshot.window_seconds}s"
        f" total={snapshot.total_requests_last_window}"
        f" global_rps={snapshot.global_rps:.2f}"
        f" unique_ips={snapshot.unique_ips}"
    )

    if snapshot.top_ips:
        for index, (ip, ip_rps, count) in enumerate(snapshot.top_ips, start=1):
            print(f"  {index:02d}. ip={ip} rps={ip_rps:.2f} count={count}")
    else:
        print("  No active IPs in current window.")


def print_baseline_stats(snapshot: BaselineSnapshot) -> None:
    slot_source = "current-hour" if snapshot.used_current_hour else "rolling-window"
    print(
        "[baseline]"
        f" mean={snapshot.effective_mean:.4f}"
        f" stddev={snapshot.effective_stddev:.4f}"
        f" error_mean={snapshot.error_mean:.4f}"
        f" samples={snapshot.sample_count}"
        f" source={slot_source}"
        f" hour={snapshot.current_hour_key}"
        f" recalculated_at={snapshot.recalculated_at}"
    )


def print_anomaly(signal: AnomalySignal) -> None:
    if signal.scope == "global":
        print(
            "[anomaly]"
            " scope=global"
            f" condition={signal.condition}"
            f" rate={signal.current_rate:.4f}"
            f" baseline_mean={signal.baseline_mean:.4f}"
            f" z={signal.z_score:.4f}"
            " action=slack_only"
        )
        return

    print(
        "[anomaly]"
        " scope=ip"
        f" ip={signal.ip}"
        f" condition={signal.condition}"
        f" rate={signal.current_rate:.4f}"
        f" baseline_mean={signal.baseline_mean:.4f}"
        f" z={signal.z_score:.4f}"
        f" tightened={signal.tightened}"
        " action=ban_candidate"
    )


def run() -> None:
    config = load_config(Path(__file__).with_name("config.yaml"))
    logs_config = config.get("logs", {})
    app_config = config.get("app", {})
    windows_config = config.get("windows", {})
    baseline_config = config.get("baseline", {})
    detection_config = config.get("detection", {})
    output_config = config.get("output", {})

    monitor = NginxLogMonitor(
        log_path=logs_config.get("nginx_access_log_path", ""),
        poll_interval_seconds=float(app_config.get("poll_interval_seconds", 0.2)),
        skip_empty_source_ip=bool(logs_config.get("skip_empty_source_ip", True)),
    )
    engine = SlidingWindowEngine(
        window_seconds=int(windows_config.get("sliding_window_seconds", 60))
    )
    baseline_engine = RollingBaselineEngine(
        window_seconds=int(baseline_config.get("window_seconds", 1800)),
        min_current_hour_samples=int(
            baseline_config.get("min_current_hour_samples", 300)
        ),
        mean_floor=float(baseline_config.get("mean_floor", 0.1)),
        stddev_floor=float(baseline_config.get("stddev_floor", 0.1)),
        error_floor=float(baseline_config.get("error_floor", 0.01)),
    )
    anomaly_evaluator = AnomalyEvaluator(
        z_threshold=float(detection_config.get("z_threshold", 3.0)),
        multiplier_threshold=float(detection_config.get("multiplier_threshold", 5.0)),
        error_surge_multiplier=float(
            detection_config.get("error_surge_multiplier", 3.0)
        ),
        tightened_z_threshold=float(
            detection_config.get("tightened_z_threshold", 2.5)
        ),
        tightened_multiplier_threshold=float(
            detection_config.get("tightened_multiplier_threshold", 4.0)
        ),
        alert_cooldown_seconds=int(
            detection_config.get("alert_cooldown_seconds", 10)
        ),
    )

    pretty = bool(output_config.get("print_pretty", True))
    print_events = bool(output_config.get("print_events", True))
    stats_print_interval_seconds = float(
        windows_config.get("stats_print_interval_seconds", 3)
    )
    stats_thread_enabled = bool(windows_config.get("stats_thread_enabled", True))
    baseline_recalc_interval_seconds = float(
        baseline_config.get("recalc_interval_seconds", 60)
    )

    stats_stop = threading.Event()

    def stats_loop() -> None:
        if stats_print_interval_seconds <= 0:
            return

        while not stats_stop.is_set():
            snapshot = engine.snapshot()
            print_window_stats(snapshot)

            if stats_stop.wait(timeout=stats_print_interval_seconds):
                return

    stats_thread: Optional[threading.Thread] = None
    if stats_thread_enabled and stats_print_interval_seconds > 0:
        stats_thread = threading.Thread(target=stats_loop, name="stats-printer", daemon=True)
        stats_thread.start()

    def baseline_loop() -> None:
        if baseline_recalc_interval_seconds <= 0:
            return

        # Run one recalculation immediately at startup for visibility.
        print_baseline_stats(baseline_engine.recalculate())
        while not stats_stop.is_set():
            if stats_stop.wait(timeout=baseline_recalc_interval_seconds):
                return
            print_baseline_stats(baseline_engine.recalculate())

    baseline_thread = threading.Thread(
        target=baseline_loop,
        name="baseline-recalculator",
        daemon=True,
    )
    baseline_thread.start()

    print("Starting detector monitor...")
    print(f"Reading log file: {monitor.log_path}")
    print("Press Ctrl+C to stop.\n")

    try:
        for event in monitor.follow():
            engine.add_event(event)
            baseline_engine.ingest_event(event)

            if print_events:
                if pretty:
                    print(json.dumps(event.to_dict(), indent=2))
                else:
                    print(json.dumps(event.to_dict()))

            baseline_snapshot = baseline_engine.last_snapshot()
            if baseline_snapshot is not None:
                window_snapshot = engine.snapshot()
                findings = anomaly_evaluator.evaluate(
                    snapshot=window_snapshot,
                    baseline=baseline_snapshot,
                )
                for finding in findings:
                    print_anomaly(finding)
    finally:
        stats_stop.set()
        if stats_thread is not None:
            stats_thread.join(timeout=2.0)
        baseline_thread.join(timeout=2.0)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nDetector monitor stopped.")
