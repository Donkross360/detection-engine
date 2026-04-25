import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from detector import SlidingWindowEngine, SlidingWindowSnapshot
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


def run() -> None:
    config = load_config(Path(__file__).with_name("config.yaml"))
    logs_config = config.get("logs", {})
    app_config = config.get("app", {})
    windows_config = config.get("windows", {})
    output_config = config.get("output", {})

    monitor = NginxLogMonitor(
        log_path=logs_config.get("nginx_access_log_path", ""),
        poll_interval_seconds=float(app_config.get("poll_interval_seconds", 0.2)),
        skip_empty_source_ip=bool(logs_config.get("skip_empty_source_ip", True)),
    )
    engine = SlidingWindowEngine(
        window_seconds=int(windows_config.get("sliding_window_seconds", 60))
    )

    pretty = bool(output_config.get("print_pretty", True))
    print_events = bool(output_config.get("print_events", True))
    stats_print_interval_seconds = float(
        windows_config.get("stats_print_interval_seconds", 3)
    )
    stats_thread_enabled = bool(windows_config.get("stats_thread_enabled", True))

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

    print("Starting detector monitor...")
    print(f"Reading log file: {monitor.log_path}")
    print("Press Ctrl+C to stop.\n")

    try:
        for event in monitor.follow():
            engine.add_event(event)

            if print_events:
                if pretty:
                    print(json.dumps(event.to_dict(), indent=2))
                else:
                    print(json.dumps(event.to_dict()))
    finally:
        stats_stop.set()
        if stats_thread is not None:
            stats_thread.join(timeout=2.0)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nDetector monitor stopped.")
