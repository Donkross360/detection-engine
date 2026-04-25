import json
import time
from pathlib import Path
from typing import Any, Dict

import yaml

from detector import SlidingWindowEngine
from monitor import NginxLogMonitor


def load_config(config_path: Path) -> Dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


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
    stats_print_interval_seconds = float(
        windows_config.get("stats_print_interval_seconds", 3)
    )
    last_stats_print_at = time.monotonic()

    print("Starting detector monitor...")
    print(f"Reading log file: {monitor.log_path}")
    print("Press Ctrl+C to stop.\n")

    for event in monitor.follow():
        engine.add_event(event)

        if pretty:
            print(json.dumps(event.to_dict(), indent=2))
        else:
            print(json.dumps(event.to_dict()))

        now_monotonic = time.monotonic()
        if now_monotonic - last_stats_print_at >= stats_print_interval_seconds:
            snapshot = engine.snapshot()
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

            last_stats_print_at = now_monotonic


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nDetector monitor stopped.")
