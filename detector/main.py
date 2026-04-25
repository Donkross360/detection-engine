import json
from pathlib import Path
from typing import Any, Dict

import yaml

from monitor import NginxLogMonitor


def load_config(config_path: Path) -> Dict[str, Any]:
    with config_path.open("r", encoding="utf-8") as config_file:
        return yaml.safe_load(config_file)


def run() -> None:
    config = load_config(Path(__file__).with_name("config.yaml"))
    logs_config = config.get("logs", {})
    app_config = config.get("app", {})
    output_config = config.get("output", {})

    monitor = NginxLogMonitor(
        log_path=logs_config.get("nginx_access_log_path", ""),
        poll_interval_seconds=float(app_config.get("poll_interval_seconds", 0.2)),
        skip_empty_source_ip=bool(logs_config.get("skip_empty_source_ip", True)),
    )

    pretty = bool(output_config.get("print_pretty", True))

    print("Starting detector monitor...")
    print(f"Reading log file: {monitor.log_path}")
    print("Press Ctrl+C to stop.\n")

    for event in monitor.follow():
        if pretty:
            print(json.dumps(event.to_dict(), indent=2))
        else:
            print(json.dumps(event.to_dict()))


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nDetector monitor stopped.")
