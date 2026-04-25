import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Generator, Optional


@dataclass
class LogEvent:
    source_ip: str
    timestamp: str
    method: str
    path: str
    status: int
    response_size: int
    request_time: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class NginxLogMonitor:
    REQUIRED_FIELDS = (
        "source_ip",
        "timestamp",
        "method",
        "path",
        "status",
        "response_size",
    )

    def __init__(
        self,
        log_path: str,
        poll_interval_seconds: float = 0.2,
        skip_empty_source_ip: bool = True,
    ) -> None:
        self.log_path = log_path
        self.poll_interval_seconds = poll_interval_seconds
        self.skip_empty_source_ip = skip_empty_source_ip

    def _normalize_timestamp(self, raw_timestamp: str) -> str:
        # Keep timestamps in a strict ISO format for downstream logic.
        try:
            parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            return raw_timestamp

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.strip()
        if not line:
            return None

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return None

        if any(field not in payload for field in self.REQUIRED_FIELDS):
            return None

        source_ip = str(payload.get("source_ip", "")).strip()
        if self.skip_empty_source_ip and not source_ip:
            return None

        try:
            status = int(payload["status"])
            response_size = int(payload["response_size"])
            request_time = float(payload.get("request_time", 0.0))
        except (TypeError, ValueError):
            return None

        return LogEvent(
            source_ip=source_ip,
            timestamp=self._normalize_timestamp(str(payload["timestamp"])),
            method=str(payload["method"]),
            path=str(payload["path"]),
            status=status,
            response_size=response_size,
            request_time=request_time,
        )

    def follow(self) -> Generator[LogEvent, None, None]:
        # Wait for log file availability so startup is resilient.
        while True:
            try:
                with open(self.log_path, "r", encoding="utf-8") as file_obj:
                    file_obj.seek(0, 2)
                    while True:
                        line = file_obj.readline()
                        if not line:
                            time.sleep(self.poll_interval_seconds)
                            continue

                        event = self.parse_line(line)
                        if event is not None:
                            yield event
            except FileNotFoundError:
                time.sleep(1.0)
