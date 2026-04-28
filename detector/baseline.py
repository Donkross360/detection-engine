from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
import statistics
import threading
from typing import Dict, List, Optional, Tuple

from monitor import LogEvent


@dataclass
class BaselineSnapshot:
    # `used_current_hour` indicates whether current-hour slot stats were preferred over full 30-min window.
    effective_mean: float
    effective_stddev: float
    error_mean: float
    sample_count: int
    used_current_hour: bool
    current_hour_key: str
    recalculated_at: str


class RollingBaselineEngine:
    def __init__(
        self,
        window_seconds: int = 1800,
        min_current_hour_samples: int = 300,
        mean_floor: float = 0.1,
        stddev_floor: float = 0.1,
        error_floor: float = 0.01,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_current_hour_samples = min_current_hour_samples
        self.mean_floor = mean_floor
        self.stddev_floor = stddev_floor
        self.error_floor = error_floor

        self._lock = threading.Lock()
        self._counts_by_second: Dict[int, int] = defaultdict(int)
        self._errors_by_second: Dict[int, int] = defaultdict(int)
        self._last_snapshot: Optional[BaselineSnapshot] = None

    def _parse_event_second(self, event: LogEvent) -> int:
        try:
            parsed = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            else:
                parsed = parsed.astimezone(timezone.utc)
            return int(parsed.timestamp())
        except ValueError:
            return int(datetime.now(timezone.utc).timestamp())

    def ingest_event(self, event: LogEvent) -> None:
        sec = self._parse_event_second(event)
        with self._lock:
            self._counts_by_second[sec] += 1
            if event.status >= 400:
                self._errors_by_second[sec] += 1

    def _build_series(self, now_sec: int) -> Tuple[List[int], List[int], str]:
        start_sec = now_sec - self.window_seconds + 1
        total_series: List[int] = []
        error_series: List[int] = []
        current_hour_key = datetime.fromtimestamp(now_sec, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H"
        )

        for sec in range(start_sec, now_sec + 1):
            total_series.append(self._counts_by_second.get(sec, 0))
            error_series.append(self._errors_by_second.get(sec, 0))

        # Drop old keys to keep memory bounded.
        stale_cutoff = start_sec - 1
        stale_total_keys = [sec for sec in self._counts_by_second if sec <= stale_cutoff]
        stale_error_keys = [sec for sec in self._errors_by_second if sec <= stale_cutoff]
        for sec in stale_total_keys:
            del self._counts_by_second[sec]
        for sec in stale_error_keys:
            del self._errors_by_second[sec]

        return total_series, error_series, current_hour_key

    def recalculate(self) -> BaselineSnapshot:
        now = datetime.now(timezone.utc)
        now_sec = int(now.timestamp())

        with self._lock:
            total_series, error_series, current_hour_key = self._build_series(now_sec)

        # Group per-second counts by hour so baseline can prefer current-hour behavior.
        start_sec = now_sec - self.window_seconds + 1
        totals_by_hour: Dict[str, List[int]] = defaultdict(list)
        errors_by_hour: Dict[str, List[int]] = defaultdict(list)
        for offset, count in enumerate(total_series):
            sec = start_sec + offset
            hour_key = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H")
            totals_by_hour[hour_key].append(count)
            errors_by_hour[hour_key].append(error_series[offset])

        selected_total = total_series
        selected_error = error_series
        used_current_hour = False

        current_hour_totals = totals_by_hour.get(current_hour_key, [])
        current_hour_errors = errors_by_hour.get(current_hour_key, [])
        # Prefer current-hour behavior once sample confidence is high enough.
        if len(current_hour_totals) >= self.min_current_hour_samples:
            selected_total = current_hour_totals
            selected_error = current_hour_errors
            used_current_hour = True

        mean_value = statistics.fmean(selected_total) if selected_total else 0.0
        stddev_value = statistics.pstdev(selected_total) if len(selected_total) > 1 else 0.0
        error_mean = statistics.fmean(selected_error) if selected_error else 0.0

        # Floors prevent unstable detection math in low-traffic startup periods.
        snapshot = BaselineSnapshot(
            effective_mean=max(mean_value, self.mean_floor),
            effective_stddev=max(stddev_value, self.stddev_floor),
            error_mean=max(error_mean, self.error_floor),
            sample_count=len(selected_total),
            used_current_hour=used_current_hour,
            current_hour_key=current_hour_key,
            recalculated_at=now.isoformat(),
        )
        self._last_snapshot = snapshot
        return snapshot

    def last_snapshot(self) -> Optional[BaselineSnapshot]:
        return self._last_snapshot
