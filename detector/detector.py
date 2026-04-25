from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Tuple

from monitor import LogEvent


@dataclass
class SlidingWindowSnapshot:
    window_seconds: int
    total_requests_last_window: int
    global_rps: float
    unique_ips: int
    top_ips: List[Tuple[str, float, int]]


class SlidingWindowEngine:
    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self.global_window: Deque[datetime] = deque()
        self.ip_windows: Dict[str, Deque[datetime]] = defaultdict(deque)

    def _parse_event_time(self, event: LogEvent) -> datetime:
        raw = event.timestamp
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            parsed = datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _evict_old(self, now_utc: datetime) -> None:
        cutoff = now_utc - timedelta(seconds=self.window_seconds)

        while self.global_window and self.global_window[0] < cutoff:
            self.global_window.popleft()

        stale_ips: List[str] = []
        for ip, window in self.ip_windows.items():
            while window and window[0] < cutoff:
                window.popleft()
            if not window:
                stale_ips.append(ip)

        for ip in stale_ips:
            del self.ip_windows[ip]

    def add_event(self, event: LogEvent) -> None:
        event_time = self._parse_event_time(event)
        self.global_window.append(event_time)
        self.ip_windows[event.source_ip].append(event_time)
        self._evict_old(event_time)

    def snapshot(self) -> SlidingWindowSnapshot:
        now_utc = datetime.now(timezone.utc)
        self._evict_old(now_utc)

        total = len(self.global_window)
        global_rps = total / float(self.window_seconds)

        ip_stats: List[Tuple[str, float, int]] = []
        for ip, window in self.ip_windows.items():
            count = len(window)
            ip_stats.append((ip, count / float(self.window_seconds), count))

        ip_stats.sort(key=lambda item: item[2], reverse=True)

        return SlidingWindowSnapshot(
            window_seconds=self.window_seconds,
            total_requests_last_window=total,
            global_rps=global_rps,
            unique_ips=len(self.ip_windows),
            top_ips=ip_stats[:10],
        )
