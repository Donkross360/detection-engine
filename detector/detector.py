from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Deque, Dict, List, Optional, Tuple

from baseline import BaselineSnapshot
from monitor import LogEvent


@dataclass
class SlidingWindowSnapshot:
    # `top_ips` stores tuples as: (ip, requests_per_second, count_in_window).
    window_seconds: int
    total_requests_last_window: int
    global_rps: float
    unique_ips: int
    top_ips: List[Tuple[str, float, int]]
    ip_rates: Dict[str, Tuple[float, int]]
    ip_error_rates: Dict[str, Tuple[float, int]]


@dataclass
class AnomalySignal:
    # `scope` is either "global" or "ip"; `ban_recommended` is true only for per-IP actions.
    scope: str
    condition: str
    current_rate: float
    baseline_mean: float
    z_score: float
    ip: Optional[str] = None
    tightened: bool = False
    ban_recommended: bool = False


class SlidingWindowEngine:
    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self.global_window: Deque[datetime] = deque()
        self.ip_windows: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.ip_error_windows: Dict[str, Deque[datetime]] = defaultdict(deque)

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
        # Keep only events inside the active sliding window.
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

        stale_error_ips: List[str] = []
        for ip, window in self.ip_error_windows.items():
            while window and window[0] < cutoff:
                window.popleft()
            if not window:
                stale_error_ips.append(ip)
        for ip in stale_error_ips:
            del self.ip_error_windows[ip]

    def add_event(self, event: LogEvent) -> None:
        event_time = self._parse_event_time(event)
        with self._lock:
            self.global_window.append(event_time)
            self.ip_windows[event.source_ip].append(event_time)
            # Track error traffic separately for adaptive threshold tightening.
            if event.status >= 400:
                self.ip_error_windows[event.source_ip].append(event_time)
            self._evict_old(event_time)

    def snapshot(self) -> SlidingWindowSnapshot:
        with self._lock:
            now_utc = datetime.now(timezone.utc)
            self._evict_old(now_utc)

            total = len(self.global_window)
            global_rps = total / float(self.window_seconds)

            ip_rates: Dict[str, Tuple[float, int]] = {}
            for ip, window in self.ip_windows.items():
                count = len(window)
                ip_rates[ip] = (count / float(self.window_seconds), count)

            ip_error_rates: Dict[str, Tuple[float, int]] = {}
            for ip, window in self.ip_error_windows.items():
                count = len(window)
                ip_error_rates[ip] = (count / float(self.window_seconds), count)

            ip_stats = [
                (ip, rate_and_count[0], rate_and_count[1])
                for ip, rate_and_count in ip_rates.items()
            ]
            ip_stats.sort(key=lambda item: item[2], reverse=True)

            return SlidingWindowSnapshot(
                window_seconds=self.window_seconds,
                total_requests_last_window=total,
                global_rps=global_rps,
                unique_ips=len(self.ip_windows),
                top_ips=ip_stats[:10],
                ip_rates=ip_rates,
                ip_error_rates=ip_error_rates,
            )


class AnomalyEvaluator:
    def __init__(
        self,
        z_threshold: float = 3.0,
        multiplier_threshold: float = 5.0,
        error_surge_multiplier: float = 3.0,
        tightened_z_threshold: float = 2.5,
        tightened_multiplier_threshold: float = 4.0,
        alert_cooldown_seconds: int = 10,
    ) -> None:
        self.z_threshold = z_threshold
        self.multiplier_threshold = multiplier_threshold
        self.error_surge_multiplier = error_surge_multiplier
        self.tightened_z_threshold = tightened_z_threshold
        self.tightened_multiplier_threshold = tightened_multiplier_threshold
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self._last_global_alert_at = 0.0
        self._last_ip_alert_at: Dict[str, float] = {}

    @staticmethod
    def _z_score(rate: float, mean: float, stddev: float) -> float:
        if stddev <= 0:
            return 0.0
        return (rate - mean) / stddev

    def evaluate(
        self,
        snapshot: SlidingWindowSnapshot,
        baseline: BaselineSnapshot,
    ) -> List[AnomalySignal]:
        now = time.monotonic()
        findings: List[AnomalySignal] = []

        global_z = self._z_score(
            rate=snapshot.global_rps,
            mean=baseline.effective_mean,
            stddev=baseline.effective_stddev,
        )
        global_condition = ""
        # Trigger if either statistical outlier or strong multiplier condition is hit.
        if global_z > self.z_threshold:
            global_condition = "z-score"
        elif snapshot.global_rps > self.multiplier_threshold * baseline.effective_mean:
            global_condition = "rate-multiplier"

        if global_condition and now - self._last_global_alert_at >= self.alert_cooldown_seconds:
            findings.append(
                AnomalySignal(
                    scope="global",
                    condition=global_condition,
                    current_rate=snapshot.global_rps,
                    baseline_mean=baseline.effective_mean,
                    z_score=global_z,
                    ban_recommended=False,
                )
            )
            self._last_global_alert_at = now

        for ip, (ip_rps, _count) in snapshot.ip_rates.items():
            error_rps = snapshot.ip_error_rates.get(ip, (0.0, 0))[0]
            # If an IP's error profile surges, apply tighter per-IP thresholds.
            tightened = error_rps > (self.error_surge_multiplier * baseline.error_mean)
            z_threshold = self.tightened_z_threshold if tightened else self.z_threshold
            mult_threshold = (
                self.tightened_multiplier_threshold
                if tightened
                else self.multiplier_threshold
            )
            ip_z = self._z_score(
                rate=ip_rps,
                mean=baseline.effective_mean,
                stddev=baseline.effective_stddev,
            )

            condition = ""
            if ip_z > z_threshold:
                condition = "z-score"
            elif ip_rps > mult_threshold * baseline.effective_mean:
                condition = "rate-multiplier"

            last_ip_alert_at = self._last_ip_alert_at.get(ip, 0.0)
            # Apply cooldown to prevent repeated alerts for the same active spike.
            if condition and now - last_ip_alert_at >= self.alert_cooldown_seconds:
                findings.append(
                    AnomalySignal(
                        scope="ip",
                        ip=ip,
                        condition=condition,
                        current_rate=ip_rps,
                        baseline_mean=baseline.effective_mean,
                        z_score=ip_z,
                        tightened=tightened,
                        ban_recommended=True,
                    )
                )
                self._last_ip_alert_at[ip] = now

        return findings
