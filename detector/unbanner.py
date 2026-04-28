import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class BanRecord:
    # `duration_seconds=None` means permanent ban (no scheduled auto-unban).
    ip: str
    offense_count: int
    banned_at_monotonic: float
    duration_seconds: Optional[int]

    @property
    def is_permanent(self) -> bool:
        return self.duration_seconds is None

    @property
    def unban_due_monotonic(self) -> Optional[float]:
        if self.duration_seconds is None:
            return None
        return self.banned_at_monotonic + self.duration_seconds


class UnbanScheduler:
    def __init__(self, backoff_seconds: list[Optional[int]]) -> None:
        self.backoff_seconds = backoff_seconds
        self._records: Dict[str, BanRecord] = {}
        self._offense_counts: Dict[str, int] = {}

    def register_ban(self, ip: str) -> BanRecord:
        offense_count = self._offense_counts.get(ip, 0) + 1
        self._offense_counts[ip] = offense_count

        idx = min(offense_count - 1, len(self.backoff_seconds) - 1)
        duration = self.backoff_seconds[idx]
        record = BanRecord(
            ip=ip,
            offense_count=offense_count,
            banned_at_monotonic=time.monotonic(),
            duration_seconds=duration,
        )
        self._records[ip] = record
        return record

    def due_unbans(self) -> list[BanRecord]:
        now = time.monotonic()
        due: list[BanRecord] = []
        for ip, record in list(self._records.items()):
            due_at = record.unban_due_monotonic
            if due_at is None:
                continue
            if now >= due_at:
                due.append(record)
        return due

    def clear_ban(self, ip: str) -> None:
        self._records.pop(ip, None)

    def is_currently_banned(self, ip: str) -> bool:
        return ip in self._records

    def active_bans(self) -> list[BanRecord]:
        return list(self._records.values())
