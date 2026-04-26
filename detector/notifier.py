import json
from datetime import datetime, timezone
from typing import Optional
from urllib import request


class SlackNotifier:
    def __init__(self, webhook_url: str, enabled: bool = True) -> None:
        self.webhook_url = webhook_url
        self.enabled = enabled and bool(webhook_url)

    def _post(self, text: str) -> bool:
        if not self.enabled:
            return False

        payload = json.dumps({"text": text}).encode("utf-8")
        req = request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=5) as response:
                return 200 <= response.status < 300
        except Exception:
            return False

    def send_global_alert(
        self,
        condition: str,
        current_rate: float,
        baseline: float,
    ) -> bool:
        text = (
            ":rotating_light: GLOBAL ANOMALY\n"
            f"condition={condition}\n"
            f"current_rate={current_rate:.4f}\n"
            f"baseline_mean={baseline:.4f}\n"
            f"timestamp={datetime.now(timezone.utc).isoformat()}"
        )
        return self._post(text)

    def send_ban_alert(
        self,
        ip: str,
        condition: str,
        current_rate: float,
        baseline: float,
        duration_seconds: Optional[int],
    ) -> bool:
        duration = "permanent" if duration_seconds is None else f"{duration_seconds}s"
        text = (
            ":no_entry: IP BANNED\n"
            f"ip={ip}\n"
            f"condition={condition}\n"
            f"current_rate={current_rate:.4f}\n"
            f"baseline_mean={baseline:.4f}\n"
            f"ban_duration={duration}\n"
            f"timestamp={datetime.now(timezone.utc).isoformat()}"
        )
        return self._post(text)

    def send_unban_alert(self, ip: str) -> bool:
        text = (
            ":white_check_mark: IP UNBANNED\n"
            f"ip={ip}\n"
            f"timestamp={datetime.now(timezone.utc).isoformat()}"
        )
        return self._post(text)
