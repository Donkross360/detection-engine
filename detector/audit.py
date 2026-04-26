from pathlib import Path


class AuditLogger:
    def __init__(self, audit_log_path: str) -> None:
        self.path = Path(audit_log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(
        self,
        timestamp: str,
        action: str,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        duration: str,
    ) -> None:
        line = (
            f"[{timestamp}] {action} {ip} | {condition} | "
            f"{rate:.4f} | {baseline:.4f} | {duration}\n"
        )
        with self.path.open("a", encoding="utf-8") as log_file:
            log_file.write(line)
