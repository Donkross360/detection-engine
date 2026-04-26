import ipaddress
import subprocess
from typing import Iterable


class IptablesBlocker:
    def __init__(self, protected_cidrs: Iterable[str]) -> None:
        self.protected_networks = [ipaddress.ip_network(cidr) for cidr in protected_cidrs]

    def _is_protected_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(ip_obj in network for network in self.protected_networks)

    @staticmethod
    def _run_iptables(args: list[str]) -> bool:
        result = subprocess.run(
            ["iptables", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    def is_blocked(self, ip: str) -> bool:
        return self._run_iptables(["-C", "INPUT", "-s", ip, "-j", "DROP"])

    def block_ip(self, ip: str) -> tuple[bool, str]:
        if self._is_protected_ip(ip):
            return False, "protected-ip"
        if self.is_blocked(ip):
            return False, "already-blocked"
        if self._run_iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"]):
            return True, "blocked"
        return False, "iptables-error"

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        if not self.is_blocked(ip):
            return False, "not-blocked"
        if self._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"]):
            return True, "unblocked"
        return False, "iptables-error"
