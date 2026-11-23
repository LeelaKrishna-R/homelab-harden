from __future__ import annotations

import glob
import os
import platform as platform_mod
import shutil
import subprocess
from pathlib import Path

from homelab_harden import parsers
from homelab_harden.facts import Facts


def _run(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def collect() -> Facts:
    system = platform_mod.system().lower()
    facts = Facts(platform=system)
    if system != "linux":
        facts.notes.append(
            "host auditing runs on Linux; run this on your server, or use --demo for sample output"
        )
        return facts
    facts.is_root = os.geteuid() == 0
    _collect_ssh(facts)
    _collect_firewall(facts)
    _collect_auto_updates(facts)
    _collect_fail2ban(facts)
    _collect_sudoers(facts)
    _collect_shadow(facts)
    _collect_listeners(facts)
    return facts


def _collect_ssh(facts: Facts) -> None:
    text = _run(["sshd", "-T"]) if shutil.which("sshd") else None
    source = "sshd -T"
    if not text:
        text = read_sshd_config("/etc/ssh/sshd_config")
        source = "config file"
    if not text:
        facts.notes.append("could not read SSH configuration")
        return
    facts.ssh = parsers.parse_sshd_config(text, source)


def read_sshd_config(path: str, depth: int = 0) -> str | None:
    """The config as sshd reads it: each `Include` replaced in place by the files it names
    (globbed, sorted, relative to /etc/ssh). sshd keeps the first value it sees, and Ubuntu's
    default file includes sshd_config.d/*.conf at the top, so a cloud image's
    `PasswordAuthentication yes` there wins."""
    text = _read(path)
    if text is None or depth > 4:
        return text
    out: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) > 1 and parts[0].lower() == "include":
            for pattern in parts[1:]:
                full = pattern if os.path.isabs(pattern) else os.path.join("/etc/ssh", pattern)
                for name in sorted(glob.glob(full)):
                    included = read_sshd_config(name, depth + 1)
                    if included:
                        out.append(included)
            continue
        out.append(line)
    return "\n".join(out)


def _collect_firewall(facts: Facts) -> None:
    if shutil.which("ufw"):
        out = _run(["ufw", "status"])
        if out is not None:
            facts.firewall_tool = "ufw"
            facts.firewall_active = parsers.parse_ufw_status(out)
            return
    if shutil.which("firewall-cmd"):
        out = _run(["firewall-cmd", "--state"])
        if out is not None:
            facts.firewall_tool = "firewalld"
            facts.firewall_active = out.strip() == "running"
            return
    if shutil.which("nft"):
        out = _run(["nft", "list", "ruleset"])
        if out is not None:
            facts.firewall_tool = "nftables"
            facts.firewall_active = _nft_has_rules(out)
            return
    if shutil.which("iptables"):
        out = _run(["iptables", "-S"])
        if out is not None:
            facts.firewall_tool = "iptables"
            facts.firewall_active = _iptables_has_rules(out)
            return
    facts.notes.append("no firewall tool detected (ufw/firewalld/nftables/iptables)")


def _nft_has_rules(out: str) -> bool:
    lowered = out.lower()
    return "chain" in lowered and ("drop" in lowered or "reject" in lowered)


def _iptables_has_rules(out: str) -> bool:
    if "-P INPUT DROP" in out or "-P INPUT REJECT" in out:
        return True
    return "-A INPUT" in out and ("DROP" in out or "REJECT" in out)


def _collect_auto_updates(facts: Facts) -> None:
    apt = _read("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt is not None:
        facts.auto_updates = parsers.parse_apt_periodic(apt)
        return
    if shutil.which("systemctl"):
        out = _run(["systemctl", "is-enabled", "dnf-automatic.timer"])
        if out is not None:
            facts.auto_updates = out.strip() == "enabled"
            return
    facts.notes.append("could not determine automatic-update status")


def _collect_fail2ban(facts: Facts) -> None:
    if not shutil.which("systemctl"):
        return
    out = _run(["systemctl", "is-active", "fail2ban"])
    if out is not None and out.strip():
        facts.fail2ban_active = out.strip() == "active"


def _collect_sudoers(facts: Facts) -> None:
    texts = []
    main = _read("/etc/sudoers")
    if main:
        texts.append(main)
    try:
        for entry in Path("/etc/sudoers.d").iterdir():
            text = _read(str(entry))
            if text:
                texts.append(text)
    except OSError:
        pass
    if not texts:
        if not facts.is_root:
            facts.notes.append("sudoers not readable (run as root to check NOPASSWD rules)")
        return
    for text in texts:
        facts.nopasswd_sudo.extend(parsers.parse_sudoers(text))


def _collect_shadow(facts: Facts) -> None:
    text = _read("/etc/shadow")
    if text is None:
        if not facts.is_root:
            facts.notes.append(
                "/etc/shadow not readable (run as root to check for empty passwords)"
            )
        return
    facts.empty_password_users = parsers.parse_shadow_empty(text)


def _collect_listeners(facts: Facts) -> None:
    out = _run(["ss", "-H", "-tuln"]) if shutil.which("ss") else None
    if out is None:
        facts.notes.append("could not list listening sockets (ss unavailable)")
        return
    facts.listeners = parsers.parse_ss_listeners(out)
