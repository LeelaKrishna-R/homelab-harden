from __future__ import annotations

import re

from homelab_harden.facts import Listener, SshConfig

_SSH_KEYS = {
    "permitrootlogin",
    "passwordauthentication",
    "permitemptypasswords",
    "maxauthtries",
    "x11forwarding",
    "permituserenvironment",
}
_PROC_NAME = re.compile(r'\("([^"]+)"')


def parse_sshd_config(text: str, source: str = "config file") -> SshConfig:
    found: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key = parts[0].lower()
        if key in _SSH_KEYS and key not in found:
            found[key] = parts[1].strip().strip('"')
    return SshConfig(
        permit_root_login=found.get("permitrootlogin"),
        password_authentication=found.get("passwordauthentication"),
        permit_empty_passwords=found.get("permitemptypasswords"),
        max_auth_tries=found.get("maxauthtries"),
        x11_forwarding=found.get("x11forwarding"),
        permit_user_environment=found.get("permituserenvironment"),
        source=source,
    )


def parse_ufw_status(text: str) -> bool | None:
    for line in text.splitlines():
        s = line.strip().lower()
        if s.startswith("status:"):
            if "inactive" in s:
                return False
            return "active" in s
    return None


def parse_apt_periodic(text: str) -> bool:
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if "Unattended-Upgrade" in line and '"1"' in line:
            return True
    return False


def parse_sudoers(text: str) -> list[str]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "NOPASSWD" in line:
            out.append(line)
    return out


def parse_shadow_empty(text: str) -> list[str]:
    users = []
    for raw in text.splitlines():
        parts = raw.split(":")
        if len(parts) >= 2 and parts[1] == "":
            users.append(parts[0])
    return users


def parse_ss_listeners(text: str) -> list[Listener]:
    listeners = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        host, sep, port = fields[4].rpartition(":")
        if not sep or not port.isdigit():
            continue
        process = None
        if "users:" in fields[-1]:
            match = _PROC_NAME.search(fields[-1])
            process = match.group(1) if match else None
        listeners.append(
            Listener(proto=fields[0], address=host.strip("[]"), port=int(port), process=process)
        )
    return listeners
