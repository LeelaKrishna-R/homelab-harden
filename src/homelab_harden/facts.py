from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    message: str
    fix: str


@dataclass
class SshConfig:
    permit_root_login: str | None = None
    password_authentication: str | None = None
    permit_empty_passwords: str | None = None
    source: str = "unavailable"


@dataclass
class Listener:
    proto: str
    address: str
    port: int
    process: str | None = None


@dataclass
class Facts:
    platform: str
    is_root: bool = False
    ssh: SshConfig | None = None
    firewall_active: bool | None = None
    firewall_tool: str | None = None
    auto_updates: bool | None = None
    fail2ban_active: bool | None = None
    nopasswd_sudo: list[str] = field(default_factory=list)
    empty_password_users: list[str] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
