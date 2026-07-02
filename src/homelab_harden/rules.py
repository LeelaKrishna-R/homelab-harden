from __future__ import annotations

from homelab_harden.facts import SEVERITY_RANK, Facts, Finding, SshConfig

SENSITIVE_PORTS = {
    1433: "SQL Server",
    2375: "Docker API",
    2376: "Docker API",
    3306: "MySQL",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5984: "CouchDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    15672: "RabbitMQ management",
    27017: "MongoDB",
}

_WILDCARD_HOSTS = {"0.0.0.0", "::", "*", ""}


def evaluate(facts: Facts) -> list[Finding]:
    out: list[Finding] = []
    if facts.ssh:
        out += _ssh_rules(facts.ssh)
    out += _firewall_rules(facts)
    out += _updates_rules(facts)
    out += _fail2ban_rules(facts)
    out += _sudo_rules(facts)
    out += _shadow_rules(facts)
    out += _listener_rules(facts)
    return sorted(out, key=lambda f: (-SEVERITY_RANK[f.severity], f.rule))


def _ssh_rules(ssh: SshConfig) -> list[Finding]:
    out = []
    if (ssh.permit_root_login or "").lower() == "yes":
        out.append(
            Finding(
                "HH001",
                "high",
                "SSH permits direct root login (PermitRootLogin yes)",
                "Set `PermitRootLogin no` in /etc/ssh/sshd_config and reload sshd",
            )
        )
    if (ssh.password_authentication or "").lower() == "yes":
        out.append(
            Finding(
                "HH002",
                "high",
                "SSH allows password authentication",
                "Set up key-based login, then set `PasswordAuthentication no` and reload sshd",
            )
        )
    if (ssh.permit_empty_passwords or "").lower() == "yes":
        out.append(
            Finding(
                "HH003",
                "high",
                "SSH permits empty passwords (PermitEmptyPasswords yes)",
                "Set `PermitEmptyPasswords no` in /etc/ssh/sshd_config and reload sshd",
            )
        )
    return out


def _firewall_rules(facts: Facts) -> list[Finding]:
    if facts.firewall_active is False:
        tool = facts.firewall_tool or "firewall"
        return [
            Finding(
                "HH004",
                "high",
                f"No active host firewall ({tool} is not filtering traffic)",
                "Enable a firewall, e.g. `ufw default deny incoming && ufw enable`",
            )
        ]
    return []


def _updates_rules(facts: Facts) -> list[Finding]:
    if facts.auto_updates is False:
        return [
            Finding(
                "HH005",
                "medium",
                "Automatic security updates are not enabled",
                "Enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic.timer (RHEL/Fedora)",
            )
        ]
    return []


def _fail2ban_rules(facts: Facts) -> list[Finding]:
    if facts.fail2ban_active is False:
        return [
            Finding(
                "HH006",
                "medium",
                "fail2ban is not running (no brute-force protection for SSH)",
                "Install and enable it: `apt install fail2ban && systemctl enable --now fail2ban`",
            )
        ]
    return []


def _sudo_rules(facts: Facts) -> list[Finding]:
    if facts.nopasswd_sudo:
        count = len(facts.nopasswd_sudo)
        return [
            Finding(
                "HH007",
                "medium",
                f"Passwordless sudo is configured ({count} NOPASSWD rule(s))",
                "Remove NOPASSWD from sudoers entries unless a specific automation needs it",
            )
        ]
    return []


def _shadow_rules(facts: Facts) -> list[Finding]:
    if facts.empty_password_users:
        users = ", ".join(facts.empty_password_users)
        return [
            Finding(
                "HH008",
                "high",
                f"Accounts with empty passwords: {users}",
                "Set a password (`passwd <user>`) or lock the account (`passwd -l <user>`)",
            )
        ]
    return []


def _listener_rules(facts: Facts) -> list[Finding]:
    out = []
    for listener in facts.listeners:
        if listener.address not in _WILDCARD_HOSTS:
            continue
        name = SENSITIVE_PORTS.get(listener.port)
        if not name:
            continue
        proc = f" ({listener.process})" if listener.process else ""
        out.append(
            Finding(
                "HH009",
                "high",
                f"{name} is listening on all interfaces at port {listener.port}{proc}",
                f"Bind it to 127.0.0.1 or a LAN IP, or firewall the port; do not expose {name}",
            )
        )
    return out
