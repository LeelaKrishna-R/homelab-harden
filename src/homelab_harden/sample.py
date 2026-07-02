from __future__ import annotations

from homelab_harden.facts import Facts, Listener, SshConfig


def sample_insecure_facts() -> Facts:
    return Facts(
        platform="linux (sample)",
        is_root=True,
        ssh=SshConfig(
            permit_root_login="yes",
            password_authentication="yes",
            permit_empty_passwords="no",
            source="sample",
        ),
        firewall_active=False,
        firewall_tool="ufw",
        auto_updates=False,
        fail2ban_active=False,
        nopasswd_sudo=["deploy ALL=(ALL) NOPASSWD: ALL"],
        listeners=[
            Listener("tcp", "0.0.0.0", 5432, "postgres"),
            Listener("tcp", "0.0.0.0", 22, "sshd"),
        ],
        notes=["sample data shown by --demo; run without --demo on a Linux host to audit it"],
    )


def sample_clean_facts() -> Facts:
    return Facts(
        platform="linux (sample)",
        is_root=True,
        ssh=SshConfig(
            permit_root_login="no",
            password_authentication="no",
            permit_empty_passwords="no",
            source="sample",
        ),
        firewall_active=True,
        firewall_tool="ufw",
        auto_updates=True,
        fail2ban_active=True,
        listeners=[
            Listener("tcp", "127.0.0.1", 5432, "postgres"),
            Listener("tcp", "0.0.0.0", 22, "sshd"),
        ],
    )
