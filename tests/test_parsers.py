from homelab_harden import parsers


def test_parse_sshd_config_reads_effective_output():
    text = "permitrootlogin yes\npasswordauthentication no\npermitemptypasswords no\n"
    ssh = parsers.parse_sshd_config(text, "sshd -T")
    assert ssh.permit_root_login == "yes"
    assert ssh.password_authentication == "no"
    assert ssh.permit_empty_passwords == "no"
    assert ssh.source == "sshd -T"


def test_parse_sshd_config_first_occurrence_wins_and_ignores_comments():
    text = "# comment\nPermitRootLogin no\nPermitRootLogin yes\n"
    ssh = parsers.parse_sshd_config(text)
    assert ssh.permit_root_login == "no"


def test_parse_ufw_status():
    assert parsers.parse_ufw_status("Status: active\n") is True
    assert parsers.parse_ufw_status("Status: inactive\n") is False
    assert parsers.parse_ufw_status("something else") is None


def test_parse_apt_periodic():
    assert parsers.parse_apt_periodic('APT::Periodic::Unattended-Upgrade "1";') is True
    assert parsers.parse_apt_periodic('APT::Periodic::Unattended-Upgrade "0";') is False
    assert parsers.parse_apt_periodic('// APT::Periodic::Unattended-Upgrade "1";') is False


def test_parse_sudoers_finds_nopasswd_only():
    text = "# header\nroot ALL=(ALL:ALL) ALL\ndeploy ALL=(ALL) NOPASSWD: ALL\n"
    rules = parsers.parse_sudoers(text)
    assert rules == ["deploy ALL=(ALL) NOPASSWD: ALL"]


def test_parse_shadow_empty_flags_only_empty_field():
    text = "root:x:...\nbob::...\nalice:!:...\ncarol:*:...\n"
    assert parsers.parse_shadow_empty(text) == ["bob"]


def test_parse_ss_listeners_handles_ipv4_ipv6_and_process():
    text = (
        'tcp   LISTEN 0 128 0.0.0.0:22   0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        'tcp   LISTEN 0 244 [::]:5432    [::]:*   users:(("postgres",pid=2,fd=7))\n'
        "tcp   LISTEN 0 128 127.0.0.1:6379 0.0.0.0:*\n"
    )
    listeners = parsers.parse_ss_listeners(text)
    assert (listeners[0].address, listeners[0].port, listeners[0].process) == (
        "0.0.0.0",
        22,
        "sshd",
    )
    assert (listeners[1].address, listeners[1].port, listeners[1].process) == (
        "::",
        5432,
        "postgres",
    )
    assert (listeners[2].address, listeners[2].port, listeners[2].process) == (
        "127.0.0.1",
        6379,
        None,
    )


def test_parse_sshd_config_reads_max_auth_tries():
    assert parsers.parse_sshd_config("maxauthtries 10\n", "sshd -T").max_auth_tries == "10"
    assert parsers.parse_sshd_config("MaxAuthTries 3\n").max_auth_tries == "3"


def test_parse_sshd_config_reads_x11_forwarding():
    assert parsers.parse_sshd_config("x11forwarding yes\n", "sshd -T").x11_forwarding == "yes"


def test_parse_sshd_config_reads_permit_user_environment():
    cfg = parsers.parse_sshd_config("permituserenvironment LANG,LC_*\n", "sshd -T")
    assert cfg.permit_user_environment == "LANG,LC_*"


def test_parse_sshd_config_reads_gateway_ports():
    cfg = parsers.parse_sshd_config("gatewayports clientspecified\n", "sshd -T")
    assert cfg.gateway_ports == "clientspecified"


def test_parse_sshd_config_reads_permit_tunnel():
    cfg = parsers.parse_sshd_config("permittunnel point-to-point\n", "sshd -T")
    assert cfg.permit_tunnel == "point-to-point"


def test_parse_sshd_config_ignores_settings_inside_match_blocks():
    text = (
        "PermitRootLogin no\n"
        "Match User backup\n"
        "    PasswordAuthentication yes\n"
        "    PermitRootLogin yes\n"
    )
    ssh = parsers.parse_sshd_config(text)
    assert ssh.permit_root_login == "no"
    assert ssh.password_authentication is None


def test_parse_sshd_config_reads_algorithm_lists():
    cfg = parsers.parse_sshd_config(
        "ciphers aes128-ctr,aes256-cbc\nmacs hmac-sha2-256\nkexalgorithms curve25519-sha256\n"
    )
    assert (cfg.ciphers, cfg.macs, cfg.kex_algorithms) == (
        "aes128-ctr,aes256-cbc",
        "hmac-sha2-256",
        "curve25519-sha256",
    )
