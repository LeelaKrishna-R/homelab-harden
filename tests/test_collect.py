from homelab_harden import collect, parsers


def test_sshd_config_includes_are_read_in_place(tmp_path):
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "50-cloud-init.conf").write_text("PasswordAuthentication yes\n")
    (d / "60-local.conf").write_text("PasswordAuthentication no\nPermitRootLogin no\n")
    main = tmp_path / "sshd_config"
    main.write_text(f"Include {d}/*.conf\nPasswordAuthentication no\nX11Forwarding yes\n")

    cfg = parsers.parse_sshd_config(collect.read_sshd_config(str(main)))

    # sshd keeps the first value it sees: 50-cloud-init.conf wins over the main file's "no"
    assert cfg.password_authentication == "yes"
    assert cfg.permit_root_login == "no"
    assert cfg.x11_forwarding == "yes"


def test_an_include_that_matches_nothing_or_loops_is_harmless(tmp_path):
    main = tmp_path / "sshd_config"
    main.write_text(f"Include {tmp_path}/missing/*.conf\nInclude {main}\nPermitRootLogin yes\n")
    cfg = parsers.parse_sshd_config(collect.read_sshd_config(str(main)))
    assert cfg.permit_root_login == "yes"


def test_an_unreadable_config_is_none(tmp_path):
    assert collect.read_sshd_config(str(tmp_path / "nope")) is None
