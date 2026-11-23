from homelab_harden.facts import Facts, Listener, SshConfig
from homelab_harden.rules import evaluate
from homelab_harden.sample import sample_clean_facts, sample_insecure_facts


def rule_ids(findings):
    return {f.rule for f in findings}


def test_clean_sample_has_no_findings():
    assert evaluate(sample_clean_facts()) == []


def test_insecure_sample_flags_expected_rules():
    ids = rule_ids(evaluate(sample_insecure_facts()))
    assert {"HH001", "HH002", "HH004", "HH005", "HH006", "HH007", "HH009"} <= ids


def test_unset_ssh_values_are_not_flagged():
    facts = Facts(platform="linux", ssh=SshConfig())
    assert evaluate(facts) == []


def test_root_login_without_password_is_not_flagged():
    facts = Facts(platform="linux", ssh=SshConfig(permit_root_login="prohibit-password"))
    assert rule_ids(evaluate(facts)) == set()


def test_firewall_unknown_is_not_flagged_but_inactive_is():
    assert evaluate(Facts(platform="linux", firewall_active=None)) == []
    assert rule_ids(evaluate(Facts(platform="linux", firewall_active=False))) == {"HH004"}


def test_listener_rule_only_flags_sensitive_wildcard_ports():
    facts = Facts(
        platform="linux",
        listeners=[
            Listener("tcp", "0.0.0.0", 22, "sshd"),
            Listener("tcp", "127.0.0.1", 5432, "postgres"),
            Listener("tcp", "0.0.0.0", 6379, "redis"),
        ],
    )
    findings = evaluate(facts)
    assert rule_ids(findings) == {"HH009"}
    assert "Redis" in findings[0].message


def test_findings_sorted_high_first():
    severities = [f.severity for f in evaluate(sample_insecure_facts())]
    assert severities == sorted(severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s])


def test_max_auth_tries_flags_only_a_raised_value():
    def audit(tries):
        return evaluate(Facts(platform="linux", ssh=SshConfig(max_auth_tries=tries)))

    for tries in ("6", "3", "junk"):
        assert audit(tries) == []
    found = audit("10")
    assert [(f.rule, f.severity) for f in found] == [("HH010", "low")]
    assert "MaxAuthTries 10" in found[0].message


def test_x11_forwarding_is_flagged_only_when_on():
    def audit(value):
        return rule_ids(evaluate(Facts(platform="linux", ssh=SshConfig(x11_forwarding=value))))

    assert audit("yes") == {"HH011"}
    assert audit("no") == set() and audit(None) == set()


def test_permit_user_environment_is_flagged_unless_no():
    def audit(value):
        return rule_ids(
            evaluate(Facts(platform="linux", ssh=SshConfig(permit_user_environment=value)))
        )

    assert audit("yes") == {"HH012"} and audit("LANG,LC_*") == {"HH012"}
    assert audit("no") == set() and audit(None) == set()


def test_gateway_ports_is_flagged_unless_no():
    def audit(value):
        return rule_ids(evaluate(Facts(platform="linux", ssh=SshConfig(gateway_ports=value))))

    assert audit("yes") == {"HH013"} and audit("clientspecified") == {"HH013"}
    assert audit("no") == set() and audit("No") == set() and audit(None) == set()


def test_permit_tunnel_is_flagged_unless_no():
    def audit(value):
        return rule_ids(evaluate(Facts(platform="linux", ssh=SshConfig(permit_tunnel=value))))

    for value in ("yes", "ethernet", "point-to-point"):
        assert audit(value) == {"HH014"}
    assert audit("no") == set() and audit("No") == set() and audit(None) == set()


def test_weak_ssh_algorithms_are_flagged_and_a_removal_is_not():
    def audit(**kw):
        return rule_ids(evaluate(Facts(platform="linux", ssh=SshConfig(**kw))))

    modern = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"
    assert audit(ciphers=modern) == set()
    assert audit(ciphers=modern + ",aes256-cbc") == {"HH015"}
    assert audit(ciphers="+3des-cbc") == {"HH015"}  # appended to the defaults: still offered
    assert audit(ciphers="-aes256-cbc,3des-cbc") == set()  # a removal list offers nothing
    assert audit(macs="hmac-sha2-256,hmac-md5") == {"HH015"}
    assert audit(kex_algorithms="curve25519-sha256,diffie-hellman-group14-sha1") == {"HH015"}
    assert audit(kex_algorithms="curve25519-sha256,diffie-hellman-group14-sha256") == set()
