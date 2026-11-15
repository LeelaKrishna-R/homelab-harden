import json

from homelab_harden import cli


def test_demo_exits_one_and_reports_findings(capsys):
    code = cli.main(["--demo", "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["high"] >= 3
    assert any(f["rule"] == "HH001" for f in payload["findings"])


def test_fail_on_none_never_fails(capsys):
    assert cli.main(["--demo", "--fail-on", "none"]) == 0


def test_fail_on_medium_trips_on_medium(capsys):
    assert cli.main(["--demo", "--fail-on", "medium"]) == 1


def test_clean_host_exits_zero(monkeypatch, capsys):
    from homelab_harden.sample import sample_clean_facts

    monkeypatch.setattr(cli, "collect", sample_clean_facts)
    assert cli.main(["--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == []


def test_ignore_silences_an_accepted_rule(capsys):
    cli.main(["--demo", "--json"])
    rules = {f["rule"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "HH006" in rules
    cli.main(["--demo", "--json", "--ignore", "HH006", "--ignore", "hh001,HH002"])
    payload = json.loads(capsys.readouterr().out)
    left = {f["rule"] for f in payload["findings"]}
    assert not left & {"HH006", "HH001", "HH002"} and left
    assert payload["ignored"] == ["HH001", "HH002", "HH006"]


def test_ignoring_every_high_finding_changes_the_exit_code(monkeypatch, capsys):
    cli.main(["--demo", "--json"])
    highs = sorted(
        {
            f["rule"]
            for f in json.loads(capsys.readouterr().out)["findings"]
            if f["severity"] == "high"
        }
    )
    assert cli.main(["--demo", "--ignore", ",".join(highs)]) == 0
    assert "ignored" in capsys.readouterr().out


def test_an_unknown_rule_id_is_a_usage_error(capsys):
    import pytest

    with pytest.raises(SystemExit) as e:
        cli.main(["--demo", "--ignore", "HH999"])
    assert e.value.code == 2


def test_list_rules_prints_every_rule_and_exits_zero(capsys):
    assert cli.main(["--list-rules"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 11 and lines[0].startswith("HH001  high")
    assert any(line.startswith("HH006  medium") and "fail2ban" in line for line in lines)


def test_every_rule_the_audit_can_raise_is_listed(capsys):
    from homelab_harden.rules import RULES, evaluate
    from homelab_harden.sample import sample_insecure_facts

    for f in evaluate(sample_insecure_facts()):
        assert f.rule in RULES and RULES[f.rule][0] == f.severity, f
