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
