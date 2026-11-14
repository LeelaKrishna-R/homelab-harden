from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from homelab_harden.collect import collect
from homelab_harden.facts import SEVERITY_RANK
from homelab_harden.render import counts, render_report, use_color
from homelab_harden.rules import RULE_IDS, RULES, evaluate
from homelab_harden.sample import sample_insecure_facts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="homelab-harden",
        description="Read-only security audit of the local Linux host. Never changes anything.",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "none"],
        default="high",
        help="exit non-zero when a finding at or above this severity exists (default: high)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE",
        help="leave out a rule you've accepted, e.g. --ignore HH006 (repeat it or use commas)",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="print every rule id, its severity and what it checks",
    )
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument(
        "--demo", action="store_true", help="audit bundled sample data (works on any OS)"
    )
    parser.add_argument("--version", action="version", version="homelab-harden 0.1.0")
    args = parser.parse_args(argv)
    if args.list_rules:
        for rule, (severity, what) in RULES.items():
            print(f"{rule}  {severity:<6}  {what}")
        return 0
    ignored = sorted(
        {r.strip().upper() for arg in args.ignore for r in arg.split(",") if r.strip()}
    )
    unknown = [r for r in ignored if r not in RULE_IDS]
    if unknown:
        parser.error(f"unknown rule {', '.join(unknown)} (rules are {RULE_IDS[0]}..{RULE_IDS[-1]})")

    facts = sample_insecure_facts() if args.demo else collect()
    findings = [f for f in evaluate(facts) if f.rule not in ignored]

    if args.json:
        payload = {
            "platform": facts.platform,
            "summary": counts(findings),
            "findings": [asdict(f) for f in findings],
            "notes": facts.notes,
            "ignored": ignored,
        }
        print(json.dumps(payload, indent=2))
    else:
        color = not args.no_color and use_color()
        print(render_report(facts, findings, color, ignored))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
