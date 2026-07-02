from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from homelab_harden.collect import collect
from homelab_harden.facts import SEVERITY_RANK
from homelab_harden.render import counts, render_report, use_color
from homelab_harden.rules import evaluate
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
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument(
        "--demo", action="store_true", help="audit bundled sample data (works on any OS)"
    )
    parser.add_argument("--version", action="version", version="homelab-harden 0.1.0")
    args = parser.parse_args(argv)

    facts = sample_insecure_facts() if args.demo else collect()
    findings = evaluate(facts)

    if args.json:
        payload = {
            "platform": facts.platform,
            "summary": counts(findings),
            "findings": [asdict(f) for f in findings],
            "notes": facts.notes,
        }
        print(json.dumps(payload, indent=2))
    else:
        color = not args.no_color and use_color()
        print(render_report(facts, findings, color))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    worst = max((SEVERITY_RANK[f.severity] for f in findings), default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
