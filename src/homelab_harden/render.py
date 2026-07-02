from __future__ import annotations

import os
import sys

from homelab_harden.facts import Facts, Finding

_TAG = {"high": "HIGH", "medium": "MED ", "low": "LOW "}
_COLOR = {
    "high": "\x1b[31m",
    "medium": "\x1b[33m",
    "low": "\x1b[90m",
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "dim": "\x1b[2m",
}


def use_color(stream=sys.stdout) -> bool:
    return stream.isatty() and not os.environ.get("NO_COLOR")


def counts(findings: list[Finding]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if f.severity == sev) for sev in ("high", "medium", "low")}


def render_report(facts: Facts, findings: list[Finding], color: bool) -> str:
    def paint(code: str) -> str:
        return _COLOR[code] if color else ""

    lines = [f"{paint('bold')}homelab-harden{paint('reset')}  {facts.platform} host", ""]
    if not findings:
        lines.append("  No issues found.")
    else:
        for f in findings:
            lines.append(f"  {paint(f.severity)}[{_TAG[f.severity]}]{paint('reset')} {f.message}")
            lines.append(f"         {paint('dim')}-> {f.fix}{paint('reset')}")
        n = counts(findings)
        lines += ["", f"  {n['high']} high, {n['medium']} medium, {n['low']} low"]
    for note in facts.notes:
        lines.append(f"  {paint('dim')}note: {note}{paint('reset')}")
    return "\n".join(lines)
