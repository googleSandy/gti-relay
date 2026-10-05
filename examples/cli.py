"""Reference adapter: a terminal. Copy this file to start your own adapter.

    export VT_API_KEY=...
    python -m examples.cli "Summarise APT29 TTPs from the last 90 days"
    python -m examples.cli "Deobfuscate this and explain what it does" --file sample.ps1

Every adapter (Slack, Teams, Google Chat, ticketing, CLI) does the same four things.
The numbered CUSTOMIZE markers show where your SOPs plug in.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from gti_agentic import GTIAgent, InvestigationResult, ProgressUpdate

# CUSTOMIZE 1 — Prompt policy.
# Anything you always want appended: output format, required sections, your SIEM's
# query dialect (SPL / KQL / UDM / EQL), your rule format (Sigma / YARA-L / Suricata),
# tone, length, classification markings. Leave empty to send the user's text verbatim.
PROMPT_SUFFIX = ""


def build_prompt(user_text: str) -> str:
    return user_text.strip() + (f"\n\n{PROMPT_SUFFIX}" if PROMPT_SUFFIX else "")


# CUSTOMIZE 2 — Progress display.
def on_progress(u: ProgressUpdate) -> None:
    print(f"[{u.elapsed_seconds:5.0f}s] {u.kind:<11} {u.detail[:120]}", file=sys.stderr)


# CUSTOMIZE 3 — Rendering. Map the API's widgets to whatever your platform shows.
# Widget types seen from the API: MARKDOWN_TEXT, CODE, RULE, GRAPH (mermaid), MITRE_ATTACK.
def render(r: InvestigationResult) -> str:
    out = [f"# {r.status} · session {r.session_id} · {r.execution_time_seconds:.0f}s", ""]
    if not r.ok:
        return "\n".join(out + [f"Error: {r.error}", f"Tools run: {', '.join(r.tools_executed) or 'none'}"])

    out.append(r.markdown)

    for w in r.widgets_of_type("CODE"):
        cw = w["code_widget"]
        out += ["", f"```{cw.get('language', '')}", cw.get("code", ""), "```"]

    for w in r.widgets_of_type("RULE"):
        rw = w["rule_widget"]
        out += ["", "```", rw.get("rule_content", ""), "```"]

    for w in r.widgets_of_type("GRAPH"):
        gw = w["graph_widget"]
        out += ["", f"## {gw.get('title', 'Diagram')}", "```mermaid", gw.get("source", ""), "```"]

    for w in r.widgets_of_type("MITRE_ATTACK"):
        out += ["", "## MITRE ATT&CK"]
        for tactic in w["mitre_attack_widget"].get("attack_matrix", {}).get("tactics", []):
            techs = ", ".join(f"{t.get('id')} {t.get('name')}" for t in tactic.get("techniques", []))
            out.append(f"- **{tactic.get('name')}**: {techs}")

    if r.citations:
        out += ["", "## Citations"]
        out += [f"- {c.get('entity_type')}: {c.get('entity_id')}" for c in r.citations]

    return "\n".join(out)


async def run(prompt: str, file: Path | None, raw: bool) -> int:
    agent = GTIAgent()  # CUSTOMIZE 4 — api_key / timeout_seconds / poll_interval
    result = await agent.investigate(
        build_prompt(prompt),
        file=file.read_bytes() if file else None,
        file_name=file.name if file else "artifact.bin",
        on_progress=on_progress,
    )
    print(json.dumps(result.widgets, indent=2) if raw else render(result))
    return 0 if result.ok else 1


def main() -> None:
    p = argparse.ArgumentParser(description="Run a GTI Agentic investigation from the terminal.")
    p.add_argument("prompt")
    p.add_argument("--file", type=Path, help="Optional artifact to upload (script, sample, log).")
    p.add_argument("--raw", action="store_true", help="Print the final widgets as JSON instead of rendering.")
    a = p.parse_args()
    sys.exit(asyncio.run(run(a.prompt, a.file, a.raw)))


if __name__ == "__main__":
    main()
