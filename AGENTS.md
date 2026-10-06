# AGENTS.md

Instructions for coding agents working in this repo. Humans: see README.md.

## What this is

`gti_relay` is a thin async relay to the Google Threat Intelligence (GTI) Agentic API
(`https://www.virustotal.com/api/v3/agentspace`). GTI hosts the agent and the LLM. This code sends
a prompt (and optional file), polls for progress, and returns the agent's widgets verbatim.
It is not an agent and makes no model calls. Keep it that way.

## Layout

| Path | Role | Edit? |
|---|---|---|
| `gti_relay/client.py` | `GTIRelay`, `InvestigationResult`, `ProgressUpdate` | Only for GTI API changes or bugs |
| `examples/cli.py` | terminal adapter, the reference for `CUSTOMIZE` markers | Copy, then edit |
| `examples/google_chat_adapter.py` | starter Google Chat app (FastAPI) | Copy, then edit |
| `examples/slack_adapter.py` | starter Slack app (Bolt + FastAPI) | Copy, then edit |
| `examples/chat_adapter_skeleton.py` | template for other platforms (Teams, Mattermost, ...) | Copy, then edit |
| `tests/` | offline tests with a mocked API | Add tests for new code |
| `docs/architecture.svg` | hand-written SVG diagram | Update if the flow changes |
| `Dockerfile` | one image for the adapters; `APP` env var picks the module | As needed |

## Where users customize

Each adapter has numbered markers. Search for `CUSTOMIZE`:

1. `PROMPT_SUFFIX`: prompt policy appended to every request (SOP sections, SIEM dialect such as
   SPL / KQL / UDM, rule format such as Sigma / YARA-L, tone, classification markings).
2. `on_progress`: how progress is shown. Keep it throttled; chat APIs rate-limit message edits.
3. `render()`: maps `result.widgets` to the platform's format (plain text, Cards V2, Block Kit).
4. `GTIRelay(...)` arguments: `timeout_seconds`, `poll_interval`, `base_url`.

When asked to customize, prefer copying an example to a new file (for example `adapters/<name>.py`)
over editing the example in place, unless the user says otherwise.

## Rules

* Do not add LLM calls, prompt rewriting, or output post-processing to `gti_relay/`. Policy belongs
  in adapters. `GTIRelay` sends the user's prompt verbatim and returns widgets verbatim.
* Secrets come only from environment variables (`VT_API_KEY`, `SLACK_BOT_TOKEN`,
  `SLACK_SIGNING_SECRET`, `CHAT_AUDIENCE`). Never read `.env` files, never hard-code or log keys.
  The key travels as the `x-apikey` header, set once on the HTTP client in `client.py`.
* Keep request verification in adapters: Google Chat ID-token check, Slack signing secret (Bolt).
* `gti_relay` depends only on `httpx`. Adapter dependencies go in the `chat` / `slack` extras in
  `pyproject.toml`, or in a new extra.
* Long investigations (up to 15 min) continue after the webhook returns. On Cloud Run this needs
  `--no-cpu-throttling`. Don't move the investigation into the request/response path.
* Sending output to third parties (for example rendering mermaid with mermaid.ink) leaks
  investigation content. Only add that if the user asks for it explicitly.
* Widget types and fields are listed in README "What you get back". Run
  `python -m examples.cli "<question>" --raw` to see real payloads before writing a renderer.

## Common requests

* **New platform:** copy `examples/chat_adapter_skeleton.py`, fill in its three TODOs, verify the
  platform's request signature, and throttle progress edits.
* **Richer layout:** replace `render()` with Cards V2 (Google Chat) or Block Kit (Slack). Keep a
  plain-text fallback, and split output to the platform's message limits.
* **Access control:** anyone who can message the bot spends the GTI quota. Add an allowlist of
  users, spaces, or channels in the adapter if the user wants one.
* **Follow-up questions:** store `result.session_id` per thread and pass it as
  `investigate(..., session_id=...)`.

## Verify

```
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,chat,slack]"
pytest
```

Tests need no network and no API key. Add tests for every new `render()` or helper.
