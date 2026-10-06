"""Slack adapter: answers @mentions and DMs with GTI investigations, replying in-thread.

STARTER EXAMPLE: copy this file and adapt it (prompt policy, rendering, access control).
It is a working starting point, not a hardened product.

Slack app setup (api.slack.com/apps):
  * Bot token scopes: app_mentions:read, chat:write, files:read, im:history
  * Event Subscriptions: Request URL = https://<your-service-url>/slack/events
    Bot events: app_mention, message.im
  * Install to the workspace, then copy the Bot Token and the Signing Secret.

Run locally (expose it with a tunnel so Slack can reach it):
    pip install -e ".[slack]"
    export VT_API_KEY=... SLACK_BOT_TOKEN=xoxb-... SLACK_SIGNING_SECRET=...
    uvicorn examples.slack_adapter:api --port 8080

On Cloud Run these flags matter:
    --set-secrets=VT_API_KEY=<vt-secret>:latest,SLACK_BOT_TOKEN=<slack-token-secret>:latest,SLACK_SIGNING_SECRET=<slack-signing-secret>:latest
    --no-cpu-throttling --min-instances=1
Bolt acknowledges the event within Slack's 3-second limit and keeps running the investigation
afterwards, so CPU must stay allocated between requests.
"""

import asyncio
import logging
import os
import re
import time

import httpx
from fastapi import FastAPI, Request
from slack_bolt.adapter.fastapi.async_handler import AsyncSlackRequestHandler
from slack_bolt.async_app import AsyncApp

from gti_relay import GTIRelay, InvestigationResult, ProgressUpdate

logger = logging.getLogger("gti_slack")
relay = GTIRelay()  # reads VT_API_KEY
bolt = AsyncApp(token=os.environ["SLACK_BOT_TOKEN"], signing_secret=os.environ["SLACK_SIGNING_SECRET"])

PROGRESS_EVERY_SECONDS = 3.0  # chat.update is rate limited; dropping intermediate updates is fine
MAX_TEXT = 3900  # Slack truncates very long messages; split reports into readable chunks

# CUSTOMIZE 1: prompt policy appended to every request (see examples/cli.py)
PROMPT_SUFFIX = ""


@bolt.event("app_mention")
async def on_mention(event, client):
    if not event["channel"].startswith("D"):  # DMs are handled by on_dm
        await investigate(event, client)


@bolt.event("message")
async def on_dm(event, client):
    if event.get("channel_type") == "im" and not event.get("bot_id") and not event.get("subtype"):
        await investigate(event, client)


async def investigate(event: dict, client) -> None:
    text = re.sub(r"<@[A-Z0-9]+>\s*", "", event.get("text", "")).strip()
    if not text:
        return
    channel, thread_ts = event["channel"], event.get("thread_ts") or event["ts"]
    placeholder = await client.chat_postMessage(channel=channel, thread_ts=thread_ts, text="Investigating…")
    loop = asyncio.get_running_loop()
    pending: list[asyncio.Future] = []
    last = 0.0

    async def edit(new_text: str) -> None:
        try:
            await client.chat_update(channel=channel, ts=placeholder["ts"], text=new_text)
        except Exception as e:  # noqa: BLE001
            logger.warning("chat.update failed: %s", e)

    def on_progress(u: ProgressUpdate) -> None:  # CUSTOMIZE 2: progress display
        nonlocal last
        if time.monotonic() - last < PROGRESS_EVERY_SECONDS:
            return
        last = time.monotonic()
        pending.append(loop.create_task(edit(f"_{u.kind}: {u.detail[:150]}_")))

    file, file_name = await _download_first(event.get("files") or [])
    try:
        result = await relay.investigate(
            text + (f"\n\n{PROMPT_SUFFIX}" if PROMPT_SUFFIX else ""),
            file=file,
            file_name=file_name,
            on_progress=on_progress,
        )
        chunks = _split(render(result))
    except Exception as e:  # noqa: BLE001
        logger.exception("investigation failed")
        chunks = [f"Investigation failed: {e}"]

    await asyncio.gather(*pending, return_exceptions=True)  # so a late progress edit can't overwrite the answer
    await edit(chunks[0])
    for chunk in chunks[1:]:
        await client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=chunk)


def render(r: InvestigationResult) -> str:  # CUSTOMIZE 3: swap for Block Kit if you want richer layout
    if not r.ok:
        return f"Investigation {r.status}: {r.error}"
    parts = [_to_mrkdwn(r.markdown)]
    for w in r.widgets_of_type("MITRE_TREE"):
        parts.append("*MITRE ATT&CK*")
        for tactic in w["mitre_tree_widget"].get("tree", {}).get("tactics", []):
            techs = ", ".join(f"{t.get('id')} {t.get('name')}" for t in tactic.get("techniques", []))
            parts.append(f"• *{tactic.get('name')}*: {techs}")
    for w in r.widgets_of_type("GRAPH"):
        g = w["graph_widget"]
        parts.append(f"*{g.get('title', 'Diagram')}*\n```\n{g.get('source', '')}\n```")
    return "\n\n".join(p for p in parts if p)


# --- Slack plumbing --------------------------------------------------------------


async def _download_first(files: list) -> tuple[bytes | None, str]:
    """Download the first file shared with the message (needs the files:read scope)."""
    for f in files:
        url = f.get("url_private_download")
        if url:
            async with httpx.AsyncClient(follow_redirects=True, timeout=60) as http:
                r = await http.get(url, headers={"Authorization": f"Bearer {os.environ['SLACK_BOT_TOKEN']}"})
                r.raise_for_status()
            return r.content, f.get("name", "artifact.bin")
    return None, "artifact.bin"


def _to_mrkdwn(md: str) -> str:
    """Map the common markdown bits onto Slack mrkdwn."""
    md = re.sub(r"^#{1,6}\s*(.+)$", r"*\1*", md, flags=re.M)  # headings -> bold line
    md = re.sub(r"\*\*(.+?)\*\*", r"*\1*", md)  # **bold** -> *bold*
    md = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r"<\2|\1>", md)  # [text](url) -> <url|text>
    return re.sub(r"^(\s*)[-*] ", r"\1• ", md, flags=re.M)


def _split(text: str) -> list[str]:
    chunks, current = [], ""
    for para in text.split("\n\n"):
        if current and len(current) + len(para) + 2 > MAX_TEXT:
            chunks.append(current)
            current = ""
        current = f"{current}\n\n{para}" if current else para
        while len(current) > MAX_TEXT:  # a single huge paragraph
            chunks.append(current[:MAX_TEXT])
            current = current[MAX_TEXT:]
    return [*chunks, current] if current else chunks or [""]


api = FastAPI()
handler = AsyncSlackRequestHandler(bolt)


@api.post("/slack/events")
async def slack_events(req: Request):
    return await handler.handle(req)  # verifies the Slack signature before any listener runs
