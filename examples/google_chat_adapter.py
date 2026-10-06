"""Google Chat adapter: a small web service that answers @mentions and DMs with GTI investigations.

STARTER EXAMPLE: copy this file and adapt it (prompt policy, rendering, access control).
It is a working starting point, not a hardened product.

Chat app setup (Google Cloud console > Google Chat API > Configuration):
  * Connection settings: HTTP endpoint URL = https://<your-service-url>/
  * Authentication audience: HTTP endpoint URL
  * Enable "Join spaces and group conversations" if you want it in spaces, not only DMs.

Run locally (expose it with a tunnel so Chat can reach it):
    pip install -e ".[chat]"
    export VT_API_KEY=... CHAT_AUDIENCE=https://<your-tunnel-url>/
    uvicorn examples.google_chat_adapter:app --port 8080

On Cloud Run the runtime service account supplies the Chat API credentials. These flags matter:
    --set-secrets=VT_API_KEY=<vt-secret>:latest
    --set-env-vars=CHAT_AUDIENCE=https://<service-url>/
    --no-cpu-throttling --min-instances=1
The investigation keeps running after the webhook returns, so CPU must stay allocated
between requests.
"""

import asyncio
import io
import logging
import os
import re
import time

import google.auth
import google.auth.transport.requests
from fastapi import FastAPI, HTTPException, Request
from google.oauth2 import id_token
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from gti_relay import GTIRelay, InvestigationResult, ProgressUpdate

logger = logging.getLogger("gti_chat")
app = FastAPI()
relay = GTIRelay()  # reads VT_API_KEY

CHAT_AUDIENCE = os.environ["CHAT_AUDIENCE"]  # must match the "HTTP endpoint URL" exactly
CHAT_ISSUER = "chat@system.gserviceaccount.com"
PROGRESS_EVERY_SECONDS = 3.0
MAX_TEXT = 4000  # split long reports so each message stays well under Chat's size limit

# CUSTOMIZE 1: prompt policy appended to every request (see examples/cli.py)
PROMPT_SUFFIX = ""

_creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/chat.bot"])
chat = build("chat", "v1", credentials=_creds, cache_discovery=False)


@app.post("/")
async def webhook(request: Request) -> dict:
    _verify(request.headers.get("authorization", ""))
    event = await request.json()
    # Classic HTTP Chat apps send {"type", "message", "space"}; add-on based apps nest it under "chat".
    payload = event.get("chat", {}).get("messagePayload", event)
    message = payload.get("message") or {}
    text = (message.get("argumentText") or message.get("text") or "").strip()
    if not text:
        return {}  # ADDED_TO_SPACE, REMOVED_FROM_SPACE, card clicks, etc.

    space = payload.get("space", {}).get("name") or message.get("space", {}).get("name")
    thread = message.get("thread", {}).get("name")
    task = asyncio.create_task(_investigate(text, space, thread, message.get("attachment") or []))
    _running.add(task)  # asyncio keeps only a weak reference to tasks
    task.add_done_callback(_running.discard)
    return {}  # reply asynchronously; Chat only waits ~30 s for a synchronous answer


_running: set[asyncio.Task] = set()


async def _investigate(text: str, space: str, thread: str | None, attachments: list) -> None:
    placeholder = await _post(space, thread, "Investigating…")
    loop = asyncio.get_running_loop()
    pending: list[asyncio.Future] = []
    last = 0.0

    def on_progress(u: ProgressUpdate) -> None:  # CUSTOMIZE 2: progress display
        nonlocal last
        if time.monotonic() - last < PROGRESS_EVERY_SECONDS:
            return  # Chat throttles rapid edits; dropping intermediate updates is fine
        last = time.monotonic()
        pending.append(loop.create_task(_edit(placeholder, f"_{u.kind}: {u.detail[:150]}_")))

    file, file_name = await asyncio.to_thread(_download_first, attachments)
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
    await _edit(placeholder, chunks[0])
    for chunk in chunks[1:]:
        await _post(space, thread, chunk)


def render(r: InvestigationResult) -> str:  # CUSTOMIZE 3: swap for Cards V2 if you want richer layout
    if not r.ok:
        return f"Investigation {r.status}: {r.error}"
    parts = [_to_chat_markup(r.markdown)]
    for w in r.widgets_of_type("MITRE_TREE"):
        parts.append("*MITRE ATT&CK*")
        for tactic in w["mitre_tree_widget"].get("tree", {}).get("tactics", []):
            techs = ", ".join(f"{t.get('id')} {t.get('name')}" for t in tactic.get("techniques", []))
            parts.append(f"• *{tactic.get('name')}*: {techs}")
    for w in r.widgets_of_type("GRAPH"):
        g = w["graph_widget"]
        parts.append(f"*{g.get('title', 'Diagram')}*\n```\n{g.get('source', '')}\n```")
    return "\n\n".join(p for p in parts if p)


# --- Google Chat plumbing --------------------------------------------------------


def _verify(authorization: str) -> None:
    """Reject requests that don't carry a Google-signed ID token issued to Google Chat for this URL."""
    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = id_token.verify_oauth2_token(token, google.auth.transport.requests.Request(), audience=CHAT_AUDIENCE)
    except ValueError as e:
        raise HTTPException(401, "invalid token") from e
    if claims.get("email") != CHAT_ISSUER or not claims.get("email_verified"):
        raise HTTPException(401, "not from Google Chat")


async def _post(space: str, thread: str | None, text: str) -> str:
    body = {"text": text, **({"thread": {"name": thread}} if thread else {})}
    msg = await asyncio.to_thread(
        chat.spaces().messages().create(
            parent=space, body=body, messageReplyOption="REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD"
        ).execute
    )
    return msg["name"]


async def _edit(message_name: str, text: str) -> None:
    try:
        await asyncio.to_thread(
            chat.spaces().messages().patch(name=message_name, updateMask="text", body={"text": text}).execute
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("edit failed: %s", e)


def _download_first(attachments: list) -> tuple[bytes | None, str]:
    """Download the first uploaded attachment, if any. Drive links are ignored."""
    for att in attachments:
        ref = att.get("attachmentDataRef", {}).get("resourceName")
        if ref:
            buf = io.BytesIO()
            downloader = MediaIoBaseDownload(buf, chat.media().download_media(resourceName=ref))
            done = False
            while not done:
                _, done = downloader.next_chunk()
            return buf.getvalue(), att.get("contentName", "artifact.bin")
    return None, "artifact.bin"


def _to_chat_markup(md: str) -> str:
    """Chat supports *bold*, _italic_, `code`, and ``` blocks; map the common markdown bits onto that."""
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
