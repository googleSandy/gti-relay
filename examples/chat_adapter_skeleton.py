"""Skeleton chat adapter. Platform SDK calls are left as TODOs on purpose.

Works the same for Slack (bolt), Microsoft Teams (botbuilder), Google Chat (REST),
Mattermost, Discord, or a ticketing webhook. Replace the three TODOs.
"""

import asyncio

from gti_relay import GTIRelay, InvestigationResult, ProgressUpdate

relay = GTIRelay()  # reads VT_API_KEY

# CUSTOMIZE 1 — your prompt policy (see examples/cli.py for the idea)
PROMPT_SUFFIX = ""


async def handle_message(user_text: str, conversation_ref: dict, attachment: bytes | None = None) -> None:
    """Call this from your platform's 'message received' handler.

    ``conversation_ref`` is whatever your platform needs to reply in-thread
    (Slack: channel + thread_ts; Teams: conversation reference; Google Chat: space + thread name).
    """
    placeholder = await post(conversation_ref, "Thinking…")  # TODO 1: platform post → returns message handle
    loop = asyncio.get_running_loop()

    def on_progress(u: ProgressUpdate) -> None:  # CUSTOMIZE 2 — progress display
        loop.create_task(update(placeholder, f"{u.kind}: {u.detail[:150]}"))  # TODO 2: platform edit-message

    result = await relay.investigate(
        user_text + (f"\n\n{PROMPT_SUFFIX}" if PROMPT_SUFFIX else ""),
        file=attachment,
        on_progress=on_progress,
    )
    await update(placeholder, render(result))  # TODO 2 again


def render(r: InvestigationResult) -> str:  # CUSTOMIZE 3 — map widgets to your platform's blocks/cards
    if not r.ok:
        return f"Investigation {r.status}: {r.error}"
    return r.markdown  # start here; add CODE / RULE / GRAPH / MITRE_ATTACK widgets as needed


# --- platform glue (TODO) -------------------------------------------------------

async def post(conversation_ref: dict, text: str):
    raise NotImplementedError("TODO 1: e.g. slack client.chat_postMessage(...), return its ts/id")


async def update(message_handle, text: str) -> None:
    raise NotImplementedError("TODO 2: e.g. slack client.chat_update(...)")
