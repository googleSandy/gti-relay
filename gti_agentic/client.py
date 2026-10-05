"""Minimal async client for the Google Threat Intelligence Agentic API.

Depends only on ``httpx``. Holds no opinions about prompts, report layout,
SIEM dialects, or chat platforms — those belong in your adapter.

    agent = GTIAgent(api_key="...")
    result = await agent.investigate("Summarise APT29 TTPs", on_progress=print)
    result.markdown   # MARKDOWN_TEXT widgets joined
    result.widgets    # every final-response widget, untouched
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

__all__ = ["GTIAgent", "InvestigationResult", "ProgressUpdate"]
__version__ = "0.1.0"

logger = logging.getLogger("gti_agentic")
BASE_URL = "https://www.virustotal.com/api/v3"


@dataclass
class ProgressUpdate:
    """Streamed to ``on_progress`` as the agent works."""

    elapsed_seconds: float
    kind: str  # "THOUGHT" | "TOOL_CALL" | "TOOL_RESULT"
    detail: str
    event: Dict[str, Any] = field(repr=False, default_factory=dict)  # raw event, if you need more


@dataclass
class InvestigationResult:
    status: str  # "COMPLETED" | "FAILED" | "TIMEOUT"
    session_id: str
    execution_time_seconds: float
    widgets: List[Dict[str, Any]] = field(default_factory=list)  # AGENT_FINAL_RESPONSE widgets, verbatim
    events: List[Dict[str, Any]] = field(default_factory=list)  # full session event log, verbatim
    tools_executed: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == "COMPLETED"

    @property
    def markdown(self) -> str:
        """All MARKDOWN_TEXT widgets joined. Nothing stripped or rewritten."""
        return "\n\n".join(
            w["markdown_text_widget"]["text"]
            for w in self.widgets
            if w.get("widget_type") == "MARKDOWN_TEXT" and w.get("markdown_text_widget", {}).get("text")
        )

    @property
    def citations(self) -> List[Dict[str, Any]]:
        """``gti_citations`` from every markdown widget (collections, actors, reports...)."""
        return [
            c
            for w in self.widgets
            if w.get("widget_type") == "MARKDOWN_TEXT"
            for c in w.get("markdown_text_widget", {}).get("gti_citations", [])
        ]

    def widgets_of_type(self, widget_type: str) -> List[Dict[str, Any]]:
        """e.g. ``widgets_of_type("GRAPH")``, ``"RULE"``, ``"CODE"``, ``"MITRE_ATTACK"``."""
        return [w for w in self.widgets if w.get("widget_type") == widget_type]


class GTIAgent:
    """Run one investigation and return the agent's final response.

    ``POST /agentspace/sessions`` blocks until the agent finishes (often minutes).
    To stream progress we start the POST in the background, discover the new
    session id from the sessions list, and poll ``GET /agentspace/sessions/{id}``.
    """

    _discovery_lock: Optional[asyncio.Lock] = None  # one discovery at a time per process

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: str = BASE_URL,
        poll_interval: float = 2.0,
        timeout_seconds: float = 900.0,
    ):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        if not self.api_key:
            raise ValueError("Pass api_key= or set VT_API_KEY.")
        self.base_url = base_url
        self.poll_interval = poll_interval
        self.timeout_seconds = timeout_seconds

    async def investigate(
        self,
        prompt: str,
        *,
        file: Optional[bytes] = None,
        file_name: str = "artifact.bin",
        session_id: Optional[str] = None,
        on_progress: Optional[Callable[[ProgressUpdate], None]] = None,
    ) -> InvestigationResult:
        """Send ``prompt`` (and optional ``file``) to a new or existing session and wait for the answer."""
        start = time.time()
        tools: List[str] = []
        seen: set = set()
        events: List[Dict[str, Any]] = []
        data = {"message": prompt}
        files = {"files": (file_name, file, "application/octet-stream")} if file else None

        async with httpx.AsyncClient(
            base_url=self.base_url, headers={"x-apikey": self.api_key}, timeout=self.timeout_seconds
        ) as client:
            if session_id:
                post = asyncio.create_task(client.post(f"/agentspace/sessions/{session_id}", data=data, files=files))
            else:
                post, session_id = await self._start_session(client, data, files)

            final: Optional[List[Dict[str, Any]]] = None
            while final is None:
                if session_id:
                    events = await self._events(client, session_id)
                    self._emit(events, seen, start, tools, on_progress)
                    final = _final_widgets(events)
                    if final is not None:
                        break
                if post.done():
                    post_err = None if post.cancelled() else post.exception()
                    if isinstance(post_err, httpx.TimeoutException):
                        return InvestigationResult("TIMEOUT", session_id or "", time.time() - start,
                                                   events=events, tools_executed=tools, error="Exceeded timeout_seconds.")
                    if post_err:
                        logger.warning("POST /agentspace/sessions failed: %s", post_err)
                    elif not session_id:
                        session_id = post.result().headers.get("x-session-id")
                    if session_id:
                        events = await self._events(client, session_id)
                        self._emit(events, seen, start, tools, on_progress)
                        final = _final_widgets(events)
                    break
                if time.time() - start > self.timeout_seconds:
                    post.cancel()
                    return InvestigationResult("TIMEOUT", session_id or "", time.time() - start,
                                               events=events, tools_executed=tools, error="Exceeded timeout_seconds.")
                await asyncio.sleep(self.poll_interval)

            if not post.done():
                post.cancel()

        if final is None:
            return InvestigationResult("FAILED", session_id or "", time.time() - start,
                                       events=events, tools_executed=tools, error="Session ended without a final response.")
        return InvestigationResult("COMPLETED", session_id or "", time.time() - start,
                                   widgets=final, events=events, tools_executed=tools)

    # ------------------------------------------------------------------ internals

    async def _start_session(self, client: httpx.AsyncClient, data: dict, files: Optional[dict]):
        if GTIAgent._discovery_lock is None:
            GTIAgent._discovery_lock = asyncio.Lock()
        async with GTIAgent._discovery_lock:
            before = await self._latest_session_id(client)
            post = asyncio.create_task(client.post("/agentspace/sessions", data=data, files=files))
            deadline = time.time() + min(30.0, self.timeout_seconds)
            while time.time() < deadline:
                if post.done():
                    try:
                        return post, post.result().headers.get("x-session-id")
                    except Exception as e:  # noqa: BLE001
                        logger.error("POST failed: %s", e)
                        return post, None
                now = await self._latest_session_id(client)
                if now and now != before:
                    logger.info("GTI session %s started", now)
                    return post, now
                await asyncio.sleep(0.5)
            return post, None

    @staticmethod
    async def _latest_session_id(client: httpx.AsyncClient) -> Optional[str]:
        try:
            r = await client.get("/agentspace/sessions", params={"limit": 1}, timeout=10.0)
            d = r.json().get("data") or [] if r.status_code == 200 else []
            return d[0].get("id") if d else None
        except Exception as e:  # noqa: BLE001
            logger.debug("list sessions failed: %s", e)
            return None

    @staticmethod
    async def _events(client: httpx.AsyncClient, session_id: str) -> List[Dict[str, Any]]:
        try:
            r = await client.get(f"/agentspace/sessions/{session_id}", timeout=15.0)
            if r.status_code == 200:
                return r.json().get("data", {}).get("attributes", {}).get("events", []) or []
        except Exception as e:  # noqa: BLE001
            logger.debug("poll failed: %s", e)
        return []

    @staticmethod
    def _emit(events, seen, start, tools, on_progress) -> None:
        for ev in events:
            key = ev.get("id") or repr(ev)
            if key in seen:
                continue
            seen.add(key)
            kind, detail, tool = _describe(ev)
            if tool and tool not in tools:
                tools.append(tool)
            if kind and on_progress:
                try:
                    on_progress(ProgressUpdate(time.time() - start, kind, detail, ev))
                except Exception as e:  # noqa: BLE001
                    logger.warning("on_progress raised: %s", e)


def _final_widgets(events: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    for ev in reversed(events):
        if ev.get("message_type") == "AGENT_FINAL_RESPONSE":
            return ev.get("agent_final_response", {}).get("widgets", []) or []
    return None


def _describe(ev: Dict[str, Any]):
    t = ev.get("message_type")
    if t == "AGENT_THOUGHT":
        th = ev.get("agent_thought", {})
        text = th.get("text") or next(
            (w.get("markdown_text_widget", {}).get("text", "") for w in th.get("widgets", []) if w.get("widget_type") == "MARKDOWN_TEXT"),
            "",
        )
        return "THOUGHT", (text.strip().split("\n")[0] if text else "Thinking"), None
    if t == "FUNCTION_CALL":
        c = ev.get("function_call", {})
        name = c.get("name") or c.get("function_id") or "tool"
        return "TOOL_CALL", f"{name}({c.get('args') or c.get('args_json') or ''})", name
    if t == "FUNCTION_RESPONSE":
        return "TOOL_RESULT", f"{ev.get('function_response', {}).get('name') or 'tool'} returned", None
    return None, "", None
