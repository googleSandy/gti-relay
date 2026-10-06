"""Tests mock the HTTP API only. No network, no API key, no opinions about content."""

import asyncio

import httpx
import pytest

from gti_relay import GTIRelay

SESSION = "sess-123"

FINAL = {
    "id": "f1",
    "message_type": "AGENT_FINAL_RESPONSE",
    "agent_final_response": {"widgets": [
        {"widget_type": "MARKDOWN_TEXT", "markdown_text_widget": {
            "text": "## Summary\nHello.",
            "gti_citations": [{"entity_type": "ENTITY_TYPE_COLLECTION", "entity_id": "malware--abc"}],
        }},
        {"widget_type": "GRAPH", "graph_widget": {"language": "MERMAID", "title": "Flow", "source": "flowchart TD\nA-->B"}},
    ]},
}


def events_at(stage: int) -> list:
    ev = [{"id": "u1", "message_type": "USER_MESSAGE"}]
    if stage >= 1:
        ev += [
            {"id": "t1", "message_type": "AGENT_THOUGHT", "agent_thought": {"text": "Looking...\nmore"}},
            {"id": "c1", "message_type": "FUNCTION_CALL", "function_call": {"name": "search", "args": {"q": "x"}}},
        ]
    if stage >= 2:
        ev.append(FINAL)
    return ev


def patch_client(monkeypatch, handler):
    real = httpx.AsyncClient

    class Patched(real):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Patched)


@pytest.fixture
def happy_api(monkeypatch):
    state = {"polls": 0, "posted": False}

    async def handler(req: httpx.Request) -> httpx.Response:
        p, m = req.url.path, req.method
        if m == "GET" and p.endswith("/agentspace/sessions"):
            return httpx.Response(200, json={"data": [{"id": SESSION if state["posted"] else "old"}]})
        if m == "POST" and p.endswith("/agentspace/sessions"):
            state["posted"] = True
            while state["polls"] < 3:  # real API: POST returns only after the final response exists
                await asyncio.sleep(0.02)
            return httpx.Response(200, headers={"x-session-id": SESSION}, json={})
        if m == "GET" and p.endswith(f"/agentspace/sessions/{SESSION}"):
            state["polls"] += 1
            return httpx.Response(200, json={"data": {"attributes": {"events": events_at(min(state["polls"] - 1, 2))}}})
        return httpx.Response(404)

    patch_client(monkeypatch, handler)
    return state


async def test_streams_progress_and_returns_raw_widgets(happy_api):
    seen = []
    r = await GTIRelay(api_key="k", poll_interval=0.05).investigate("anything", on_progress=seen.append)

    assert r.ok and r.session_id == SESSION
    assert [u.kind for u in seen] == ["THOUGHT", "TOOL_CALL"]
    assert seen[0].detail == "Looking..." and seen[0].event["id"] == "t1"
    assert r.tools_executed == ["search"]

    assert r.widgets == FINAL["agent_final_response"]["widgets"]  # verbatim
    assert r.markdown == "## Summary\nHello."
    assert r.citations[0]["entity_id"] == "malware--abc"
    assert r.widgets_of_type("GRAPH")[0]["graph_widget"]["source"].startswith("flowchart")
    assert any(e["id"] == "f1" for e in r.events)


async def test_prompt_is_sent_verbatim(monkeypatch):
    captured = {}

    async def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            captured["body"] = req.content
            return httpx.Response(200, headers={"x-session-id": SESSION}, json={})
        if req.url.path.endswith(f"/{SESSION}"):
            return httpx.Response(200, json={"data": {"attributes": {"events": [FINAL]}}})
        return httpx.Response(200, json={"data": []})

    patch_client(monkeypatch, handler)
    await GTIRelay(api_key="k", poll_interval=0.01).investigate("exactly this", file=b"abc", file_name="a.ps1")
    assert b"exactly this" in captured["body"] and b'filename="a.ps1"' in captured["body"]


async def test_timeout(monkeypatch):
    async def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            await asyncio.sleep(10)
        return httpx.Response(200, json={"data": []})

    patch_client(monkeypatch, handler)
    r = await GTIRelay(api_key="k", poll_interval=0.05, timeout_seconds=0.5).investigate("x")
    assert r.status == "TIMEOUT" and not r.ok and r.error


async def test_post_finishes_without_final_response(monkeypatch):
    async def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(200, headers={"x-session-id": SESSION}, json={})
        if req.url.path.endswith(f"/{SESSION}"):
            return httpx.Response(200, json={"data": {"attributes": {"events": events_at(1)}}})
        return httpx.Response(200, json={"data": []})

    patch_client(monkeypatch, handler)
    r = await GTIRelay(api_key="k", poll_interval=0.01).investigate("x")
    assert r.status == "FAILED" and r.tools_executed == ["search"] and r.widgets == []


def test_requires_api_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(ValueError):
        GTIRelay()
