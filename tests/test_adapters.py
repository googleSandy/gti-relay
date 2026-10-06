"""Offline tests for the example adapters' pure helpers. Skipped if the chat/slack extras aren't installed."""

import os
from unittest import mock

import pytest

from gti_relay import InvestigationResult

os.environ.setdefault("VT_API_KEY", "test")
os.environ.setdefault("CHAT_AUDIENCE", "https://example.test/")
os.environ.setdefault("SLACK_BOT_TOKEN", "xoxb-test")
os.environ.setdefault("SLACK_SIGNING_SECRET", "test")

WIDGETS = [
    {"widget_type": "MARKDOWN_TEXT", "markdown_text_widget": {"text": "## Summary\n**APT29** uses [x](https://a.b)\n- item"}},
    {"widget_type": "MITRE_TREE", "mitre_tree_widget": {"tree": {"tactics": [
        {"id": "TA0001", "name": "Initial Access", "techniques": [{"id": "T1566", "name": "Phishing"}]}]}}},
    {"widget_type": "GRAPH", "graph_widget": {"title": "Flow", "source": "graph TD; A-->B"}},
]


@pytest.fixture(scope="module")
def chat():
    pytest.importorskip("googleapiclient")
    import google.auth

    with mock.patch.object(google.auth, "default", return_value=(mock.Mock(), "p")), \
         mock.patch("googleapiclient.discovery.build"):
        from examples import google_chat_adapter
        yield google_chat_adapter


@pytest.fixture(scope="module")
def slack():
    pytest.importorskip("slack_bolt")
    from examples import slack_adapter
    return slack_adapter


@pytest.fixture(params=["chat", "slack"])
def adapter(request):
    return request.getfixturevalue(request.param)


def test_render_completed(adapter):
    out = adapter.render(InvestigationResult("COMPLETED", "s", 1.0, widgets=WIDGETS))
    assert "*Summary*" in out and "*APT29*" in out and "<https://a.b|x>" in out and "• item" in out
    assert "TA0001" not in out and "*Initial Access*: T1566 Phishing" in out
    assert "graph TD; A-->B" in out


def test_render_failed(adapter):
    out = adapter.render(InvestigationResult("TIMEOUT", "s", 1.0, error="Exceeded timeout_seconds."))
    assert out == "Investigation TIMEOUT: Exceeded timeout_seconds."


def test_split_respects_limit(adapter):
    text = "\n\n".join(["p" * 1000] * 10) + "\n\n" + "x" * (adapter.MAX_TEXT * 2 + 5)
    chunks = adapter._split(text)
    assert all(len(c) <= adapter.MAX_TEXT for c in chunks)
    assert "".join(chunks).replace("\n", "") == text.replace("\n", "")


def test_chat_rejects_unsigned_requests(chat):
    from fastapi.testclient import TestClient

    assert TestClient(chat.app).post("/", json={"message": {"text": "hi"}}).status_code == 401
