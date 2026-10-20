import asyncio
import json

import httpx

from lookingglass import ai
from lookingglass.ai import Analyst
from lookingglass.config import Settings

S = Settings(ai_base_url="https://ai.example/v1", ai_api_key="k", ai_model="m")


_sleep = asyncio.sleep


async def no_wait(_seconds):
    await _sleep(0)


def sse(*chunks: dict) -> bytes:
    return b"".join(f"data: {json.dumps(c)}\n\n".encode() for c in chunks) + b"data: [DONE]\n\n"


def run(handler, settings=S, **kw):
    async def main():
        async with httpx.AsyncClient(base_url="https://ai.example/v1/", transport=httpx.MockTransport(handler)) as client:
            a = Analyst(settings)
            return a, await a._complete(client, [{"role": "user", "content": "hi"}], **kw)
    return asyncio.run(main())


def test_stream_reassembles_content_and_tool_calls():
    def handler(req):
        assert json.loads(req.content)["stream"] is True
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse(
            {"choices": [{"delta": {"content": "Let me "}}]},
            {"choices": [{"delta": {"content": "check."}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "sql_", "arguments": '{"que'}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "query", "arguments": 'ry": "SELECT 1"}'}}]}}]}))
    _, msg = run(handler)
    assert msg["content"] == "Let me check."
    assert msg["tool_calls"] == [{"id": "c1", "type": "function", "function": {"name": "sql_query", "arguments": '{"query": "SELECT 1"}'}}]


def test_504_is_retried(monkeypatch):
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)
    calls = []

    def handler(req):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(504, text="<html><body><h1>504 Gateway Time-out</h1></body></html>")
        return httpx.Response(200, headers={"content-type": "text/event-stream"},
                              content=sse({"choices": [{"delta": {"content": "done"}}]}))
    _, msg = run(handler)
    assert msg["content"] == "done" and len(calls) == 2


def test_endpoint_without_streaming_falls_back(monkeypatch):
    def handler(req):
        if json.loads(req.content).get("stream"):
            return httpx.Response(400, json={"error": {"message": "stream is not supported"}})
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "plain"}}]})
    a, msg = run(handler)
    assert msg["content"] == "plain" and a._no_stream


def test_error_explains_the_504(monkeypatch):
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)

    def handler(req):
        return httpx.Response(504, text="<html><body><center><h1>504 Gateway Time-out</h1></center><hr>nginx</body></html>")
    try:
        run(handler, step=3)
    except RuntimeError as exc:
        text = str(exc)
    assert "HTTP 504 Gateway Timeout" in text and "step 3" in text and "3 attempts" in text
    assert "gave up waiting" in text and "Stream answers" in text and "<h1>" not in text and "504 Gateway Time-out nginx" in text


def test_401_is_not_retried(monkeypatch):
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(401, json={"error": "invalid key"})
    try:
        run(handler)
    except RuntimeError as exc:
        assert "refused" in str(exc)
    assert len(calls) == 1
