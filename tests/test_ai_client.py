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


def test_tool_messages_refused_retried_as_plain_text(monkeypatch):
    """Some servers / chat templates answer 400 once the history holds tool messages: send them as text instead."""
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)
    seen = []

    def handler(req):
        msgs = json.loads(req.content)["messages"]
        seen.append([m["role"] for m in msgs])
        if any(m["role"] == "tool" for m in msgs):
            return httpx.Response(400, content=b"")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "done"}}]})

    history = [{"role": "user", "content": "check alert"},
               {"role": "assistant", "content": "", "tool_calls": [
                   {"id": "c1", "type": "function", "function": {"name": "list_alerts", "arguments": "{}"}}]},
               {"role": "tool", "tool_call_id": "c1", "content": "[]"}]

    async def main():
        async with httpx.AsyncClient(base_url="https://ai.example/v1/", transport=httpx.MockTransport(handler)) as client:
            return await Analyst(Settings(**{**S.__dict__, "ai_stream": False}))._complete(client, history)
    msg = asyncio.run(main())
    assert msg["content"] == "done"
    assert seen == [["user", "assistant", "tool"], ["user", "assistant", "user"]]


def test_invalid_tool_arguments_become_empty_object():
    assert ai._valid_json('{"query": "SELECT') == "{}"
    assert ai._valid_json('{"a": 1}') == '{"a": 1}'
    assert ai._valid_json(None) == "{}"


def test_no_empty_text_next_to_tool_calls():
    """Anthropic (behind OmniRoute / LiteLLM) refuses empty text blocks with HTTP 400."""
    sent = []

    def handler(req):
        sent.append(json.loads(req.content)["messages"])
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    history = [{"role": "user", "content": "x"},
               {"role": "assistant", "content": "", "tool_calls": [
                   {"id": "c1", "type": "function", "function": {"name": "list_alerts", "arguments": "{}"}}]},
               {"role": "tool", "tool_call_id": "c1", "content": ""}]

    async def main():
        async with httpx.AsyncClient(base_url="https://ai.example/v1/", transport=httpx.MockTransport(handler)) as client:
            await Analyst(Settings(**{**S.__dict__, "ai_stream": False}))._complete(client, history)
    asyncio.run(main())
    assert sent[0][1]["content"] is None and sent[0][2]["content"] == "(no output)"
    assert history[1]["content"] == ""  # the stored conversation is left as it is


def test_dropped_stream_retried_without_streaming(monkeypatch):
    """'peer closed connection without sending complete message body': the next try is a normal request."""
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)
    seen = []

    def handler(req):
        seen.append(bool(json.loads(req.content).get("stream")))
        if seen[-1]:
            raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "plain"}}]})
    a, msg = run(handler)
    assert msg["content"] == "plain" and seen == [True, False] and not a._no_stream


def test_last_try_shortens_older_tool_results(monkeypatch):
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)
    sizes = []

    def handler(req):
        msgs = json.loads(req.content)["messages"]
        sizes.append([len(m["content"]) for m in msgs if m["role"] == "tool"])
        if len(sizes) < 3:
            raise httpx.RemoteProtocolError("peer closed connection")
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    def call(i):
        return {"role": "assistant", "content": "", "tool_calls": [
            {"id": f"c{i}", "type": "function", "function": {"name": "list_alerts", "arguments": "{}"}}]}

    history = [{"role": "user", "content": "x"}, call(1), {"role": "tool", "tool_call_id": "c1", "content": "a" * 20000},
               call(2), {"role": "tool", "tool_call_id": "c2", "content": "b" * 20000}]

    async def main():
        async with httpx.AsyncClient(base_url="https://ai.example/v1/", transport=httpx.MockTransport(handler)) as client:
            return await Analyst(S)._complete(client, history, step=3)
    assert asyncio.run(main())["content"] == "ok"
    assert sizes[:2] == [[20000, 20000]] * 2 and sizes[2][0] < 5000 and sizes[2][1] == 20000
    assert len(history[2]["content"]) == 20000  # the stored conversation is left as it is


def test_error_explains_a_dropped_connection(monkeypatch):
    monkeypatch.setattr(ai.asyncio, "sleep", no_wait)

    def handler(req):
        raise httpx.RemoteProtocolError("peer closed connection without sending complete message body")
    try:
        run(handler, step=5)
    except RuntimeError as exc:
        text = str(exc)
    assert "closed the connection" in text and "step 5" in text and "num_ctx" in text
