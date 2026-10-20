#!/usr/bin/env python3
"""Fake OpenAI-compatible AI endpoint for testing the AI analyst / reports.

    python tools/mock_ai.py [port] [mode]     # base URL http://127.0.0.1:<port>/v1

mode "gateway" (default): like a gateway with a short timeout - normal requests get 504, streamed ones work.
mode "down": every request gets 504.  mode "ok": everything works.
The first call asks for a tool (sql_query), the next one answers.
"""
from __future__ import annotations

import json
import sys

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

MODE = sys.argv[2] if len(sys.argv) > 2 else "gateway"
app = FastAPI()
# a realistic answer (the IPs / names are the ones tools/simulate.py and the mocks produce)
SAMPLE_ANSWER = """## Executive summary
One internal device needs attention now: **192.168.1.33 (office laptop)** shows several independent signs of an
infection. The rest is the usual internet background noise, all blocked.

## Findings
| Severity | Finding | Evidence |
|---|---|---|
| **Critical** | 192.168.1.33 talks to command & control | Allowed connection to 185.100.87.41:9001 (Tor), Zenarmor blocked *update-check.badsite.example* (Command and Control), IDS: *ET MALWARE Cobalt Strike Beacon Observed* |
| **High** | DNS tunneling from 192.168.1.21 | 800 unique subdomains of *exfil-example.net* in 10 minutes |
| **High** | Password guessed on the firewall | 7 failed logins for `root` from 192.168.1.66, then a successful one |
| Low | Port scans from the internet | 203.0.113.5 tried 120 ports - all blocked |

## Recommended actions
1. **Isolate 192.168.1.33**: UniFi Network › Client Devices › *Office laptop* › Block, then scan or reinstall it.
2. Check 192.168.1.21 for the program that queries *exfil-example.net*.
3. Change the `root` password of the firewall and find out who logged in from 192.168.1.66.
"""
GATEWAY_504 = "<html><head><title>504 Gateway Time-out</title></head><body><h1>504 Gateway Time-out</h1>nginx</body></html>"


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    stream = bool(body.get("stream"))
    if MODE == "down" or (MODE == "gateway" and not stream):
        return HTMLResponse(GATEWAY_504, status_code=504)
    used_tool = any(m.get("role") == "tool" for m in body["messages"])
    if not used_tool and body.get("tools"):
        msg = {"role": "assistant", "content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {
            "name": "sql_query", "arguments": json.dumps({"query": "SELECT count(*) FROM events"})}}]}
    else:
        msg = {"role": "assistant", "content": SAMPLE_ANSWER}
    if not stream:
        return JSONResponse({"choices": [{"message": msg}]})

    async def events():
        if msg.get("tool_calls"):
            tc = msg["tool_calls"][0]
            args = tc["function"]["arguments"]
            yield f"data: {json.dumps({'choices': [{'delta': {'tool_calls': [{'index': 0, 'id': 'c1', 'function': {'name': 'sql_query', 'arguments': args[:10]}}]}}]})}\n\n"
            yield f"data: {json.dumps({'choices': [{'delta': {'tool_calls': [{'index': 0, 'function': {'arguments': args[10:]}}]}}]})}\n\n"
        else:
            for word in msg["content"].split(" "):
                yield f"data: {json.dumps({'choices': [{'delta': {'content': word + ' '}}]})}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(events(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 18700, log_level="warning")
