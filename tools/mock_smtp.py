"""Tiny SMTP server for testing mail notifications (no TLS - use encryption "none").

    python tools/mock_smtp.py [port] [outdir]       # default 2525, ./mock-mail

Accepts any login (AUTH PLAIN / LOGIN) and stores every mail as <outdir>/<n>.eml.
"""
from __future__ import annotations

import pathlib
import socketserver
import sys

OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "mock-mail")
COUNTER = [0]


class Handler(socketserver.StreamRequestHandler):
    def say(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        self.say("220 mock-smtp ready")
        rcpt: list[str] = []
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            cmd = raw.decode(errors="replace").strip()
            verb = cmd.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250-mock-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif verb == "AUTH":
                parts = cmd.split()
                if parts[1].upper() == "LOGIN":
                    for prompt in ("VXNlcm5hbWU6", "UGFzc3dvcmQ6"):
                        if len(parts) > 2 and prompt == "VXNlcm5hbWU6":
                            continue
                        self.say("334 " + prompt)
                        self.rfile.readline()
                self.say("235 ok")
            elif verb == "MAIL":
                rcpt = []
                self.say("250 ok")
            elif verb == "RCPT":
                rcpt.append(cmd.split(":", 1)[1].strip())
                self.say("250 ok")
            elif verb == "DATA":
                self.say("354 go ahead")
                lines = []
                while (line := self.rfile.readline()) not in (b".\r\n", b".\n", b""):
                    lines.append(line[1:] if line.startswith(b"..") else line)
                COUNTER[0] += 1
                OUT.mkdir(parents=True, exist_ok=True)
                (OUT / f"{COUNTER[0]}.eml").write_bytes(b"".join(lines))
                print(f"mail {COUNTER[0]} to {', '.join(rcpt)}", flush=True)
                self.say("250 queued")
            elif verb == "QUIT":
                self.say("221 bye")
                return
            else:
                self.say("250 ok")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2525
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler) as srv:
        print(f"mock SMTP on 127.0.0.1:{port}, mails go to {OUT}/", flush=True)
        srv.serve_forever()
