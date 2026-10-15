#!/usr/bin/env python3
"""Drive `kc set` through a pty: feed two hex-encoded inputs at the two prompts.
Exits with kc's exit code."""
import os, pty, sys, select

kc, keychain, svc, acct, in1_hex, in2_hex = sys.argv[1:7]
inputs = [bytes.fromhex(in1_hex) + b"\n", bytes.fromhex(in2_hex) + b"\n"]
prompts = [b"Password:", b"Retype password:"]

pid, fd = pty.fork()
if pid == 0:
    os.execv(kc, [kc, "set", "-s", svc, "-a", acct, "-k", keychain])
    os._exit(127)

buf = b""
sent = 0
pending = None
wpos = 0
while True:
    wset = [fd] if pending is not None else []
    try:
        r, w, _ = select.select([fd], wset, [], 10)
    except (OSError, select.error):
        break
    if fd in w and pending is not None:
        try:
            n = os.write(fd, pending[wpos:wpos + 256])
            wpos += n
        except OSError:
            pass
        if wpos >= len(pending):
            pending = None
            sent += 1
    if fd in r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if sent < 2 and pending is None and prompts[sent] in buf:
            pending = inputs[sent]
            wpos = 0
    elif not r and not w:
        break
try:
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
except ChildProcessError:
    code = 127
os.close(fd)
sys.exit(code)
