"""A blocked collector must keep the interactive progress view alive."""
import fcntl
import os
import pathlib
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


def capture(reader, seconds, until):
    data = b""
    deadline = time.monotonic() + seconds
    while (left := deadline - time.monotonic()) > 0:
        if not select.select([reader], [], [], left)[0]:
            break
        data += os.read(reader, 4096)
        if until(data):
            break
    return data


def check(directory, mode):
    reader, terminal = pty.openpty()
    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 20, 80, 0, 0))
    args = [sys.argv[1], "findings"]
    if mode == "json":
        args.append("--json")
    try:
        with subprocess.Popen(
            args, env=dict(os.environ, HOME=directory, TERM="dumb" if mode == "dumb" else "xterm"),
            stdin=terminal, stdout=subprocess.PIPE if mode == "pipe" else terminal, stderr=terminal,
        ) as child:
            try:
                if mode == "interactive":
                    data = capture(reader, 3, lambda b: b"0:01" in b)
                    frames = [f for f in data.split(b"\r") if b"Reading scan settings" in f]
                    assert len(set(frames)) >= 3 and b"0:01" in data, "progress froze while loading settings"
                    assert data.count(b"\n") <= 1, "animation scrolled the terminal"
                elif mode == "dumb":
                    data = capture(reader, 2, lambda b: b"\n" in b)
                    assert b"Reading scan settings" in data and b"\x1b" not in data
                else:
                    data = capture(reader, 0.5, bool)
                    assert not data, f"{mode} emitted progress"
                    if mode == "pipe":
                        assert not select.select([child.stdout], [], [], 0)[0], "progress leaked into stdout"
                assert child.poll() is None, "fixture did not block the scan"
            finally:
                child.terminate()
    finally:
        os.close(terminal)
        os.close(reader)


with tempfile.TemporaryDirectory() as directory:
    config = pathlib.Path(directory, ".stepsecurity")
    config.mkdir()
    os.mkfifo(config / "config.json")
    for mode in ("interactive", "dumb", "json", "pipe"):
        check(directory, mode)
