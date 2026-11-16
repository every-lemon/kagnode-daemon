"""Real Rust terminal: sign-in, role views, Users screen, sign-out, owner mode,
resizing, cancellation and terminal restoration, against a real `kagnode serve`.

Test passwords only; the store is a temporary directory. The Daemon limits sign-in
attempts per account (review finding F1), so this test clears those counters
between scenarios, as the store owner may.
"""

from pathlib import Path
import fcntl
import json
import os
import pty
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import termios
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
binary = Path(
    os.environ.get("KAGNODE_RUST_BINARY", str(ROOT / "target/debug/kagnode"))
).resolve()
PASSWORD = "fixture-long-terminal-password"
OPERATOR = "owner@fixture.invalid"


def init_store(folder, name, owner=False):
    state = folder / name
    if owner:
        subprocess.run(
            [str(binary), "--root", str(state), "init-owner"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        return state
    password = folder / "password"
    password.write_text(PASSWORD)
    password.chmod(0o600)
    subprocess.run(
        [str(binary), "--root", str(state), "init", "--email", OPERATOR]
        + ["--password-file", str(password)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    return state


def serve(state, port):
    process = subprocess.Popen(
        [str(binary), "--root", str(state), "serve", "--listen", f"127.0.0.1:{port}"]
        + ["--origin", f"http://127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        if (state / "run/control.sock").exists():
            return process
        time.sleep(0.1)
    raise AssertionError("daemon did not start")


def clear_rate(state):
    db = sqlite3.connect(state / "daemon.sqlite", timeout=10)
    db.execute("DELETE FROM security_attempts")
    db.commit()
    db.close()


def call(state, payload, session=None, confirmation=None):
    clear_rate(state)
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(30)
    s.connect(str(state / "run/control.sock"))
    request = {
        "version": 1,
        "request_id": uuid.uuid4().hex,
        "session": session,
        "confirmation": confirmation,
        "payload": payload,
    }
    s.sendall(json.dumps(request).encode() + b"\n")
    data = b""
    while chunk := s.recv(65536):
        data += chunk
    s.close()
    reply = json.loads(data)
    assert reply["ok"], reply
    return reply["value"]


def create_user(state, account, role, grants):
    token = call(state, {"action": "login", "account": OPERATOR, "password": PASSWORD})[
        "token"
    ]
    spec = {
        "action": "user_create",
        "account": account,
        "password": PASSWORD,
        "role": role,
        "grants": grants,
    }
    proof = call(
        state,
        {"action": "reauthenticate", "password": PASSWORD, "target": spec},
        session=token,
    )
    call(state, spec, session=token, confirmation=proof["confirmation"])


class Terminal:
    def __init__(self, state, width, height):
        self.state = state
        self.master, self.slave = pty.openpty()
        self.before = termios.tcgetattr(self.slave)
        fcntl.ioctl(
            self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0)
        )
        self.process = subprocess.Popen(
            [str(binary), "--root", str(state), "tui", "--no-mouse"],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            env={**os.environ, "TERM": "xterm-256color"},
            start_new_session=True,
        )
        self.output = bytearray()

    def drain(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.05)[0]:
                try:
                    self.output.extend(os.read(self.master, 65536))
                except OSError:
                    break

    def mark(self):
        return len(self.output)

    def since(self, mark):
        return bytes(self.output[mark:])

    def send(self, data, wait=0.4):
        os.write(self.master, data)
        self.drain(wait)

    def sign_in(self, account, password, wait=1.2):
        clear_rate(self.state)
        self.send(account.encode() + b"\r")
        self.send(password.encode() + b"\r", wait)

    def finish(self):
        self.send(b"\x03", 0.2)
        self.process.wait(timeout=5)
        self.drain(0.1)
        assert self.process.returncode == 0, self.process.returncode
        assert termios.tcgetattr(self.slave) == self.before, "terminal settings leaked"
        assert b"\x1b[?1000h" not in self.output and b"\x1b[?1006h" not in self.output

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        os.close(self.master)
        os.close(self.slave)


with tempfile.TemporaryDirectory(prefix="kagnode-rust-tui-") as temporary:
    folder = Path(temporary)
    state = init_store(folder, "controller")
    daemon = serve(state, 18761)
    marker = folder / "application-data"
    marker.write_text("retained")
    try:
        create_user(state, "viewer@fixture.invalid", "viewer", {})
        create_user(state, "manager@fixture.invalid", "manager", {"mail": "view"})

        # 1. Operator at three sizes: sign-in, workspace, palette, search, resize.
        for width, height in [(30, 10), (80, 24), (140, 40)]:
            t = Terminal(state, width, height)
            try:
                t.drain(0.6)
                assert t.process.poll() is None
                assert b"Sign in" in t.output, "sign-in screen not shown"
                t.sign_in(OPERATOR, PASSWORD)
                assert b"KagNode. Daemon" in t.output
                assert PASSWORD.encode() not in t.output, "password was drawn"
                t.send(b"\x10", 0.3)
                assert b"Commands" in t.output
                t.send(b"\x1b", 0.2)
                t.send(b"/netctl\r", 0.3)
                t.send(b"\x1b[6~\x1b[5~\x1b[D", 0.3)
                fcntl.ioctl(
                    t.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 16, 55, 0, 0)
                )
                t.process.send_signal(signal.SIGWINCH)
                t.drain(0.3)
                t.finish()
                assert marker.read_text() == "retained"
            finally:
                t.close()

        # 2. Wrong password: refused, nothing echoed, still on the form.
        t = Terminal(state, 100, 30)
        try:
            t.drain(0.6)
            t.sign_in(OPERATOR, "wrong-password-xxxx")
            assert b"Authentication refused" in t.output
            assert b"wrong-password-xxxx" not in t.output
            t.send(b"\x1b", 0.4)
            t.process.wait(timeout=5)
        finally:
            t.close()

        # 3. Operator: Users screen lists accounts, offers actions; sign out returns.
        t = Terminal(state, 110, 30)
        try:
            t.drain(0.6)
            t.sign_in(OPERATOR, PASSWORD)
            mark = t.mark()
            t.send(b"u", 0.6)
            shown = t.since(mark)
            assert b"Users" in shown and b"viewer@fixture.invalid" in shown, shown[
                -400:
            ]
            assert b"Reset password" in shown and b"manager@fixture.invalid" in shown
            t.send(b"\x1b", 0.4)  # back to the workspace
            mark = t.mark()
            t.send(b"o", 0.8)  # sign out
            assert b"Sign in" in t.since(mark), "sign-out did not return to sign-in"
            t.send(b"\x1b", 0.4)
            t.process.wait(timeout=5)
        finally:
            t.close()

        # 4. Viewer and Manager: analytics only, no user management offered.
        for account, expect_services in [
            ("viewer@fixture.invalid", False),
            ("manager@fixture.invalid", True),
        ]:
            t = Terminal(state, 100, 30)
            try:
                t.drain(0.6)
                mark = t.mark()
                t.sign_in(account, PASSWORD)
                shown = t.since(mark)
                assert b"Analytics (read-only)" in shown, shown[-300:]
                assert (b"Your services" in shown) == expect_services
                assert b"Users" not in shown and b"Backups" not in shown
                t.send(b"u", 0.4)
                assert b"Reset password" not in t.since(mark)
                t.send(b"q", 0.4)
                t.process.wait(timeout=5)
                assert t.process.returncode == 0
            finally:
                t.close()
    finally:
        daemon.terminate()
        daemon.wait(5)

    # 5. Owner mode: no password asked, a visible unprotected marker.
    owner_state = init_store(folder, "owner-mode", owner=True)
    daemon = serve(owner_state, 18762)
    try:
        t = Terminal(owner_state, 120, 30)
        try:
            t.drain(1.2)
            assert b"Sign in" not in t.output, "owner mode must not ask for a password"
            assert b"UNPROTECTED" in t.output
            mark = t.mark()
            t.send(b"u", 0.6)
            assert b"owner@localhost" in t.since(mark)
            t.send(b"\x1b", 0.4)  # Users screen back to the workspace
            t.finish()
        finally:
            t.close()
    finally:
        daemon.terminate()
        daemon.wait(5)
print(
    "PASS Rust terminal: sign-in, wrong password, Operator Users screen, sign-out, "
    "Viewer/Manager read-only view, owner mode, 30/80/140 columns, resize, restoration"
)
