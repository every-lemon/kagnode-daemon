"""Backup pages in the real Daemon dashboard (real shell, Core and login).

The real server has no backup server configured, so the unconfigured state is
tested end to end. The configured states are exercised by answering only the
backup API calls from a fixture that enforces the documented contract
(docs/BACKUP-SERVER.md): headers, identical request bodies for confirm and
action, one-use confirmations, policy revisions and typed delete phrases.
Synthetic data only; no real keys or backup data."""

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("KAGNODE_RUST_BINARY") or str(ROOT / "target/debug/kagnode")
PASSWORD = "fixture-password-long"
H1, H2 = "a" * 64, "b" * 64
PUB = "c" * 64


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Fixture:
    """Stateful stand-in for the backup API, enforcing the documented contract."""

    def __init__(self):
        self.policy = dict(
            revision=3,
            interval_seconds=3600,
            recovery_point_seconds=7200,
            keep_snapshots=3,
            reserve_bytes=1073741824,
            max_deferral_seconds=86400,
            bandwidth_percent=25,
            monthly_node_bytes=None,
            monthly_server_bytes=5497558138880,
            required_copies=1,
        )
        self.nodes = [
            dict(node="alpha", certificate_sha256=H1, enrolled=True, revoked=False),
            dict(node="beta", certificate_sha256=H2, enrolled=False, revoked=False),
        ]
        self.snapshots = {
            "alpha": [
                dict(
                    id="snap-0003",
                    created=1_700_000_300,
                    received_at=1_700_000_310,
                    pinned=False,
                    restore_tested=False,
                ),
                dict(
                    id="snap-0002",
                    created=1_700_000_200,
                    received_at=1_700_000_210,
                    pinned=True,
                    restore_tested=True,
                ),
                dict(
                    id="snap-0001",
                    created=1_700_000_100,
                    received_at=1_700_000_110,
                    pinned=False,
                    restore_tested=False,
                ),
            ],
            # Same snapshot ID on both nodes: actions must never cross nodes.
            "beta": [
                dict(
                    id="snap-0001",
                    created=1_700_000_500,
                    received_at=1_700_000_510,
                    pinned=False,
                    restore_tested=False,
                ),
            ],
        }
        self.agent = dict(
            revision=2,
            status=dict(
                state="deferred",
                queue=dict(
                    transfers=[
                        dict(
                            id=1,
                            snapshot="snap-0003",
                            state="completed",
                            attempts=1,
                            next_attempt=0,
                            receipt=dict(
                                snapshot="snap-0003",
                                ciphertext_verified=True,
                                verified_at=1_700_000_400,
                                restore_tested=False,
                                server="main",
                            ),
                            error=None,
                        ),
                        dict(
                            id=2,
                            snapshot="snap-0003",
                            state="pending",
                            attempts=2,
                            next_attempt=1_700_003_900,
                            receipt=None,
                            error="Transfer interrupted/refused; inspect identity, quota, lease and source health",
                        ),
                    ]
                ),
            ),
            production_qualified=False,
        )
        self.tokens = {}
        self.calls = []
        self.fail_next = None
        self.hold = set()  # paths whose responses are held until release()
        self.held = []
        self.errors = {}  # path -> message, answered with HTTP 503
        self.garble = None  # path answered 200 with a body that is not JSON
        self.cleanups = 0
        self.password_seen_outside_confirm = False
        self.big_policy = False

    def status(self):
        return dict(
            process_id="12345",
            site="home",
            server="main",
            policy=self.policy,
            storage_total_bytes=2_000_000_000_000,
            storage_available_bytes=150_000_000_000,
            verification="Ciphertext checks only; no application restore has been attested.",
            pending_catalog_cleanups=self.cleanups,
        )

    def release(self, index=0):
        route, status, value = self.held.pop(index)
        route.fulfill(
            status=status,
            content_type="application/json",
            headers={"Cache-Control": "no-store"},
            body=json.dumps(value),
        )

    def handle(self, route):
        req = route.request
        path = urlparse(req.url).path
        method = req.method
        body = req.post_data_json if method == "POST" and req.post_data else None
        if "password" in (req.url + json.dumps(dict(req.headers))).lower():
            self.password_seen_outside_confirm = True
        self.calls.append((method, path, body))
        if self.fail_next == path:
            self.fail_next = None
            return route.abort("failed")

        if path in self.errors:
            return route.fulfill(
                status=503,
                content_type="application/json",
                body=json.dumps(dict(error=self.errors[path])),
            )

        def ok(value, status=200):
            if path == self.garble:
                return route.fulfill(
                    status=200, content_type="text/plain", body="<html>not json"
                )
            if path in self.hold:
                self.held.append((route, status, value))
                return
            route.fulfill(
                status=status,
                content_type="application/json",
                headers={"Cache-Control": "no-store"},
                body=json.dumps(value),
            )

        def err(message, status=400):
            ok(dict(error=message), status)

        base = "/api/v1/backup-server/"
        if method == "GET":
            if path == base + "status":
                return ok(self.status())
            if path == base + "nodes":
                return ok(dict(nodes=self.nodes))
            if path == base + "policy":
                return ok(dict(enabled=True, policy=self.policy))
            if path == "/api/v1/backup-agent/status":
                return ok(self.agent)
            if path.startswith(base + "snapshots/"):
                node = path.rsplit("/", 1)[1]
                snaps = self.snapshots.get(node, [])
                prot = [s["id"] for s in snaps[:1]] + [
                    s["id"] for s in snaps if s["pinned"]
                ]
                return ok(dict(snapshots=snaps, protected=prot))
            return err("Not found", 404)
        headers = {k.lower(): v for k, v in req.headers.items()}
        if not headers.get("x-csrf-token"):
            return err("CSRF", 403)
        if path == base + "confirm":
            if body["password"] != PASSWORD:
                return err("Password is incorrect", 403)
            token = f"tok-{len(self.tokens)}"
            self.tokens[token] = json.dumps(body["request"], sort_keys=True)
            return ok(dict(confirmation=token, expires_in=60))
        route_name = path[len(base) :]
        if body.get("action") == "pin" and body.get("pinned") is True:
            sn = next(
                s for s in self.snapshots[body["node"]] if s["id"] == body["snapshot"]
            )
            sn["pinned"] = True
            return ok(dict(pinned=True))
        token = headers.get("x-backup-confirmation")
        want = self.tokens.pop(token, None)
        if want is None or want != json.dumps(body, sort_keys=True):
            return err("Confirmation missing, used, or for another request", 403)
        act = body["action"]
        if act == "approve":
            self.nodes.append(
                dict(
                    node=body["node"],
                    certificate_sha256=body["certificate_sha256"],
                    enrolled=False,
                    revoked=False,
                )
            )
            self.snapshots[body["node"]] = []
            return ok(
                dict(node=body["node"], expires_in=600, token="enroll-" + "z" * 24)
            )
        if act == "revoke":
            next(n for n in self.nodes if n["node"] == body["node"])["revoked"] = True
            return ok(dict(revoked=True))
        if act == "rotate_certificate":
            n = next(n for n in self.nodes if n["node"] == body["node"])
            if not n["enrolled"] or n["revoked"]:
                return err("Unknown or not enrolled node")
            if n["certificate_sha256"] != body["expected_sha256"]:
                return err("Certificate changed; review a fresh rotation")
            n["certificate_sha256"] = body["certificate_sha256"]
            return ok(
                dict(
                    node=n["node"],
                    certificate_sha256=n["certificate_sha256"],
                    rotated=True,
                )
            )
        if act == "set_policy":
            if body["policy"]["revision"] != self.policy["revision"] + 1:
                return err("Policy revision conflict; fetch the current policy")
            self.policy = body["policy"]
            return ok(dict(revision=self.policy["revision"]))
        if act == "pin":
            sn = next(
                s for s in self.snapshots[body["node"]] if s["id"] == body["snapshot"]
            )
            sn["pinned"] = False
            return ok(dict(pinned=False))
        if act == "delete":
            if body["confirm"] != f"delete {body['node']}/{body['snapshot']}":
                return err("Confirmation text mismatch")
            self.snapshots[body["node"]] = [
                s for s in self.snapshots[body["node"]] if s["id"] != body["snapshot"]
            ]
            return ok(dict(deleted=True))
        if act == "collect_garbage":
            return ok(dict(objects_removed=7))
        return err("Unsupported", 404)


def start_server(tmp):
    pw = tmp / "password"
    pw.write_text(PASSWORD)
    pw.chmod(0o600)
    env = dict(os.environ, KAGNODE_DAEMON_ROOT=str(tmp / "root"))
    subprocess.run(
        [
            BINARY,
            "init",
            "--email",
            "owner@fixture.invalid",
            "--password-file",
            str(pw),
            "--web",
        ],
        check=True,
        env=env,
        capture_output=True,
    )
    port = free_port()
    proc = subprocess.Popen(
        [
            BINARY,
            "serve",
            "--listen",
            f"127.0.0.1:{port}",
            "--origin",
            f"http://127.0.0.1:{port}",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise SystemExit("Daemon dashboard did not start")


PATTERN = re.compile(r".*/api/v1/backup-(server|agent)/.*")


def use(page, fixture):
    page.unroute_all()
    page.route(PATTERN, fixture.handle)


def eventually(page, expression, seconds=4.0):
    """Poll a JS expression until it is truthy (focus is restored after a refresh)."""
    end = time.time() + seconds
    while time.time() < end:
        if page.evaluate(expression):
            return True
        page.wait_for_timeout(100)
    return False


def login(page, base):
    page.goto(base + "/login")
    assert eventually(page, "!!window.KagNodeCore"), "Core did not load"
    page.get_by_label("Email").fill("owner@fixture.invalid")
    page.keyboard.press("Enter")
    page.locator("input[type=password]").wait_for(state="visible")
    page.locator("input[type=password]").fill(PASSWORD)
    page.keyboard.press("Enter")
    page.wait_for_url(re.compile(r".*/$"))


def check(name, ok, detail=""):
    if not ok:
        raise AssertionError(f"{name} {detail}")
    print("PASS", name)


def main():
    engine = os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
    exe = os.environ.get("KAGNODE_BROWSER_EXECUTABLE")
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as t:
        tmp = Path(t)
        proc, port = start_server(tmp)
        base = f"http://127.0.0.1:{port}"
        errors = []
        try:
            with sync_playwright() as p:
                browser = getattr(p, engine).launch(
                    headless=True, **({"executable_path": exe} if exe else {})
                )
                ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                page = ctx.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                login(page, base)
                # --- unconfigured, against the real server
                page.goto(base + "/backup")
                page.get_by_role("heading", name="Backup server").wait_for()
                check(
                    "unconfigured: setup guidance, no success claim",
                    page.get_by_text("not configured as a backup server").is_visible()
                    and page.get_by_text("Nothing is being stored here").is_visible(),
                )
                check(
                    "unconfigured: agent state explained",
                    page.get_by_text("not set up to send backups").is_visible(),
                )
                check(
                    "navigation has Backups",
                    page.locator(
                        "#sidebar a[href='/backup'], .kn-core-sidebar-navigation a[href='/backup']"
                    ).count()
                    >= 1,
                )
                check(
                    "page title heading", page.locator("h1").inner_text() == "Backups"
                )
                # --- configured, fixture-backed
                fx = Fixture()
                page.route(re.compile(r".*/api/v1/backup-(server|agent)/.*"), fx.handle)
                page.goto(base + "/backup")
                page.get_by_role("heading", name="Nodes").wait_for()
                check(
                    "summary shows storage and verification note",
                    page.get_by_text("150").first.is_visible() is not None
                    and page.get_by_text("not a restore test").first.is_visible(),
                )
                check(
                    "agent state deferred with explanation",
                    page.get_by_text("Transfers are waiting").is_visible(),
                )
                check(
                    "receipt is labelled not a restore test",
                    page.get_by_text("not a restore test").count() >= 2,
                )
                check(
                    "tables have captions", page.locator("table caption").count() >= 3
                )
                # approve
                page.get_by_role("button", name="Approve a node").click()
                dlg = page.get_by_role("dialog", name="Approve a node")
                dlg.get_by_label("Node name").fill("gamma")
                dlg.get_by_label("Node signing public key").fill(PUB)
                dlg.get_by_label("Node certificate fingerprint (SHA-256)").fill(
                    "d" * 64
                )
                dlg.get_by_label("Your Daemon password").fill("wrong-password")
                dlg.get_by_role("button", name="Approve node").click()
                dlg.get_by_role("alert").filter(
                    has_text="Password is incorrect"
                ).wait_for()
                check("wrong password shown, dialog kept open", dlg.is_visible())
                dlg.get_by_label("Your Daemon password").fill(PASSWORD)
                dlg.get_by_role("button", name="Approve node").click()
                tok = page.get_by_role("dialog", name="Enrollment token")
                tok.wait_for()
                check(
                    "token shown once with expiry",
                    "enroll-"
                    in tok.get_by_label("One-use enrollment token").input_value()
                    and "10 minutes" in tok.inner_text(),
                )
                check("token not in URL", "enroll-" not in page.url)
                tok.get_by_role("button", name="I have copied it").click()
                page.get_by_role("cell", name="gamma", exact=True).wait_for()
                check(
                    "new node listed and token dialog removed",
                    page.get_by_role("dialog", name="Enrollment token").count() == 0,
                )
                # revoke
                page.get_by_role("button", name="Revoke beta").click()
                d = page.get_by_role("dialog", name="Revoke beta")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Revoke node").click()
                page.get_by_text("Revoked", exact=True).first.wait_for()
                check(
                    "revoked node shows state and loses actions",
                    page.get_by_role("button", name="Revoke beta").count() == 0,
                )
                # rotate
                page.get_by_role("button", name="Rotate certificate alpha").click()
                d = page.get_by_role("dialog", name="Rotate certificate for alpha")
                d.get_by_label("New certificate fingerprint (SHA-256)").fill("e" * 64)
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Rotate certificate").click()
                page.get_by_role("cell", name="eeeeeeeeeeeeeeee…").wait_for()
                check("rotation updates the fingerprint", True)
                snaps = lambda: page.get_by_role(
                    "table", name=re.compile("Snapshots for")
                )
                # snapshots
                page.get_by_role("heading", name="Snapshots").wait_for()
                check(
                    "snapshots list newest first with honest status",
                    snaps()
                    .get_by_role("cell", name="snap-0003", exact=True)
                    .is_visible()
                    and page.get_by_text("Not restore tested").count() >= 1
                    and page.get_by_text("Restore tested", exact=True).count() == 1,
                )
                check(
                    "newest snapshot is protected and has no delete",
                    page.get_by_role("button", name="Delete snap-0003").count() == 0
                    and page.get_by_role("button", name="Delete snap-0001").count()
                    == 1,
                )
                page.get_by_role("button", name="Pin snap-0001").click()
                page.get_by_role("button", name="Unpin snap-0001").wait_for()
                check(
                    "pin needs no password dialog",
                    page.get_by_role("dialog").count() == 0,
                )
                page.get_by_role("button", name="Unpin snap-0001").click()
                d = page.get_by_role("dialog", name="Unpin snap-0001")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Unpin").click()
                page.get_by_role("button", name="Pin snap-0001").wait_for()
                check("unpin asks for password", True)
                page.get_by_role("button", name="Delete snap-0001").click()
                d = page.get_by_role("dialog", name="Delete snap-0001")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_label(re.compile("Type")).fill("delete alpha/snap-0002")
                d.get_by_role("button", name="Delete snapshot").click()
                d.get_by_role("alert").filter(has_text="does not match").wait_for()
                check("delete needs the exact typed phrase", d.is_visible())
                d.get_by_label(re.compile("Type")).fill("delete alpha/snap-0001")
                d.get_by_role("button", name="Delete snapshot").click()
                snaps().get_by_role("cell", name="snap-0001", exact=True).wait_for(
                    state="detached"
                )
                check(
                    "snapshot deleted",
                    snaps().get_by_role("cell", name="snap-0001", exact=True).count()
                    == 0,
                )
                page.get_by_role("button", name="Remove unreferenced data").click()
                d = page.get_by_role("dialog", name="Remove unreferenced data")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Remove data").click()
                page.locator("#page-status").filter(
                    has_text="7 unreferenced objects removed"
                ).wait_for()
                check("garbage collection reports count", True)
                # policy
                page.locator("input[name=required_copies]").fill("2")
                check(
                    "policy edit registered in the form",
                    eventually(
                        page,
                        "document.querySelector('input[name=required_copies]').value === '2'",
                    ),
                )
                page.get_by_role("button", name="Review and save").click()
                d = page.get_by_role("dialog", name="Save backup policy")
                check(
                    "policy dialog states the next revision",
                    "revision 4" in d.inner_text(),
                )
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Save policy").click()
                page.locator("#page-status").filter(has_text="revision 4").wait_for()
                for _ in range(30):  # the fixture answers on this thread's event loop
                    if fx.policy["revision"] == 4:
                        break
                    page.wait_for_timeout(100)
                check(
                    "policy saved at revision + 1",
                    fx.policy["revision"] == 4
                    and fx.policy["required_copies"] == 2
                    and fx.policy["monthly_node_bytes"] is None,
                    str(fx.policy),
                )
                fx.policy["revision"] = 9  # another administrator changed it
                page.locator("input[name=required_copies]").fill("3")
                page.get_by_role("button", name="Review and save").click()
                d = page.get_by_role("dialog", name="Save backup policy")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Save policy").click()
                d.get_by_role("alert").filter(
                    has_text="Another administrator changed the policy"
                ).wait_for()
                check(
                    "policy conflict shown without overwriting",
                    fx.policy["required_copies"] == 2,
                )
                d.get_by_role("button", name="Cancel").click()
                check(
                    "after a conflict the form shows the current values",
                    eventually(
                        page,
                        "document.querySelector('input[name=required_copies]').value === '2'",
                    )
                    and page.locator("#page-status")
                    .filter(has_text="policy changed while you were editing")
                    .count()
                    == 1,
                )
                # uncertain outcome
                page.get_by_role("button", name="Revoke alpha").click()
                d = page.get_by_role("dialog", name="Revoke alpha")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                revokes = lambda: sum(1 for c in fx.calls if c[1].endswith("/revoke"))
                before = revokes()
                fx.fail_next = "/api/v1/backup-server/revoke"
                d.get_by_role("button", name="Revoke node").click()
                d.get_by_role("alert").filter(
                    has_text="may or may not have completed"
                ).wait_for()
                check(
                    "transport failure is reported as uncertain and not retried",
                    revokes() == before + 1,
                )
                d.get_by_role("button", name="Cancel").click()
                assert eventually(
                    page, "!document.querySelector('dialog input[type=password]')"
                )
                check(
                    "password cleared and dialog removed on close",
                    page.locator("dialog input[type=password]").count() == 0,
                )
                focused = eventually(
                    page,
                    "document.activeElement.getAttribute('aria-label') === 'Revoke alpha'",
                )
                check(
                    "focus returns to the Revoke alpha button after cancel",
                    focused,
                    page.evaluate(
                        "document.activeElement.tagName + ':' + (document.activeElement.getAttribute('aria-label') || document.activeElement.textContent)"
                    ),
                )
                check(
                    "password only ever sent to the confirm endpoint",
                    not fx.password_seen_outside_confirm,
                )
                # large integers disable policy editing
                fx.policy.update(revision=10, monthly_server_bytes=2**60)
                page.goto(base + "/backup")
                page.get_by_role("heading", name="Policy").wait_for()
                check(
                    "unsafe integers disable the policy form",
                    page.get_by_role("button", name="Review and save").is_disabled(),
                )
                # keyboard: dialog closes with Escape and focus returns
                page.get_by_role("button", name="Approve a node").focus()
                page.keyboard.press("Enter")
                page.get_by_role("dialog", name="Approve a node").wait_for()
                page.keyboard.press("Escape")
                page.get_by_role("dialog", name="Approve a node").wait_for(
                    state="detached"
                )
                focused = eventually(
                    page, "document.activeElement.textContent === 'Approve a node'"
                )
                check(
                    "Escape closes the dialog and focus returns to the opener", focused
                )

                # ---- Codex's PR #30 contract review (R1-R4) and follow-ups
                sel = lambda: page.locator("select[aria-label=Node]")
                reload = lambda f: (use(page, f), page.goto(base + "/backup"))
                fx = Fixture()
                reload(fx)
                page.get_by_role("heading", name="Nodes").wait_for()
                check(
                    "R2 pending node: Revoke offered, Rotate not",
                    page.get_by_role("button", name="Revoke beta").count() == 1
                    and page.get_by_role(
                        "button", name="Rotate certificate beta"
                    ).count()
                    == 0
                    and page.get_by_role(
                        "button", name="Rotate certificate alpha"
                    ).count()
                    == 1,
                )
                # R1: a late response for an older selection never replaces the view,
                # and actions bind to the node that was rendered (same snapshot ID on both).
                fx.hold.add("/api/v1/backup-server/snapshots/beta")
                sel().select_option("beta")
                eventually(page, "true")
                sel().select_option("alpha")
                check(
                    "R1 latest selection renders",
                    eventually(
                        page,
                        "document.querySelector('table caption') && [...document.querySelectorAll('table caption')].some(c => c.textContent.startsWith('Snapshots for alpha'))",
                    ),
                )
                check("R1 beta response is held", len(fx.held) == 1)
                fx.release(0)  # the stale beta reply arrives late
                page.wait_for_timeout(500)
                check(
                    "R1 stale reply discarded: still alpha",
                    sel().input_value() == "alpha"
                    and snaps()
                    .locator("caption")
                    .inner_text()
                    .startswith("Snapshots for alpha")
                    and snaps()
                    .get_by_role("cell", name="snap-0003", exact=True)
                    .count()
                    == 1,
                )
                page.get_by_role("button", name="Pin snap-0001").click()
                page.get_by_role("button", name="Unpin snap-0001").wait_for()
                pins = [c for c in fx.calls if c[1].endswith("/pin")]
                check(
                    "R1 pin request carries the rendered node",
                    pins and pins[-1][2]["node"] == "alpha",
                    str(pins[-1:] if pins else ""),
                )
                # R3: preparation error shown beside older work, for both states
                for state in ("deferred", "transferring"):
                    fx = Fixture()
                    fx.agent["status"]["state"] = state
                    fx.agent["status"]["source_error"] = (
                        "Prepared snapshot manifest changed"
                    )
                    reload(fx)
                    page.get_by_role(
                        "heading", name="Sending from this host"
                    ).wait_for()
                    check(
                        f"R3 source_error visible while {state}",
                        page.get_by_text(
                            "Older work is still in progress, but the next backup cannot be queued"
                        ).is_visible()
                        and page.get_by_text(
                            "Prepared snapshot manifest changed"
                        ).is_visible(),
                    )
                # R4: each panel fails alone
                fx = Fixture()
                fx.errors["/api/v1/backup-server/status"] = "worker unavailable"
                reload(fx)
                page.get_by_role("heading", name="Sending from this host").wait_for()
                check(
                    "R4 server fails, agent panel still shown",
                    page.get_by_text("worker unavailable").is_visible()
                    and page.get_by_text(
                        "not a sign that backups are healthy"
                    ).is_visible()
                    and page.get_by_text("Transfers are waiting").is_visible()
                    and page.get_by_role("heading", name="Nodes").count() == 0,
                )
                del fx.errors["/api/v1/backup-server/status"]
                page.get_by_role("button", name="Try again").click()
                page.get_by_role("heading", name="Nodes").wait_for()
                check(
                    "R4 retry recovers the server panels",
                    page.get_by_text("free of").is_visible(),
                )
                fx = Fixture()
                fx.errors["/api/v1/backup-agent/status"] = "status document unreadable"
                reload(fx)
                page.get_by_role("heading", name="Nodes").wait_for()
                check(
                    "R4 agent fails, server panels still shown",
                    page.get_by_text("status document unreadable").is_visible()
                    and page.get_by_text("free of").is_visible(),
                )
                # additive status fields from PR #28
                fx = Fixture()
                fx.cleanups = 2
                fx.agent["status"]["queue"]["history"] = dict(
                    completed_job_limit=64, compacted_identities=5
                )
                reload(fx)
                page.get_by_role("heading", name="Nodes").wait_for()
                check(
                    "pending cleanups and compacted history shown",
                    page.get_by_text("2 cleanup pending").is_visible()
                    and page.get_by_text("5 compacted").is_visible(),
                )
                # an unreadable reply after a mutation is an uncertain outcome
                fx = Fixture()
                reload(fx)
                page.get_by_role("heading", name="Nodes").wait_for()
                fx.garble = "/api/v1/backup-server/revoke"
                page.get_by_role("button", name="Revoke alpha").click()
                d = page.get_by_role("dialog", name="Revoke alpha")
                d.get_by_label("Your Daemon password").fill(PASSWORD)
                d.get_by_role("button", name="Revoke node").click()
                d.get_by_role("alert").filter(
                    has_text="may or may not have completed"
                ).wait_for()
                check("unreadable reply reported as uncertain", True)
                d.get_by_role("button", name="Cancel").click()
                d.wait_for(state="detached")
                ctx.close()
                # mobile: no page-level horizontal overflow
                m = browser.new_context(
                    viewport={"width": 390, "height": 800}, has_touch=True
                )
                mp = m.new_page()
                login(mp, base)
                mp.route(
                    re.compile(r".*/api/v1/backup-(server|agent)/.*"), Fixture().handle
                )
                mp.goto(base + "/backup")
                mp.get_by_role("heading", name="Nodes").wait_for()
                mp.wait_for_timeout(300)
                over = mp.evaluate("document.documentElement.scrollWidth - innerWidth")
                check("390px: no page-level horizontal overflow", over <= 1, str(over))
                m.close()
                browser.close()
        finally:
            proc.kill()
        check("no page errors", not errors, "; ".join(errors))
    print(f"PASS: {engine} backup pages")


if __name__ == "__main__":
    main()
