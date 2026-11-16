"""Daemon Administration page (/admin) in a real browser against a real server.

Roles API sign-in, tabs per role, user creation/editing/disabling/reset with
password confirmation, the web-administration switch, layout at 390px and no
page errors. Test passwords only; a temporary store.
"""

import os
import re
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from backup_pages_browser import PASSWORD, control, enable_web_admin, start_server  # noqa: E402

OPERATOR = "owner@fixture.invalid"
NEW_PASSWORD = "another-long-password-1"


def check(name, ok, detail=""):
    if not ok:
        raise AssertionError(f"{name} {detail}")
    print("PASS", name)


def eventually(page, expression, seconds=5.0):
    end = time.time() + seconds
    while time.time() < end:
        if page.evaluate(expression):
            return True
        page.wait_for_timeout(100)
    return False


def sign_in(page, base, account, password):
    page.goto(base + "/admin")
    page.get_by_role("heading", name="Sign in").wait_for()
    page.get_by_label("Account").fill(account)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Sign in").click()


def dialog_confirm(page, password=PASSWORD):
    dlg = page.get_by_role("dialog")
    dlg.get_by_label("Your Daemon password").fill(password)
    return dlg


def choose(page, scope, label, option):
    """Core turns selects into comboboxes; pick by visible option text."""
    scope.get_by_role("combobox", name=label, exact=True).click()
    page.get_by_role("option", name=re.compile(option)).first.click()


def tabs(page):
    return [t.inner_text() for t in page.get_by_role("tab").all()]


def create_user(page, account, role, grants=None, password=PASSWORD):
    page.get_by_role("button", name="New user").click()
    dlg = page.get_by_role("dialog")
    dlg.get_by_label("Account (email)").fill(account)
    dlg.get_by_label("Password").first.fill(PASSWORD)
    choose(page, dlg, "Role", role.capitalize())
    for product, level in (grants or {}).items():
        choose(page, dlg, product, level.capitalize())
    dlg.get_by_label("Your Daemon password").fill(password)
    dlg.get_by_role("button", name="Create user").click()


def main():
    engine = os.environ.get("KAGNODE_BROWSER_ENGINE", "chromium")
    exe = os.environ.get("KAGNODE_BROWSER_EXECUTABLE")
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as t:
        tmp = Path(t)
        proc, port = start_server(tmp, admin=False)
        base = f"http://127.0.0.1:{port}"
        errors = []
        known = []

        def record(text):
            # Expected refusals log "Failed to load resource"; WebKit's CSP warning
            # for Core's native-select styling is documented and counted, not hidden.
            if "Failed to load resource" in text:
                return
            if "Refused to apply a stylesheet" in text:
                known.append(text)
                return
            errors.append(text)

        try:
            with sync_playwright() as p:
                browser = getattr(p, engine).launch(
                    headless=True, **({"executable_path": exe} if exe else {})
                )
                ctx = browser.new_context(viewport={"width": 1280, "height": 900})
                page = ctx.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.on(
                    "console",
                    lambda m: record(m.text) if m.type == "error" else None,
                )

                # 1. Wrong password stays on the form; password field is cleared.
                sign_in(page, base, OPERATOR, "wrong-password-xxxx")
                page.get_by_text("Sign-in failed").wait_for()
                check(
                    "wrong password refused, field cleared",
                    page.get_by_label("Password").input_value() == "",
                )

                # 2. Operator signs in; web administration is off by default.
                sign_in(page, base, OPERATOR, PASSWORD)
                page.get_by_role("tab", name="Users").wait_for()
                check(
                    "operator tabs",
                    tabs(page)[:2] == ["Overview", "Users"],
                    str(tabs(page)),
                )
                check(
                    "overview shows server and role",
                    page.get_by_text("Your access").is_visible(),
                )
                page.get_by_role("tab", name="Users").click()
                page.get_by_text("Web administration is disabled").first.wait_for()
                check(
                    "admin off: explained, with the terminal way to enable it",
                    page.get_by_text(
                        "An Operator turns it on from the terminal"
                    ).is_visible(),
                )

                # 3. Enable it (as the local owner would), then manage users.
                enable_web_admin(tmp / "root")
                page.get_by_role("tab", name="Overview").click()
                page.get_by_role("tab", name="Users").click()
                page.get_by_role("heading", name="Users").wait_for()
                check(
                    "operator listed as you",
                    page.get_by_text(f"{OPERATOR} (you)").is_visible(),
                )

                create_user(
                    page,
                    "viewer@fixture.invalid",
                    "viewer",
                    password="wrong-password-xxxx",
                )
                page.get_by_role("dialog").locator(".form-error").filter(
                    has_text=re.compile(".+")
                ).wait_for()
                check(
                    "wrong confirmation keeps the dialog open",
                    page.get_by_role("dialog").is_visible(),
                )
                page.get_by_role("dialog").get_by_label("Your Daemon password").fill(
                    PASSWORD
                )
                page.get_by_role("dialog").get_by_role(
                    "button", name="Create user"
                ).click()
                page.get_by_text("viewer@fixture.invalid").wait_for()
                check("viewer created", page.get_by_text("analytics only").is_visible())

                page.get_by_role("button", name="New user").click()
                dlg = page.get_by_role("dialog")
                check(
                    "service levels hidden for a Viewer",
                    not dlg.get_by_role(
                        "combobox", name="Mail", exact=True
                    ).is_visible(),
                )
                choose(page, dlg, "Role", "Manager")
                check(
                    "service levels shown for a Manager",
                    dlg.get_by_role("combobox", name="Mail", exact=True).is_visible(),
                )
                dlg.get_by_role("button", name="Cancel").click()
                create_user(
                    page, "manager@fixture.invalid", "manager", {"Mail": "view"}
                )
                page.get_by_text("manager@fixture.invalid").wait_for()
                check(
                    "manager created with a service",
                    page.get_by_text("Mail: view").is_visible(),
                )

                # 3b. A Manager sees a Services tab limited to their grants.
                mctx = browser.new_context(viewport={"width": 1100, "height": 800})
                mpage = mctx.new_page()
                sign_in(mpage, base, "manager@fixture.invalid", PASSWORD)
                mpage.get_by_role("tab", name="Services").wait_for()
                check(
                    "manager tabs",
                    tabs(mpage) == ["Overview", "Services", "My account"],
                    str(tabs(mpage)),
                )
                mpage.get_by_role("tab", name="Services").click()
                mpage.get_by_role("heading", name="Mail").wait_for()
                body = mpage.locator("main").inner_text()
                check(
                    "manager sees only the granted service and its level",
                    "VPN" not in body and "view" in body and "Read-only" in body,
                    body[:300],
                )
                mctx.close()

                # 4. Edit role, disable, reset password.
                page.get_by_role(
                    "button", name="Edit role manager@fixture.invalid"
                ).click()
                dlg = page.get_by_role("dialog")
                choose(page, dlg, "Mail", "Operate")
                dlg.get_by_label("Your Daemon password").fill(PASSWORD)
                dlg.get_by_role("button", name="Save").click()
                page.get_by_text("Mail: operate").wait_for()
                check("service level changed", True)
                page.get_by_role(
                    "button", name="Reset password viewer@fixture.invalid"
                ).click()
                dlg = page.get_by_role("dialog")
                dlg.get_by_label("New password").fill(NEW_PASSWORD)
                dlg.get_by_label("Your Daemon password").fill(PASSWORD)
                dlg.get_by_role("button", name="Reset password").click()
                page.get_by_role("dialog").wait_for(state="detached")
                page.get_by_role(
                    "button", name="Disable manager@fixture.invalid"
                ).click()
                dialog_confirm(page)
                page.get_by_role("dialog").get_by_role("button", name="Disable").click()
                page.get_by_text("disabled", exact=True).wait_for()
                check("disabled shown", True)

                # 5. Audit tab and Settings tab.
                page.get_by_role("tab", name="Activity").click()
                page.get_by_role("heading", name="Recent security activity").wait_for()
                check(
                    "activity lists actions",
                    "user_create" in page.locator("table").inner_text(),
                )
                check(
                    "audit holds no passwords",
                    PASSWORD not in page.content()
                    and NEW_PASSWORD not in page.content(),
                )
                page.get_by_role("tab", name="Settings").click()
                page.get_by_text("Web administration", exact=True).first.wait_for()
                page.get_by_role("button", name="Turn web administration off").click()
                dialog_confirm(page)
                page.get_by_role("dialog").get_by_role(
                    "button", name="Turn off"
                ).click()
                page.get_by_role("button", name="Turn web administration on").wait_for()
                page.get_by_role("tab", name="Users").click()
                page.get_by_text("Web administration is disabled").first.wait_for()
                check("turning administration off blocks the Users tab", True)
                enable_web_admin(tmp / "root")

                # 6. Viewer: new password works, old one does not, limited tabs.
                page.get_by_role("tab", name="Overview").click()
                page.get_by_role("button", name="Sign out").click()
                page.get_by_role("heading", name="Sign in").wait_for()
                sign_in(page, base, "viewer@fixture.invalid", PASSWORD)
                page.get_by_text("Sign-in failed").wait_for()
                check("old password refused after reset", True)
                sign_in(page, base, "viewer@fixture.invalid", NEW_PASSWORD)
                page.get_by_role("tab", name="Overview").wait_for()
                check(
                    "viewer sees only Overview and My account",
                    tabs(page) == ["Overview", "My account"],
                    str(tabs(page)),
                )
                check(
                    "viewer overview shows role",
                    page.get_by_text("Read-only server analytics").is_visible(),
                )
                status = page.evaluate(
                    "fetch('/api/v1/roles/users').then(r => r.status)"
                )
                check("viewer refused the users API", status == 403, str(status))

                # 7. Mobile: no page-level horizontal overflow, 44px tabs.
                ctx.close()
                m = browser.new_context(
                    viewport={"width": 390, "height": 800}, has_touch=True
                )
                mp = m.new_page()
                mp.on("pageerror", lambda e: errors.append(str(e)))
                sign_in(mp, base, OPERATOR, PASSWORD)
                mp.get_by_role("tab", name="Users").click()
                mp.get_by_role("heading", name="Users").wait_for()
                mp.wait_for_timeout(300)
                over = mp.evaluate("document.documentElement.scrollWidth - innerWidth")
                check("390px: no page-level horizontal overflow", over <= 1, str(over))
                height = mp.get_by_role("tab").first.bounding_box()["height"]
                check("tabs are touch-sized", height >= 44, str(height))
                m.close()
                browser.close()
        finally:
            proc.kill()
        check("no page errors or console errors", not errors, "; ".join(errors))
        if known:
            print(
                f"NOTE {len(known)} known WebKit native-select CSP warnings (documented, unfixed)"
            )
    print(f"PASS: {engine} administration pages")


if __name__ == "__main__":
    main()
