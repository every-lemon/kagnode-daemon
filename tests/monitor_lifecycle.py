"""Collector lifecycle through authenticated v1 local control; no TUI integration claim."""

import json, os, pathlib, subprocess, tempfile, time, signal

binary = pathlib.Path(os.environ["KAGNODE_RUST_BINARY"]).resolve()
with tempfile.TemporaryDirectory(prefix="monitor-lifecycle-") as folder:
    root = pathlib.Path(folder) / "controller"
    password = pathlib.Path(folder) / "password"
    password.write_text("fixture-monitor-lifecycle-password")
    password.chmod(0o600)

    token = None
    request_counter = 0

    def wire(payload, session=None, confirmation=None):
        global request_counter
        request_counter += 1
        request = dict(
            version=1,
            request_id=f"fixture-{request_counter}",
            session=session,
            confirmation=confirmation,
            payload=payload,
        )
        return json.loads(
            subprocess.check_output(
                [str(binary), "--root", str(root), "user", "request"],
                input=json.dumps(request),
                text=True,
                stderr=subprocess.PIPE,
            )
        )

    def rpc(payload, confirm=False):
        global token
        if token is None:
            token = wire(
                dict(
                    action="login",
                    account="monitor@example.invalid",
                    password="fixture-monitor-lifecycle-password",
                )
            )["token"]
        confirmation = None
        if confirm:
            confirmation = wire(
                dict(
                    action="reauthenticate",
                    password="fixture-monitor-lifecycle-password",
                    target=payload,
                ),
                token,
            )["confirmation"]
        return wire(payload, token, confirmation)

    def run(*args):
        if args[0] == "monitor":
            payload = (
                dict(action="overview")
                if len(args) == 1
                else dict(
                    action="metrics",
                    name=args[2],
                    since=int(time.time()) - 3600,
                    until=int(time.time()),
                )
            )
            return json.dumps(rpc(payload))
        if args[0] == "retention":
            current = rpc(dict(action="retention"))
            if len(args) == 1:
                return json.dumps(current)
            policy = dict(current["policy"])
            policy["days"] = int(args[args.index("--days") + 1])
            return json.dumps(
                rpc(
                    dict(
                        action="set_retention",
                        revision=int(args[args.index("--revision") + 1]),
                        policy=policy,
                        confirm_trim="--confirm-trim" in args,
                    ),
                    confirm=True,
                )
            )
        return subprocess.check_output(
            [str(binary), "--root", str(root), *args], text=True
        )

    run("init", "--email", "monitor@example.invalid", "--password-file", str(password))

    def start():
        p = subprocess.Popen(
            [str(binary), "--root", str(root), "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for _ in range(100):
            if p.poll() is not None:
                raise AssertionError(p.stderr.read().decode())
            if (root / "run/control.sock").exists():
                try:
                    data = json.loads(run("monitor"))
                    if data["nodes"][0]["last_sample"]:
                        return p, data
                except subprocess.CalledProcessError:
                    pass
            time.sleep(0.1)
        p.kill()
        raise AssertionError("collector not ready")

    p, first = start()
    try:
        assert first["nodes"][0]["health"] == "online"
        policy = json.loads(run("retention"))
        assert policy["policy"]["days"] == 30
        try:
            run("retention", "--days", "2", "--revision", "0")
            raise AssertionError("trim accepted without explicit review")
        except subprocess.CalledProcessError as error:
            assert (
                "Reducing retention requires explicit trim confirmation" in error.stderr
            )
        run("retention", "--days", "2", "--revision", "0", "--confirm-trim")
        time.sleep(11)
        second = json.loads(run("monitor"))
        assert (
            second["nodes"][0]["last_sample"]["at"]
            > first["nodes"][0]["last_sample"]["at"]
        )
        assert "cpu.percent" in second["nodes"][0]["last_sample"]["values"]
        history = json.loads(run("monitor", "--metric", "cpu.percent"))
        assert history["points"]
    finally:
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=5)
        assert p.returncode == 0, p.stderr.read().decode()
    assert not (root / "run/control.sock").exists()
    p, third = start()
    try:
        assert json.loads(run("retention"))["policy"]["days"] == 2
        assert json.loads(run("monitor", "--metric", "cpu.percent"))["points"]
    finally:
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=5)
        assert p.returncode == 0
print(
    "PASS persistent metrics, CPU history, revision guards, terminal independence, SIGTERM and restart"
)
