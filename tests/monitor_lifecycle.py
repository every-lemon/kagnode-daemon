"""Isolated daemon collector, terminal disconnect, restart and retention regression."""

import json, os, pathlib, subprocess, tempfile, time, signal

binary = pathlib.Path(os.environ["KAGNODE_RUST_BINARY"]).resolve()
with tempfile.TemporaryDirectory(prefix="monitor-lifecycle-") as folder:
    root = pathlib.Path(folder) / "controller"
    password = pathlib.Path(folder) / "password"
    password.write_text("fixture-monitor-lifecycle-password")
    password.chmod(0o600)

    def run(*args):
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
        result = subprocess.run(
            [
                str(binary),
                "--root",
                str(root),
                "retention",
                "--days",
                "2",
                "--revision",
                "0",
            ],
            capture_output=True,
        )
        assert result.returncode != 0
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
