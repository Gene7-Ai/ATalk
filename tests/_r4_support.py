"""Shared helpers for the r4 flag-off equivalence / no-nacl startup tests
(r4 F1/P1).  Stdlib only.  Imported by test modules in this directory
(pytest puts a non-package tests/ dir on sys.path); never executed as a
script.  The server subprocess itself is tests/_r4_flagoff_driver.py.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASE_COMMIT = "ed9973d"
DRIVER = Path(__file__).resolve().parent / "_r4_flagoff_driver.py"


def reserve_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(REPO_ROOT), *args],
                          capture_output=True, text=True, timeout=120)


def have_base_commit() -> bool:
    return git("rev-parse", "--verify", "--quiet",
               BASE_COMMIT + "^{commit}").returncode == 0


@contextlib.contextmanager
def base_worktree(parent: str):
    """Pristine checkout of BASE_COMMIT in a temp git worktree; the repo
    working tree is never touched (r4 P1)."""
    root = Path(tempfile.mkdtemp(prefix="atalk-base-", dir=parent))
    proc = git("worktree", "add", "--detach", str(root), BASE_COMMIT)
    if proc.returncode != 0:
        shutil.rmtree(root, ignore_errors=True)
        raise RuntimeError(f"git worktree add failed: {proc.stderr}")
    try:
        yield root
    finally:
        git("worktree", "remove", "--force", str(root))
        git("worktree", "prune")
        shutil.rmtree(root, ignore_errors=True)


def child_env(source_root, env_extra=None) -> dict:
    env = {k: v for k, v in os.environ.items() if k != "ATALK_FEDERATION"}
    env["PYTHONPATH"] = str(source_root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if env_extra:
        env.update(env_extra)
    return env


def run_nonacl(args, source_root=REPO_ROOT, env_extra=None, timeout=120, cwd=None):
    """Run args under `-S` (no site module -> no site-packages -> no PyNaCl)
    with only <source_root> on PYTHONPATH.  A version-faithful stand-in for a
    system interpreter without PyNaCl.  `cwd` (r5 #4) runs the child outside
    the source tree so '' on sys.path cannot shadow <source_root>."""
    return subprocess.run(
        [sys.executable, "-S", *[str(a) for a in args]],
        capture_output=True, text=True, timeout=timeout,
        env=child_env(source_root, env_extra), cwd=cwd)


def wait_port_free(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.closing(socket.socket()) as sock:
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"port {port} still in use")


@contextlib.contextmanager
def serve(source_root, python_args=("-S",), env_extra=None, port=None,
          state_dir=None, timeout=30.0, cwd=None):
    """Start the driver server for <source_root> and yield its base URL.
    python_args ("-S",) reproduces the zero-dependency (no PyNaCl) case.
    `cwd` (r5 #4) runs the driver outside the source tree (e.g. an installed
    wheel target) so nothing from the checkout is implicitly importable."""
    port = port or reserve_port()
    if state_dir is None:
        state_dir = tempfile.mkdtemp(prefix="atalk-flagoff-state-")
        cleanup_state = True
    else:
        cleanup_state = False
    wait_port_free(port)
    env = child_env(source_root, env_extra)
    proc = subprocess.Popen(
        [sys.executable, *python_args, str(DRIVER), str(source_root),
         str(state_dir), "127.0.0.1", str(port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=cwd)
    try:
        deadline = time.monotonic() + timeout
        ready = False
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                break  # process exited
            if line.strip() == "READY":
                ready = True
                break
        if not ready:
            proc.kill()
            proc.wait(timeout=10)
            err = proc.stderr.read() if proc.stderr else ""
            raise RuntimeError(f"driver not ready\nstderr={err[-2000:]}")
        yield f"http://127.0.0.1:{port}"
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=10)
        if cleanup_state:
            shutil.rmtree(state_dir, ignore_errors=True)


def http_raw(method: str, url: str, raw=None, headers=None, timeout: float = 10.0):
    """(status, Content-Type, raw body bytes); the literal string
    "broken-pipe" in the status slot when the connection died mid-request
    (the pre-existing no-drain early-reject alias)."""
    req = urllib.request.Request(url, data=raw, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.headers.get("Content-Type"), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type"), exc.read()
    except (BrokenPipeError, ConnectionResetError):
        return "broken-pipe", None, None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (BrokenPipeError, ConnectionResetError)):
            return "broken-pipe", None, None
        raise
