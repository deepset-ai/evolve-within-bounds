# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""
Running work inside an NVIDIA OpenShell sandbox, created through NemoClaw (sandbox/).

Both benchmarks use it: the synthetic benchmark for its scans and the optimizer's code (`security_agent.synthetic.
sandbox`), PrimeVul for judging functions (`security_agent.primevul.sandbox`). The host keeps the benchmark, its answer
key, the loop and the optimizer. Each piece of work is a job:
1. On the host, a job directory holds `job.json` (what to run, with which settings) and the files the job needs.
2. `openshell sandbox upload` copies it into the sandbox. `openshell sandbox exec` runs the benchmark's `run-job`
   command there (`OpenShell.command`), which runs the job and deletes the upload.
3. `openshell sandbox download` brings back the result, one JSON file, and the host removes it from the sandbox.

OpenShell 0.0.106 occasionally leaves an exec hanging, before its command starts or after it ended, and an exec can
also return while its command still runs. So the host watches each job: the job writes a marker when it starts and
touches it every `HEARTBEAT_S`, and the host checks the marker and the result with short execs while it waits. A job
that has not started within `START_TIMEOUT_S`, or whose marker went stale, is retried; once its result exists, the host
stops waiting for the exec.

Inside the sandbox the model is reached through OpenShell's managed inference route, `https://inference.local/v1`,
which NemoClaw points at the model server on the host. The sandbox's policy (`sandbox/security-triage/
policy-additions.yaml`) allows nothing else out but reads from the PrimeVul knowledge base's Qdrant on the host.

**Versions.** Each job carries a hash of the host's `security_agent` code, and the sandbox refuses a job from different
code: after changing the code, recreate the sandbox (`sandbox/sandbox.sh create`), which installs the current code.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

INFERENCE_URL = "https://inference.local/v1"
ROOT = "/sandbox/security-agent"  # jobs and results inside the sandbox
START_TIMEOUT_S = 120  # a job that has not started by then is retried
POLL_S = 20  # how often the host checks on a running job
HEARTBEAT_S = 30  # how often a running job touches its marker; a marker 4 times older belongs to a dead job


class SandboxError(RuntimeError):
    pass


@functools.cache
def code_version() -> str:
    """A hash of the `security_agent` package's Python code, the same on the host and in a sandbox built from it."""
    root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()[:16]


def _run(args: list[str], timeout_s: float) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout_s, check=False)


def _spawn(args: list[str], stderr: Any) -> subprocess.Popen:
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=stderr, text=True)


class OpenShell:
    """
    One OpenShell sandbox, driven through the `openshell` CLI. Each benchmark's subclass adds its jobs.

    :param name: the sandbox's name (`nemoclaw onboard --name`).
    :param inference_url: the model server's address inside the sandbox.
    :param exec_timeout_s: the longest a job may run.
    :param retries: how often a job is retried after a failure of the sandbox itself (not of the job).
    """

    # The command that runs one job inside the sandbox, as `<command> --job DIR --out FILE`.
    command: tuple[str, ...] = ()

    def __init__(
        self,
        name: str,
        *,
        binary: str = "openshell",
        inference_url: str = INFERENCE_URL,
        exec_timeout_s: int = 7_200,
        retries: int = 1,
        runner: Callable[[list[str], float], subprocess.CompletedProcess] | None = None,
        spawner: Callable[[list[str], Any], Any] | None = None,
    ) -> None:
        self.name, self.binary, self.inference_url = name, binary, inference_url
        self.exec_timeout_s, self.retries = exec_timeout_s, retries
        self.runner, self.spawner = runner or _run, spawner or _spawn

    def _call(self, args: list[str], timeout_s: float = 600) -> str:
        try:
            proc = self.runner([self.binary, "sandbox", *args], timeout_s)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxError(f"openshell sandbox {args[0]}: {type(exc).__name__}: {exc}") from exc
        if proc.returncode != 0:
            raise SandboxError(
                f"openshell sandbox {args[0]} failed ({proc.returncode}): {(proc.stderr or proc.stdout or '')[-1500:]}"
            )
        return proc.stdout

    def upload(self, local: Path, parent: str) -> None:
        """Copy the local directory `local` to `<parent>/<its name>` in the sandbox."""
        # Benchmark repositories contain .gitignore files: without --no-git-ignore, files they name would be left out.
        self._call(["upload", "--no-git-ignore", self.name, str(local), parent])

    def download(self, remote: str, local: Path) -> None:
        """Copy the sandbox's file `remote` into the local directory `local`."""
        self._call(["download", self.name, remote, str(local)])

    def exec(self, *command: str, timeout_s: float | None = None) -> str:
        """Run a command in the sandbox and return its output."""
        timeout_s = timeout_s or self.exec_timeout_s
        return self._call(
            ["exec", "--name", self.name, "--timeout", str(int(timeout_s)), "--no-tty", "--", *command], timeout_s + 60
        )

    def _state(self, result: str, started: str) -> str:
        """
        The job's state, from its marker and its result.

        "done", "running", "stalled" (its marker went stale), "" (not started), or "unknown" when the check itself
        failed.
        """
        script = (
            f'if [ -e "{result}" ]; then echo done; '
            f'elif [ -e "{started}" ]; then echo running $(( $(date +%s) - $(stat -c %Y "{started}") )); fi'
        )
        try:
            words = self.exec("sh", "-c", script, timeout_s=60).split()
        except SandboxError:
            return "unknown"
        if words[:1] == ["running"]:
            return (
                "stalled"
                if len(words) == 2 and words[1].lstrip("-").isdigit() and int(words[1]) > 4 * HEARTBEAT_S
                else "running"
            )
        return words[0] if words else ""

    def _run_job(self, remote_job: str, result: str, started: str) -> str:
        """The job in the sandbox, watched (see the module docstring). Returns what a failed exec said."""
        args = [
            self.binary,
            "sandbox",
            "exec",
            "--name",
            self.name,
            "--timeout",
            str(self.exec_timeout_s),
            "--no-tty",
            "--",
            *self.command,
            "--job",
            remote_job,
            "--out",
            result,
        ]
        with tempfile.TemporaryFile("w+") as err:
            proc = self.spawner(args, err)
            begun = time.monotonic()
            exited: str | None = None  # what the exec said when it returned; the result file decides
            try:
                while True:
                    if exited is None:
                        try:
                            code = proc.wait(timeout=POLL_S)
                            err.seek(0)
                            exited = f"exit {code}: {err.read()[-1500:]}" if code else ""
                        except subprocess.TimeoutExpired:
                            pass
                    else:
                        time.sleep(POLL_S)
                    state = self._state(result, started)
                    if state == "done":
                        return exited or ""
                    if state == "stalled":
                        raise SandboxError("the job stopped without a result")
                    if exited is not None and state != "running":
                        return exited
                    if state == "" and time.monotonic() - begun > START_TIMEOUT_S:
                        raise SandboxError(f"the job did not start within {START_TIMEOUT_S} s")
                    if time.monotonic() - begun > self.exec_timeout_s + 60:
                        raise SandboxError(f"the job did not finish within {self.exec_timeout_s} s")
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()

    def model(self, model: dict[str, Any]) -> dict[str, Any]:
        """The model settings as the sandbox sees them: the same server, through the inference route."""
        return {**model, "api_base_url": self.inference_url}

    def run_job(self, job: dict[str, Any], files: dict[str, Path]) -> dict[str, Any]:
        """Run one job in the sandbox and return its result. `files`: path in the job -> a local file or directory."""
        job_id = uuid.uuid4().hex
        remote_job, remote_out, started = (
            f"{ROOT}/jobs/{job_id}",
            f"{ROOT}/results/{job_id}.json",
            f"{ROOT}/results/{job_id}.started",
        )
        with tempfile.TemporaryDirectory(prefix="security-agent-job-") as tmp:
            local = Path(tmp) / job_id
            local.mkdir()
            (local / "job.json").write_text(json.dumps({**job, "code_version": code_version()}), encoding="utf-8")
            for rel, source in files.items():
                target = local / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if Path(source).is_dir():
                    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
                else:
                    shutil.copy2(source, target)
            for attempt in range(self.retries + 1):
                out = Path(tmp) / f"out-{attempt}"
                out.mkdir()
                try:
                    self.upload(local, f"{ROOT}/jobs")
                    failed = self._run_job(remote_job, remote_out, started)
                    # An exec can end without the command's exit status: the result file is the proof that it ran.
                    with contextlib.suppress(SandboxError):
                        self.download(remote_out, out)
                    result = out / f"{job_id}.json"
                    if result.is_file():
                        return json.loads(result.read_text(encoding="utf-8"))
                    error = SandboxError(
                        f"no result for job {job_id}" + (f"; the exec ended with {failed}" if failed else "")
                    )
                except SandboxError as exc:
                    error = exc
                finally:
                    with contextlib.suppress(SandboxError):
                        self.exec("rm", "-rf", remote_job, remote_out, started, timeout_s=120)
                if attempt == self.retries:
                    raise error
        raise AssertionError("unreachable")


# -- inside the sandbox ----------------------------------------------------------------------------


def _refuse_other_code(job: dict[str, Any]) -> None:
    if job.get("code_version") != code_version():
        raise RuntimeError(
            f"the sandbox runs security_agent {code_version()}, the host {job.get('code_version')}: "
            "recreate the sandbox (sandbox/sandbox.sh create)"
        )


def run_job(job_dir: Path, out: Path, execute: Callable[[dict[str, Any], Path], dict[str, Any]]) -> None:
    """
    Run one uploaded job with `execute(job, job_dir)` and write its result to `out`; the job directory is removed.

    A failure is a result too, and so is a job from other code than the sandbox's.
    """
    job_dir, out = Path(job_dir), Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    marker = out.with_suffix(".started")  # the host's sign that the job runs, touched while it does
    marker.touch()
    stop = threading.Event()

    def heartbeat() -> None:
        while not stop.wait(HEARTBEAT_S):
            marker.touch()

    threading.Thread(target=heartbeat, daemon=True).start()
    try:
        job = json.loads((job_dir / "job.json").read_text(encoding="utf-8"))
        _refuse_other_code(job)
        result = execute(job, job_dir)
    except Exception as exc:  # noqa: BLE001 - reported to the host
        result = {"error": f"{type(exc).__name__}: {exc}"[-2_000:]}
    finally:
        stop.set()
        shutil.rmtree(job_dir, ignore_errors=True)
    partial = out.with_suffix(".partial")
    partial.write_text(json.dumps(result, default=str), encoding="utf-8")
    partial.replace(out)
