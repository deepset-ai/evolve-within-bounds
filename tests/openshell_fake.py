# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

"""The `openshell` CLI, faked over a local directory, for both benchmarks' sandbox tests."""

import re
import shutil
import subprocess
from pathlib import Path

import security_agent.primevul.sandbox as primevul_sandbox
import security_agent.synthetic.sandbox as synthetic_sandbox

# What runs a job inside the sandbox, by the command the host asks for.
JOBS = {synthetic_sandbox.RUN_JOB: synthetic_sandbox.run_job, primevul_sandbox.RUN_JOB: primevul_sandbox.run_job}


class Finished:
    def __init__(self, returncode):
        self.returncode = returncode

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        pass


class Hung:
    """An exec that never starts its command and never returns, until killed."""

    returncode = None

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("openshell", timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class FakeOpenShell:
    """The `openshell` CLI (0.0.106) against a directory standing in for the sandbox's filesystem. Like the real one, it
    uploads a directory into `<dest>/<its name>` and downloads a file into a directory. The first `fail_execs` job
    executions fail; the first `hang_execs` hang."""

    def __init__(self, root: Path, fail_execs: int = 0, hang_execs: int = 0):
        self.root, self.fail_execs, self.hang_execs = root, fail_execs, hang_execs
        self.calls: list[list[str]] = []

    def spawn(self, args, stderr):
        if self.hang_execs:
            self.hang_execs -= 1
            self.calls.append(args)
            return Hung()
        done = self(args, 0)
        stderr.write(done.stderr)
        return Finished(done.returncode)

    def path(self, remote: str) -> Path:
        if remote.startswith(str(self.root)):  # the deployed agent, as a job sees it
            return Path(remote)
        assert remote.startswith("/sandbox/")
        return self.root / remote.removeprefix("/sandbox/")

    def __call__(self, args, timeout_s):
        self.calls.append(args)
        assert args[:2] == ["openshell", "sandbox"]
        verb, rest = args[2], args[3:]
        if verb == "upload":
            assert rest[0] == "--no-git-ignore" and rest[1] == "sbx"
            local, dest = Path(rest[2]), self.path(rest[3])
            shutil.copytree(local, dest / local.name)
        elif verb == "download":
            source, dest = self.path(rest[1]), Path(rest[2])
            if not source.is_file():
                return subprocess.CompletedProcess(args, 1, "", "no such file")
            shutil.copy2(source, dest / source.name)
        elif verb == "exec":
            command = rest[rest.index("--") + 1 :]
            if tuple(command[:-4]) in JOBS:
                if self.fail_execs:
                    self.fail_execs -= 1
                    return subprocess.CompletedProcess(args, 255, "", "relay closed")
                JOBS[tuple(command[:-4])](
                    self.path(command[command.index("--job") + 1]), self.path(command[command.index("--out") + 1])
                )
            elif command[:2] == ["sh", "-c"]:  # the host's check on a running job
                result, started = re.findall(r'"([^"]+)"', command[2])[:2]
                state = "done" if self.path(result).exists() else "running 0" if self.path(started).exists() else ""
                return subprocess.CompletedProcess(args, 0, state + "\n", "")
            elif command[:2] == ["rm", "-rf"]:
                for remote in command[2:]:
                    target = self.path(remote)
                    shutil.rmtree(target) if target.is_dir() else target.unlink(missing_ok=True)
            else:
                raise AssertionError(command)
        return subprocess.CompletedProcess(args, 0, "", "")

    def leftovers(self) -> list[str]:
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*") if p.is_file())
