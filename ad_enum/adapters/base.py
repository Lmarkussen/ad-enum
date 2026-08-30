from dataclasses import dataclass
import shutil
import subprocess
import threading
import queue
import time
from pathlib import Path

@dataclass
class ToolCapability:
    name: str
    executable: str
    status: str
    version: str = ""
    detail: str = ""

class ToolAdapter:
    source_name = "tool"
    executable = "tool"

    def resolve_executable(self):
        path = shutil.which(self.executable)
        if path:
            return path
        candidate = Path.home() / ".local" / "bin" / self.executable
        return str(candidate) if candidate.is_file() else None

    def detect(self):
        path = self.resolve_executable()
        if not path: return ToolCapability(self.source_name, self.executable, "MISSING")
        try:
            p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3, check=False)
            text = (p.stdout or p.stderr).strip().splitlines()
            return ToolCapability(self.source_name, path, "AVAILABLE", text[0] if text else "UNKNOWN VERSION")
        except subprocess.TimeoutExpired:
            return ToolCapability(self.source_name, path, "AVAILABLE", "UNKNOWN VERSION")
        except OSError as exc:
            return ToolCapability(self.source_name, path, "INCOMPATIBLE", detail=str(exc))

    @staticmethod
    def redact_command(command, secrets=()):
        return ["<redacted>" if part in secrets else part for part in command]

    @staticmethod
    def redact_text(text, secrets=()):
        for secret in secrets:
            if secret: text = text.replace(secret, "<redacted>")
        return text

    def execute(self, command, *, cwd=None, timeout=30, secrets=(), stream=None):
        command = list(command)
        resolved = self.resolve_executable()
        if resolved and command and command[0] == self.executable:
            command[0] = resolved
        try:
            proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, bufsize=1)
        except OSError:
            raise
        captured = {"stdout": [], "stderr": []}
        events = queue.Queue()

        def drain(name, pipe):
            try:
                for line in iter(pipe.readline, ""):
                    events.put((name, line))
            finally:
                pipe.close()

        threads = [threading.Thread(target=drain, args=(name, getattr(proc, name)), daemon=True)
                   for name in ("stdout", "stderr")]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout
        while any(thread.is_alive() for thread in threads) or proc.poll() is None or not events.empty():
            try:
                name, line = events.get(timeout=0.05)
                captured[name].append(line)
                if stream:
                    stream(name, self.redact_text(line, secrets))
            except queue.Empty:
                pass
            if proc.poll() is None and time.monotonic() > deadline:
                proc.kill()
                for thread in threads: thread.join(timeout=1)
                raise TimeoutError(f"{self.source_name} timed out after {timeout}s")
        for thread in threads: thread.join(timeout=1)
        result = subprocess.CompletedProcess(command, proc.returncode,
                                             "".join(captured["stdout"]), "".join(captured["stderr"]))
        if result.returncode:
            raise RuntimeError(f"{self.source_name} exited {result.returncode}: {result.stderr[-500:]}")
        return result
