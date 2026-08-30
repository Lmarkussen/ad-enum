from dataclasses import dataclass
import shutil
import subprocess
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

    def execute(self, command, *, cwd=None, timeout=30, secrets=()):
        command = list(command)
        resolved = self.resolve_executable()
        if resolved and command and command[0] == self.executable:
            command[0] = resolved
        try:
            proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                  timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"{self.source_name} timed out after {timeout}s") from exc
        if proc.returncode:
            raise RuntimeError(f"{self.source_name} exited {proc.returncode}: {proc.stderr[-500:]}")
        return proc
