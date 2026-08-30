"""Safe CinderPath-derived CRED-1 acquisition boundary.

The optional helper performs one targeted PXE exchange and bounded raw
boot.var retrieval.  It intentionally stops before any media or MP-policy
decryption.  AD-Enum owns normalization and secret/report policy.
"""
import json
import shutil
import subprocess
from pathlib import Path

from .sccm_models import normalize_cred1_evidence


def helper_path():
    found = shutil.which("ad-enum-sccm-pxe")
    if found:
        return found
    local = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "ad-enum-sccm-pxe"
    return str(local) if local.is_file() else None


def run_safe_cred1(target, *, interface="", timeout=10, limits=None, executable=None):
    """Run the narrow helper against exactly one already-known DP.

    No credentials are accepted by this API and the helper receives no
    options for decryption, cracking, policy requests, or deployment actions.
    """
    executable = executable or helper_path()
    if not executable:
        return normalize_cred1_evidence({"dp": target, "sources": ["CinderPath-derived helper"],
                                         "evidence": ["helper unavailable"], "secret_inspection": "NOT ATTEMPTED"})
    command = [executable, "--target", str(target), "--timeout", f"{float(timeout):g}"]
    if interface:
        command.extend(("--interface", interface))
    # Limits are enforced by the helper build. Keep this API explicit so the
    # caller cannot accidentally turn a future helper into an unbounded read.
    if limits is not None:
        command.extend(("--max-files", str(limits.max_files),
                        "--max-file-bytes", str(limits.max_file_bytes),
                        "--max-total-bytes", str(limits.max_total_bytes)))
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=float(timeout) + 2, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return normalize_cred1_evidence({"dp": target, "sources": ["CinderPath-derived helper"],
                                         "evidence": [f"{type(exc).__name__}: {exc}"],
                                         "secret_inspection": "NOT ATTEMPTED"})
    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        payload = {"dp": target, "evidence": ["helper returned malformed JSON"],
                   "secret_inspection": "NOT ATTEMPTED"}
    if completed.returncode:
        payload.setdefault("errors", []).append(f"helper exit {completed.returncode}")
    payload.setdefault("sources", []).append("CinderPath-derived safe PXE helper")
    return normalize_cred1_evidence(payload)


def build_helper(project_root):
    """Build the source helper reproducibly; never download a binary."""
    root = Path(project_root)
    output = root / ".venv" / "bin" / "ad-enum-sccm-pxe"
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["go", "build", "-o", str(output), "./helpers/sccm_pxe"],
                   cwd=root, check=True)
    return output
