from .base import ToolAdapter

class SCCMSecretsAdapter(ToolAdapter):
    """Capability-only adapter; secret retrieval is not enabled by default."""
    source_name = "sccmsecrets"
    executable = "SCCMSecrets.py"

    def run(self, *, context):
        raise RuntimeError("SCCMSecrets discovery is intentionally not executed automatically")
