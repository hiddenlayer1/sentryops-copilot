"""SentryOps Copilot — autonomous Splunk ops with a structural approval gate."""
from .audit import AuditChain, AuditEntry
from .operator import Operator
from .orchestrator import Orchestrator, TriageResult
from .splunk_mcp import ApprovalRequired, Backend, SplunkMCPBoundary, SyntheticBackend, ToolResult
from .warrant import Warrant, canonical, mint_warrant, verify_warrant

__all__ = [
    "AuditChain",
    "AuditEntry",
    "Operator",
    "Orchestrator",
    "TriageResult",
    "ApprovalRequired",
    "Backend",
    "SplunkMCPBoundary",
    "SyntheticBackend",
    "ToolResult",
    "Warrant",
    "canonical",
    "mint_warrant",
    "verify_warrant",
]

# Live backend is imported lazily (only needed for a real tenant):
#   from sentryops.splunk_live import LiveSplunkBackend
