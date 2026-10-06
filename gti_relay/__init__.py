"""gti_relay: a minimal relay client for the Google Threat Intelligence Agentic API. Not an agent; makes no model calls."""

from .client import GTIRelay, InvestigationResult, ProgressUpdate

__all__ = ["GTIRelay", "InvestigationResult", "ProgressUpdate"]
