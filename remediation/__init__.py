"""
MCP Security Remediation Library

Comprehensive security implementations for Model Context Protocol vulnerabilities.
"""

__version__ = "1.0.0"
__author__ = "Your Name"

from .common.exceptions import SecurityException
from .common.logging_config import setup_logging

# Set up logging
setup_logging()

# Export main classes
from .01_command_injection import InputSanitizer, CommandWhitelist
from .02_tool_poisoning import ToolVerificationSystem, ToolSandbox
from .03_sse_problems import ConnectionLimiter, SSERateLimiter
from .04_privilege_escalation import ServiceAuthenticationSystem, LeastPrivilegeManager
from .05_persistent_context import ContextSigningSystem, SecureContextStorage
from .06_server_takeover import ZeroTrustGateway, CredentialIsolationManager

__all__ = [
    "SecurityException",
    "InputSanitizer",
    "CommandWhitelist",
    "ToolVerificationSystem",
    "ToolSandbox",
    "ConnectionLimiter",
    "SSERateLimiter",
    "ServiceAuthenticationSystem",
    "LeastPrivilegeManager",
    "ContextSigningSystem",
    "SecureContextStorage",
    "ZeroTrustGateway",
    "CredentialIsolationManager",
]
