"""
Command Injection Remediation Module

This module provides comprehensive protection against command injection attacks in MCP systems
through multiple layers of defense:

1. Input Sanitization - Multi-layer input cleaning and validation
2. Command Whitelisting - Explicit allowlist of permitted commands with parameter validation  
3. Prompt Boundaries - Cryptographic boundaries to prevent prompt injection

Example usage:
    from remediation.command_injection import CommandInjectionProtector
    
    # Initialize protector
    protector = CommandInjectionProtector(secret_key="your-secret-key")
    
    # Sanitize and validate input
    safe_input = protector.sanitize_input(user_input)
    
    # Execute whitelisted command
    result = protector.execute_command("summarize_text", {"text": safe_input})
    
    # Create bounded prompt
    secure_prompt = protector.create_bounded_prompt(user_input, context)
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass

# Import main classes from submodules
from .input_sanitizer import (
    InputSanitizer,
    SanitizationLevel,
    SanitizationRule,
    ValidationResult
)

from .command_whitelist import (
    CommandWhitelist,
    WhitelistedCommand,
    CommandParameter,
    CommandCategory,
    whitelisted_command
)

from .prompt_boundaries import (
    PromptBoundaryManager,
    BoundaryType,
    BoundaryToken,
    create_secure_prompt,
    validate_secure_prompt
)

# Version info
__version__ = "1.0.0"
__author__ = "MCP Security Team"

# Module logger
logger = logging.getLogger(__name__)

# Export main classes and functions
__all__ = [
    # Main protector class
    "CommandInjectionProtector",
    
    # Input sanitization
    "InputSanitizer",
    "SanitizationLevel",
    "SanitizationRule",
    "ValidationResult",
    
    # Command whitelisting
    "CommandWhitelist", 
    "WhitelistedCommand",
    "CommandParameter",
    "CommandCategory",
    "whitelisted_command",
    
    # Prompt boundaries
    "PromptBoundaryManager",
    "BoundaryType",
    "BoundaryToken",
    "create_secure_prompt",
    "validate_secure_prompt",
    
    # Configuration
    "CommandInjectionConfig",
    
    # Utilities
    "detect_injection_patterns",
    "validate_command_safety"
]

@dataclass
class CommandInjectionConfig:
    """Configuration for command injection protection"""
    
    # Sanitization settings
    max_input_length: int = 10000
    allow_unicode: bool = True
    strip_html: bool = True
    escape_special_chars: bool = True
    
    # Whitelist settings
    enable_strict_mode: bool = True
    default_rate_limit: int = 100
    require_authentication: bool = True
    
    # Boundary settings
    use_xml_boundaries: bool = True
    enable_nested_boundaries: bool = False
    boundary_timeout: int = 3600  # 1 hour
    
    # Security settings
    log_suspicious_activity: bool = True
    block_on_injection_detection: bool = True
    alert_on_repeated_attempts: bool = True
    max_failed_attempts: int = 5

class CommandInjectionProtector:
    """
    Unified interface for command injection protection.
    
    Combines input sanitization, command whitelisting, and prompt boundaries
    to provide comprehensive protection against command injection attacks.
    """
    
    def __init__(self, secret_key: str, config: Optional[CommandInjectionConfig] = None):
        """
        Initialize the command injection protector.
        
        Args:
            secret_key: Secret key for cryptographic operations
            config: Optional configuration object
        """
        self.config = config or CommandInjectionConfig()
        self.secret_key = secret_key
        
        # Initialize components
        self.sanitizer = InputSanitizer(
            max_length=self.config.max_input_length,
            custom_patterns=None  # Will be set based on detected threats
        )
        
        self.whitelist = CommandWhitelist(
            enable_strict_mode=self.config.enable_strict_mode
        )
        
        self.boundary_manager = PromptBoundaryManager(
            secret_key=secret_key,
            use_xml_format=self.config.use_xml_boundaries,
            enable_nested_boundaries=self.config.enable_nested_boundaries
        )
        
        # Track security events
        self.failed_attempts = {}
        self.blocked_ips = set()
        
        logger.info("CommandInjectionProtector initialized")
    
    def protect(self, user_input: str, command: Optional[str] = None,
                context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Apply all protection layers to user input.
        
        Args:
            user_input: Raw user input
            command: Optional command to execute
            context: Execution context
            
        Returns:
            Dictionary with protection results
        """
        
        result = {
            'success': False,
            'sanitized_input': None,
            'command_result': None,
            'bounded_prompt': None,
            'errors': [],
            'warnings': []
        }
        
        # Check if source is blocked
        if context and self._is_blocked(context):
            result['errors'].append("Source is blocked due to repeated violations")
            return result
        
        try:
            # Step 1: Sanitize input
            sanitized = self.sanitize_input(user_input, context)
            result['sanitized_input'] = sanitized
            
            # Step 2: Create bounded prompt
            if context:
                bounded = self.create_bounded_prompt(sanitized, context)
                result['bounded_prompt'] = bounded
            
            # Step 3: Execute command if specified
            if command:
                command_result = self.execute_command(
                    command,
                    {'input': sanitized},
                    context
                )
                result['command_result'] = command_result
            
            result['success'] = True
            
        except Exception as e:
            logger.error(f"Protection failed: {str(e)}")
            result['errors'].append(str(e))
            
            # Track failed attempts
            self._track_failed_attempt(context)
        
        return result
    
    def sanitize_input(self, user_input: str, 
                      context: Optional[Dict[str, Any]] = None) -> str:
        """
        Sanitize user input with context awareness.
        
        Args:
            user_input: Raw user input
            context: Optional context for enhanced sanitization
            
        Returns:
            Sanitized input
        """
        
        # Apply base sanitization
        sanitized = self.sanitizer.sanitize_prompt(user_input, context)
        
        # Additional context-based sanitization
        if context:
            # Stricter sanitization for untrusted sources
            trust_level = context.get('trust_level', 0)
            if trust_level < 5:
                # Remove more potentially dangerous patterns
                additional_patterns = [
                    r'file://',
                    r'data:',
                    r'javascript:',
                    r'vbscript:'
                ]
                for pattern in additional_patterns:
                    sanitized = sanitized.replace(pattern, '')
        
        return sanitized
    
    def execute_command(self, command_name: str, params: Dict[str, Any],
                       context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Execute a whitelisted command with full validation.
        
        Args:
            command_name: Name of the command to execute
            params: Command parameters
            context: Execution context
            
        Returns:
            Command execution result
        """
        
        # Ensure context has required fields
        if not context:
            context = self._create_default_context()
        
        # Add rate limiting info
        context['rate_limit_multiplier'] = self._get_rate_limit_multiplier(context)
        
        # Execute through whitelist
        return self.whitelist.execute_command(command_name, params, context)
    
    def create_bounded_prompt(self, user_input: str,
                            context: Dict[str, Any],
                            system_instructions: Optional[str] = None) -> str:
        """
        Create a cryptographically bounded prompt.
        
        Args:
            user_input: User's input (should be pre-sanitized)
            context: Execution context
            system_instructions: Optional system instructions
            
        Returns:
            Bounded and signed prompt
        """
        
        # Add security metadata
        metadata = {
            'protection_version': __version__,
            'sanitization_applied': True,
            'trust_level': context.get('trust_level', 0)
        }
        
        return self.boundary_manager.create_bounded_prompt(
            user_input,
            context,
            system_instructions,
            metadata
        )
    
    def validate_bounded_prompt(self, prompt: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Validate a bounded prompt.
        
        Args:
            prompt: The bounded prompt to validate
            
        Returns:
            Tuple of (is_valid, extracted_data)
        """
        
        return self.boundary_manager.validate_bounded_prompt(prompt)
    
    def register_safe_command(self, command: WhitelistedCommand,
                            aliases: Optional[List[str]] = None):
        """
        Register a new safe command.
        
        Args:
            command: Command definition
            aliases: Optional command aliases
        """
        
        self.whitelist.register_command(command, aliases)
        logger.info(f"Registered safe command: {command.name}")
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics and statistics"""
        
        return {
            'total_requests': len(self.whitelist.execution_history),
            'failed_attempts': sum(len(attempts) for attempts in self.failed_attempts.values()),
            'blocked_sources': len(self.blocked_ips),
            'commands_registered': len(self.whitelist.commands),
            'active_boundaries': len(self.boundary_manager.processed_boundaries),
            'config': {
                'strict_mode': self.config.enable_strict_mode,
                'block_on_injection': self.config.block_on_injection_detection
            }
        }
    
    def _is_blocked(self, context: Dict[str, Any]) -> bool:
        """Check if source is blocked"""
        
        ip = context.get('ip_address')
        user_id = context.get('user_id')
        
        if ip and ip in self.blocked_ips:
            return True
        
        # Could add more blocking logic (user_id, etc.)
        return False
    
    def _track_failed_attempt(self, context: Optional[Dict[str, Any]]):
        """Track failed attempt and potentially block source"""
        
        if not context:
            return
        
        identifier = context.get('ip_address') or context.get('user_id', 'unknown')
        
        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []
        
        self.failed_attempts[identifier].append({
            'timestamp': time.time(),
            'context': context
        })
        
        # Clean old attempts (older than 1 hour)
        current_time = time.time()
        self.failed_attempts[identifier] = [
            attempt for attempt in self.failed_attempts[identifier]
            if current_time - attempt['timestamp'] < 3600
        ]
        
        # Block if too many attempts
        if len(self.failed_attempts[identifier]) >= self.config.max_failed_attempts:
            if context.get('ip_address'):
                self.blocked_ips.add(context['ip_address'])
                logger.warning(f"Blocked IP due to repeated failures: {context['ip_address']}")
    
    def _get_rate_limit_multiplier(self, context: Dict[str, Any]) -> float:
        """Get rate limit multiplier based on trust level"""
        
        trust_level = context.get('trust_level', 5)
        
        if trust_level >= 8:
            return 2.0  # Double rate limit for highly trusted
        elif trust_level >= 5:
            return 1.0  # Normal rate limit
        elif trust_level >= 3:
            return 0.5  # Half rate limit
        else:
            return 0.2  # Heavily restricted
    
    def _create_default_context(self) -> Dict[str, Any]:
        """Create default execution context"""
        
        return {
            'authenticated': False,
            'user_id': 'anonymous',
            'roles': ['guest'],
            'trust_level': 1,
            'session_created_at': time.time()
        }

# Utility functions
def detect_injection_patterns(text: str) -> List[str]:
    """
    Detect potential injection patterns in text.
    
    Args:
        text: Text to analyze
        
    Returns:
        List of detected patterns
    """
    
    detector = InputSanitizer()
    patterns = []
    
    # Check against dangerous patterns
    for pattern in detector.DANGEROUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            patterns.append(pattern)
    
    return patterns

def validate_command_safety(command_string: str) -> Tuple[bool, Optional[str]]:
    """
    Validate if a command string is safe to execute.
    
    Args:
        command_string: Command string to validate
        
    Returns:
        Tuple of (is_safe, reason_if_unsafe)
    """
    
    # Check for obvious dangerous patterns
    dangerous_commands = [
        'rm ', 'del ', 'format ', 'drop table', 'delete from',
        'exec ', 'eval ', 'compile ', '__import__'
    ]
    
    lower_command = command_string.lower()
    
    for dangerous in dangerous_commands:
        if dangerous in lower_command:
            return False, f"Contains dangerous command: {dangerous}"
    
    # Check for shell operators
    shell_operators = ['|', '&', ';', '`', '$', '>', '<']
    
    for operator in shell_operators:
        if operator in command_string:
            return False, f"Contains shell operator: {operator}"
    
    return True, None

# Module initialization
def _initialize_module():
    """Initialize module-level resources"""
    
    # Set up default patterns
    global DEFAULT_INJECTION_PATTERNS
    DEFAULT_INJECTION_PATTERNS = [
        r'execute\s*:',
        r'system\s*\(',
        r'eval\s*\(',
        r'exec\s*\(',
        r'__.*__',
        r'import\s+os',
        r'subprocess',
        r'shell\s*=\s*true'
    ]
    
    logger.info(f"Command Injection module v{__version__} initialized")

# Initialize module
_initialize_module()

# Convenience function for quick protection
def protect_against_injection(user_input: str, secret_key: str = None) -> str:
    """
    Quick function to protect against command injection.
    
    Args:
        user_input: Raw user input
        secret_key: Optional secret key (uses default if not provided)
        
    Returns:
        Sanitized input
    """
    
    if not secret_key:
        secret_key = os.environ.get('MCP_SECRET_KEY', 'default-secret-key')
    
    protector = CommandInjectionProtector(secret_key)
    return protector.sanitize_input(user_input)

# Example usage in docstring
"""
Quick Start Examples:

1. Basic input sanitization:
    from remediation.command_injection import protect_against_injection
    
    safe_input = protect_against_injection(user_input)

2. Full protection with command execution:
    from remediation.command_injection import CommandInjectionProtector
    
    protector = CommandInjectionProtector("secret-key")
    result = protector.protect(
        user_input,
        command="summarize_text",
        context={'user_id': 'user123', 'roles': ['user']}
    )

3. Register custom safe commands:
    from remediation.command_injection import (
        CommandInjectionProtector, 
        WhitelistedCommand,
        CommandCategory,
        CommandParameter
    )
    
    protector = CommandInjectionProtector("secret-key")
    
    custom_command = WhitelistedCommand(
        name="custom_analysis",
        category=CommandCategory.ANALYSIS,
        handler=my_analysis_function,
        parameters=[
            CommandParameter(name="data", type=str, required=True)
        ],
        description="Custom analysis command",
        allowed_roles=["analyst", "admin"]
    )
    
    protector.register_safe_command(custom_command)
"""
