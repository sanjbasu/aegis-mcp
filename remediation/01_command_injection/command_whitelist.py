"""
Command Whitelist Module

Implements a comprehensive command whitelisting system with parameter validation,
context-aware permissions, and audit logging for MCP command execution.
"""

import re
import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import inspect
import logging
from datetime import datetime

from ..common.exceptions import ValidationError, AuthorizationError, SecurityException
from ..common.logging_config import security_logger

logger = logging.getLogger(__name__)

class CommandCategory(Enum):
    """Categories of commands for organization and permissions"""
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    SYSTEM_INFO = "system_info"
    USER_MANAGEMENT = "user_management"
    ANALYSIS = "analysis"
    COMMUNICATION = "communication"
    UTILITY = "utility"

@dataclass
class CommandParameter:
    """Defines a parameter for a whitelisted command"""
    name: str
    type: type
    required: bool = True
    default: Any = None
    validator: Optional[Callable] = None
    allowed_values: Optional[List[Any]] = None
    min_value: Optional[Any] = None
    max_value: Optional[Any] = None
    pattern: Optional[str] = None
    description: str = ""

@dataclass
class WhitelistedCommand:
    """Represents a whitelisted command with validation rules"""
    name: str
    category: CommandCategory
    handler: Callable
    parameters: List[CommandParameter] = field(default_factory=list)
    description: str = ""
    requires_auth: bool = True
    requires_mfa: bool = False
    rate_limit: Optional[int] = None  # requests per minute
    allowed_roles: Set[str] = field(default_factory=set)
    allowed_services: Set[str] = field(default_factory=set)
    dangerous: bool = False
    audit_level: str = "normal"  # normal, detailed, paranoid

class CommandWhitelist:
    """
    Comprehensive command whitelisting system with validation and security controls
    """
    
    def __init__(self, enable_strict_mode: bool = True):
        self.enable_strict_mode = enable_strict_mode
        self.commands: Dict[str, WhitelistedCommand] = {}
        self.command_aliases: Dict[str, str] = {}
        self.execution_history: List[Dict] = []
        self.rate_limiters: Dict[str, List[float]] = {}
        self._initialize_default_commands()
    
    def _initialize_default_commands(self):
        """Initialize default safe commands"""
        
        # Read operations
        self.register_command(WhitelistedCommand(
            name="read_file",
            category=CommandCategory.DATA_READ,
            handler=self._safe_read_file,
            parameters=[
                CommandParameter(
                    name="path",
                    type=str,
                    validator=self._validate_file_path,
                    description="File path to read"
                ),
                CommandParameter(
                    name="encoding",
                    type=str,
                    required=False,
                    default="utf-8",
                    allowed_values=["utf-8", "ascii", "latin-1"],
                    description="File encoding"
                )
            ],
            description="Safely read a file with path validation",
            allowed_roles={"user", "admin"},
            rate_limit=100
        ))
        
        # Analysis operations
        self.register_command(WhitelistedCommand(
            name="summarize_text",
            category=CommandCategory.ANALYSIS,
            handler=self._safe_summarize,
            parameters=[
                CommandParameter(
                    name="text",
                    type=str,
                    validator=lambda x: len(x) < 100000,
                    description="Text to summarize"
                ),
                CommandParameter(
                    name="max_length",
                    type=int,
                    required=False,
                    default=500,
                    min_value=50,
                    max_value=5000,
                    description="Maximum summary length"
                )
            ],
            description="Generate text summary",
            allowed_roles={"user", "admin"},
            rate_limit=50
        ))
        
        # Utility operations
        self.register_command(WhitelistedCommand(
            name="calculate",
            category=CommandCategory.UTILITY,
            handler=self._safe_calculate,
            parameters=[
                CommandParameter(
                    name="expression",
                    type=str,
                    validator=self._validate_math_expression,
                    pattern=r'^[0-9\+\-\*\/\(\)\.\s]+$',
                    description="Mathematical expression"
                )
            ],
            description="Perform safe mathematical calculations",
            allowed_roles={"user", "admin"},
            requires_auth=False,
            rate_limit=200
        ))
    
    def register_command(self, command: WhitelistedCommand, aliases: Optional[List[str]] = None):
        """Register a new whitelisted command"""
        
        # Validate command
        if not self._validate_command_definition(command):
            raise ValueError(f"Invalid command definition: {command.name}")
        
        # Check for conflicts
        if command.name in self.commands:
            raise ValueError(f"Command '{command.name}' already registered")
        
        # Register command
        self.commands[command.name] = command
        
        # Register aliases
        if aliases:
            for alias in aliases:
                if alias in self.command_aliases:
                    raise ValueError(f"Alias '{alias}' already in use")
                self.command_aliases[alias] = command.name
        
        logger.info(f"Registered command: {command.name} (category: {command.category.value})")
    
    def execute_command(self, command_name: str, params: Dict[str, Any], 
                       context: Optional[Dict[str, Any]] = None) -> Any:
        """
        Execute a whitelisted command with full validation
        
        Args:
            command_name: Name or alias of the command
            params: Command parameters
            context: Execution context (user, service, etc.)
            
        Returns:
            Command execution result
            
        Raises:
            ValidationError: Invalid command or parameters
            AuthorizationError: Insufficient permissions
            SecurityException: Security policy violation
        """
        
        # Resolve aliases
        actual_command_name = self.command_aliases.get(command_name, command_name)
        
        # Check if command exists
        if actual_command_name not in self.commands:
            self._log_suspicious_activity("unknown_command", {
                "command": command_name,
                "context": context
            })
            raise ValidationError(f"Unknown command: {command_name}")
        
        command = self.commands[actual_command_name]
        
        # Create execution record
        execution_id = self._generate_execution_id()
        start_time = time.time()
        
        try:
            # Step 1: Authentication check
            if command.requires_auth:
                self._check_authentication(context)
            
            # Step 2: MFA check
            if command.requires_mfa:
                self._check_mfa(context)
            
            # Step 3: Authorization check
            self._check_authorization(command, context)
            
            # Step 4: Rate limiting
            self._check_rate_limit(command, context)
            
            # Step 5: Validate parameters
            validated_params = self._validate_parameters(command, params)
            
            # Step 6: Additional security checks for dangerous commands
            if command.dangerous:
                self._perform_dangerous_command_checks(command, validated_params, context)
            
            # Step 7: Execute command
            result = command.handler(**validated_params)
            
            # Step 8: Log successful execution
            self._log_execution(execution_id, command, validated_params, context, 
                              "success", time.time() - start_time)
            
            return result
            
        except Exception as e:
            # Log failed execution
            self._log_execution(execution_id, command, params, context, 
                              f"failed: {str(e)}", time.time() - start_time)
            raise
    
    def _validate_command_definition(self, command: WhitelistedCommand) -> bool:
        """Validate command definition"""
        
        # Check command name format
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', command.name):
            return False
        
        # Check handler is callable
        if not callable(command.handler):
            return False
        
        # Validate parameters match handler signature
        sig = inspect.signature(command.handler)
        handler_params = set(sig.parameters.keys())
        
        # Remove 'self' if present
        handler_params.discard('self')
        
        command_params = {p.name for p in command.parameters}
        
        # All required command parameters must be in handler
        required_params = {p.name for p in command.parameters if p.required}
        if not required_params.issubset(handler_params):
            return False
        
        return True
    
    def _check_authentication(self, context: Optional[Dict[str, Any]]):
        """Check if user is authenticated"""
        
        if not context or not context.get('authenticated'):
            raise AuthorizationError("Authentication required")
        
        # Check session validity
        session_created = context.get('session_created_at', 0)
        session_timeout = 3600  # 1 hour
        
        if time.time() - session_created > session_timeout:
            raise AuthorizationError("Session expired")
    
    def _check_mfa(self, context: Optional[Dict[str, Any]]):
        """Check MFA verification"""
        
        if not context or not context.get('mfa_verified'):
            raise AuthorizationError("MFA verification required for this command")
    
    def _check_authorization(self, command: WhitelistedCommand, context: Optional[Dict[str, Any]]):
        """Check if user/service is authorized to execute command"""
        
        if not context:
            context = {}
        
        # Check role-based access
        if command.allowed_roles:
            user_roles = set(context.get('roles', []))
            if not user_roles.intersection(command.allowed_roles):
                raise AuthorizationError(
                    f"Command requires one of roles: {command.allowed_roles}"
                )
        
        # Check service-based access
        if command.allowed_services:
            service = context.get('service')
            if service not in command.allowed_services:
                raise AuthorizationError(
                    f"Command not allowed for service: {service}"
                )
    
    def _check_rate_limit(self, command: WhitelistedCommand, context: Optional[Dict[str, Any]]):
        """Check and enforce rate limiting"""
        
        if not command.rate_limit:
            return
        
        # Create rate limit key
        user_id = context.get('user_id', 'anonymous') if context else 'anonymous'
        rate_key = f"{command.name}:{user_id}"
        
        # Get or create rate limiter
        if rate_key not in self.rate_limiters:
            self.rate_limiters[rate_key] = []
        
        # Clean old entries (older than 1 minute)
        current_time = time.time()
        self.rate_limiters[rate_key] = [
            t for t in self.rate_limiters[rate_key] 
            if current_time - t < 60
        ]
        
        # Check rate limit
        if len(self.rate_limiters[rate_key]) >= command.rate_limit:
            raise SecurityException(
                f"Rate limit exceeded for command '{command.name}' "
                f"({command.rate_limit} requests per minute)"
            )
        
        # Record request
        self.rate_limiters[rate_key].append(current_time)
    
    def _validate_parameters(self, command: WhitelistedCommand, 
                           params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize command parameters"""
        
        validated = {}
        
        for param_def in command.parameters:
            param_name = param_def.name
            
            # Check if parameter is provided
            if param_name not in params:
                if param_def.required:
                    raise ValidationError(f"Missing required parameter: {param_name}")
                else:
                    validated[param_name] = param_def.default
                    continue
            
            value = params[param_name]
            
            # Type validation
            if not isinstance(value, param_def.type):
                try:
                    value = param_def.type(value)
                except (ValueError, TypeError):
                    raise ValidationError(
                        f"Invalid type for parameter '{param_name}': "
                        f"expected {param_def.type.__name__}"
                    )
            
            # Allowed values check
            if param_def.allowed_values and value not in param_def.allowed_values:
                raise ValidationError(
                    f"Invalid value for parameter '{param_name}': "
                    f"must be one of {param_def.allowed_values}"
                )
            
            # Range validation
            if param_def.min_value is not None and value < param_def.min_value:
                raise ValidationError(
                    f"Parameter '{param_name}' below minimum value: {param_def.min_value}"
                )
            
            if param_def.max_value is not None and value > param_def.max_value:
                raise ValidationError(
                    f"Parameter '{param_name}' above maximum value: {param_def.max_value}"
                )
            
            # Pattern validation
            if param_def.pattern and isinstance(value, str):
                if not re.match(param_def.pattern, value):
                    raise ValidationError(
                        f"Parameter '{param_name}' does not match required pattern"
                    )
            
            # Custom validator
            if param_def.validator:
                try:
                    if not param_def.validator(value):
                        raise ValidationError(
                            f"Parameter '{param_name}' failed custom validation"
                        )
                except Exception as e:
                    raise ValidationError(
                        f"Parameter '{param_name}' validation error: {str(e)}"
                    )
            
            validated[param_name] = value
        
        # Check for extra parameters
        extra_params = set(params.keys()) - {p.name for p in command.parameters}
        if extra_params and self.enable_strict_mode:
            raise ValidationError(f"Unexpected parameters: {extra_params}")
        
        return validated
    
    def _perform_dangerous_command_checks(self, command: WhitelistedCommand,
                                        params: Dict[str, Any],
                                        context: Optional[Dict[str, Any]]):
        """Additional security checks for dangerous commands"""
        
        # Require admin role for dangerous commands
        if 'admin' not in context.get('roles', []):
            raise AuthorizationError("Dangerous commands require admin role")
        
        # Log dangerous command attempt
        self._log_suspicious_activity("dangerous_command_attempt", {
            "command": command.name,
            "params": params,
            "context": context
        })
        
        # Could add additional checks like:
        # - Require additional confirmation
        # - Check time-based restrictions
        # - Verify from trusted IP
        # - Send notification to security team
    
    def _validate_file_path(self, path: str) -> bool:
        """Validate file path to prevent directory traversal"""
        
        import os
        
        # Normalize path
        normalized = os.path.normpath(path)
        
        # Check for directory traversal
        if '..' in normalized or normalized.startswith('/'):
            return False
        
        # Check against allowed directories
        allowed_prefixes = ['data/', 'public/', 'uploads/']
        if not any(normalized.startswith(prefix) for prefix in allowed_prefixes):
            return False
        
        return True
    
    def _validate_math_expression(self, expr: str) -> bool:
        """Validate mathematical expression"""
        
        # Only allow safe characters
        allowed_chars = '0123456789+-*/()., '
        if not all(c in allowed_chars for c in expr):
            return False
        
        # Check balanced parentheses
        balance = 0
        for char in expr:
            if char == '(':
                balance += 1
            elif char == ')':
                balance -= 1
            if balance < 0:
                return False
        
        return balance == 0
    
    def _generate_execution_id(self) -> str:
        """Generate unique execution ID"""
        
        timestamp = str(time.time())
        random_data = str(hash(timestamp))
        return hashlib.sha256(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
    def _log_execution(self, execution_id: str, command: WhitelistedCommand,
                      params: Dict[str, Any], context: Optional[Dict[str, Any]],
                      status: str, duration: float):
        """Log command execution for audit trail"""
        
        log_entry = {
            'execution_id': execution_id,
            'timestamp': datetime.utcnow().isoformat(),
            'command': command.name,
            'category': command.category.value,
            'status': status,
            'duration': duration,
            'user_id': context.get('user_id') if context else None,
            'service': context.get('service') if context else None,
        }
        
        # Add parameters based on audit level
        if command.audit_level == "detailed":
            # Log parameter names but not values
            log_entry['parameters'] = list(params.keys())
        elif command.audit_level == "paranoid":
            # Log everything
            log_entry['parameters'] = params
            log_entry['context'] = context
        
        self.execution_history.append(log_entry)
        
        # Also log to security logger
        security_logger.info("command_executed", **log_entry)
        
        # Trim history if too large
        if len(self.execution_history) > 10000:
            self.execution_history = self.execution_history[-5000:]
    
    def _log_suspicious_activity(self, activity_type: str, details: Dict[str, Any]):
        """Log suspicious activity"""
        
        security_logger.warning("suspicious_activity", 
                              activity_type=activity_type,
                              details=details,
                              timestamp=datetime.utcnow().isoformat())
    
    # Safe command implementations
    def _safe_read_file(self, path: str, encoding: str = 'utf-8') -> str:
        """Safe file reading implementation"""
        
        # Additional runtime validation
        if not self._validate_file_path(path):
            raise ValidationError("Invalid file path")
        
        try:
            with open(path, 'r', encoding=encoding) as f:
                return f.read()
        except FileNotFoundError:
            raise ValidationError(f"File not found: {path}")
        except Exception as e:
            raise SecurityException(f"Error reading file: {str(e)}")
    
    def _safe_summarize(self, text: str, max_length: int = 500) -> str:
        """Safe text summarization"""
        
        # Simple implementation - in production, use proper NLP
        sentences = text.split('.')
        summary = []
        current_length = 0
        
        for sentence in sentences:
            sentence = sentence.strip()
            if sentence and current_length + len(sentence) <= max_length:
                summary.append(sentence)
                current_length += len(sentence)
        
        return '. '.join(summary) + '.'
    
    def _safe_calculate(self, expression: str) -> float:
        """Safe mathematical calculation"""
        
        # Additional validation
        if not self._validate_math_expression(expression):
            raise ValidationError("Invalid mathematical expression")
        
        # Safe evaluation using ast
        import ast
        import operator
        
        # Allowed operators
        operators = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow
        }
        
        def eval_expr(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return operators[type(node.op)](
                    eval_expr(node.left), 
                    eval_expr(node.right)
                )
            elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
                return -eval_expr(node.operand)
            else:
                raise ValueError("Unsupported operation")
        
        try:
            tree = ast.parse(expression, mode='eval')
            return eval_expr(tree.body)
        except Exception:
            raise ValidationError("Invalid expression")
    
    def get_command_info(self, command_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a command"""
        
        actual_name = self.command_aliases.get(command_name, command_name)
        
        if actual_name not in self.commands:
            return None
        
        command = self.commands[actual_name]
        
        return {
            'name': command.name,
            'category': command.category.value,
            'description': command.description,
            'parameters': [
                {
                    'name': p.name,
                    'type': p.type.__name__,
                    'required': p.required,
                    'description': p.description,
                    'allowed_values': p.allowed_values,
                    'default': p.default
                }
                for p in command.parameters
            ],
            'requires_auth': command.requires_auth,
            'requires_mfa': command.requires_mfa,
            'rate_limit': command.rate_limit,
            'dangerous': command.dangerous
        }
    
    def list_commands(self, category: Optional[CommandCategory] = None) -> List[str]:
        """List available commands, optionally filtered by category"""
        
        if category:
            return [
                cmd.name for cmd in self.commands.values()
                if cmd.category == category
            ]
        return list(self.commands.keys())

# Helper decorator for command handlers
def whitelisted_command(name: str, category: CommandCategory, **kwargs):
    """Decorator to register a function as a whitelisted command"""
    
    def decorator(func):
        # Extract parameters from function signature
        sig = inspect.signature(func)
        parameters = []
        
        for param_name, param in sig.parameters.items():
            if param_name == 'self':
                continue
            
            param_type = param.annotation if param.annotation != inspect.Parameter.empty else str
            required = param.default == inspect.Parameter.empty
            default = None if required else param.default
            
            parameters.append(CommandParameter(
                name=param_name,
                type=param_type,
                required=required,
                default=default
            ))
        
        # Create command
        command = WhitelistedCommand(
            name=name,
            category=category,
            handler=func,
            parameters=parameters,
            **kwargs
        )
        
        # Store command info on function for later registration
        func._whitelisted_command = command
        
        return func
    
    return decorator

# Example usage
if __name__ == "__main__":
    # Create whitelist
    whitelist = CommandWhitelist()
    
    # Example context
    context = {
        'authenticated': True,
        'user_id': 'user123',
        'roles': ['user'],
        'session_created_at': time.time()
    }
    
    # Execute safe command
    try:
        result = whitelist.execute_command(
            'calculate',
            {'expression': '2 + 2 * 3'},
            context
        )
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")
