"""
Input Sanitization Module

Provides comprehensive input sanitization for preventing command injection attacks.
"""

import re
import bleach
from typing import Dict, Any, List
from ..common.exceptions import ValidationError
from ..common.logging_config import security_logger

class InputSanitizer:
    """Multi-layer input sanitization system"""
    
    # Define dangerous patterns
    DANGEROUS_PATTERNS = [
        r'execute\s*:',
        r'system\s*\(',
        r'eval\s*\(',
        r'exec\s*\(',
        r'__.*__',  # Python magic methods
        r'<!--.*?-->',  # HTML comments
        r'<script.*?>.*?</script>',  # Script tags
        r'\$\{.*?\}',  # Template injections
    ]
    
    def __init__(self, max_length: int = 10000, custom_patterns: List[str] = None):
        self.max_length = max_length
        if custom_patterns:
            self.DANGEROUS_PATTERNS.extend(custom_patterns)
    
    def sanitize_prompt(self, prompt: str, context: Dict[str, Any] = None) -> str:
        """
        Multi-layer prompt sanitization
        
        Args:
            prompt: Raw user input
            context: Optional context for logging
            
        Returns:
            Sanitized prompt
            
        Raises:
            ValidationError: If dangerous content detected
        """
        
        # Layer 1: Remove HTML and suspicious content
        cleaned = bleach.clean(prompt, tags=[], strip=True)
        
        # Layer 2: Check for dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, cleaned, re.IGNORECASE):
                security_logger.warning(
                    "dangerous_pattern_detected",
                    pattern=pattern,
                    context=context
                )
                raise ValidationError(f"Potentially malicious pattern detected: {pattern}")
        
        # Layer 3: Escape special characters
        cleaned = cleaned.replace('\\', '\\\\')
        cleaned = cleaned.replace('"', '\\"')
        cleaned = cleaned.replace("'", "\\'")
        
        # Layer 4: Length validation
        if len(cleaned) > self.max_length:
            raise ValidationError("Prompt exceeds maximum allowed length")
        
        return cleaned
