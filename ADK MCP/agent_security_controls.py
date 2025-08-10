"""
Consolidated Agent Security Implementation

This module consolidates agent security controls by leveraging the comprehensive
MCP security framework. This approach eliminates code duplication while maintaining
all necessary security functionality for the agent service.

Architecture:
- Reuses InputSanitizer, ContextSanitizer, and SecurityException from mcp_security_controls
- Adds agent-specific wrappers and configurations
- Maintains backward compatibility with existing OptimizedAgentSecurity interface

Benefits:
1. Reduced code duplication
2. Consistent security implementations across agent and MCP layers
3. Easier maintenance and updates
4. Shared threat intelligence and patterns
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Import comprehensive security controls from MCP framework
from mcp_security_controls import (
    InputSanitizer,          # Comprehensive prompt injection detection with Model Armor
    ContextSanitizer,        # Context sanitization and PII redaction
    SecurityException,       # Security-related exceptions
    # Additional imports as needed for comprehensive functionality
)

# Configure logging
logging.basicConfig(level=logging.INFO)

@dataclass
class ConsolidatedSecurityConfig:
    """Consolidated security configuration leveraging MCP framework"""
    # Agent-specific controls using MCP framework
    enable_prompt_injection_protection: bool = True
    enable_context_size_validation: bool = True
    enable_mcp_response_verification: bool = True
    enable_response_sanitization: bool = True
    enable_security_audit_logging: bool = True
    
    # LLM Guard controls
    enable_llm_input_guard: bool = True
    enable_llm_output_guard: bool = True
    
    # Thresholds and limits
    max_context_size: int = 10000
    prompt_injection_threshold: float = 0.7
    max_response_size: int = 50000
    
    # MCP verification settings
    verify_mcp_signatures: bool = True
    trust_unsigned_responses: bool = False
    
    # LLM Guard settings
    llm_model_name: str = "gemini-1.5-flash"
    llm_guard_timeout: float = 4.0


class AgentPromptGuard:
    """
    Agent-specific wrapper for InputSanitizer with agent context.
    Delegates comprehensive prompt injection detection to MCP InputSanitizer.
    """
    
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
        self.input_sanitizer = InputSanitizer()
        self.logger = logging.getLogger("agent_prompt_guard")
        
    async def detect_injection(self, message: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect prompt injection using MCP InputSanitizer with agent context.
        
        Args:
            message: User input message to analyze
            
        Returns:
            Tuple of (is_injection, risk_score, details)
        """
        try:
            # Use comprehensive InputSanitizer from MCP framework
            sanitized_input = self.input_sanitizer.sanitize(message)
            
            # Check if input was modified (indicating potential threats)
            if sanitized_input != message:
                # Input was sanitized, indicating a threat was detected
                return True, 0.9, {
                    "sanitized_input": sanitized_input,
                    "original_input": message,
                    "threat_detected": True,
                    "detection_method": "mcp_input_sanitizer",
                    "agent_context": True,
                    "timestamp": datetime.utcnow().isoformat()
                }
            else:
                # Input unchanged, no threats detected
                return False, 0.0, {
                    "sanitized_input": sanitized_input,
                    "detection_method": "mcp_input_sanitizer",
                    "agent_context": True,
                    "timestamp": datetime.utcnow().isoformat()
                }
            
        except Exception as e:
            self.logger.error(f"Prompt injection detection failed: {e}")
            # Fail-safe: assume injection on error
            return True, 1.0, {"error": str(e), "fail_safe": True}


class AgentContextValidator:
    """
    Agent-specific wrapper for ContextSanitizer with size validation.
    Delegates comprehensive context validation to MCP ContextSanitizer.
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.context_sanitizer = ContextSanitizer()
        self.logger = logging.getLogger("agent_context_validator")
        
    async def validate_size(self, message: str, context: str = "") -> Tuple[bool, Dict[str, Any]]:
        """
        Validate context size using MCP ContextSanitizer.
        
        Args:
            message: User message
            context: Additional context
            
        Returns:
            Tuple of (is_valid, validation_details)
        """
        try:
            total_content = f"{context}\n{message}"
            
            # Use comprehensive ContextSanitizer from MCP framework
            # ContextSanitizer expects a dictionary, so create a proper context structure
            context_dict = {
                "user_message": message,
                "conversation_context": context,
                "combined_content": total_content
            }
            
            sanitized_context = self.context_sanitizer.sanitize(context_dict)
            
            # Check size after sanitization
            sanitized_content = sanitized_context.get("combined_content", total_content)
            sanitized_size = len(sanitized_content)
            is_valid = sanitized_size <= self.max_size
            
            validation_details = {
                "original_size": len(total_content),
                "sanitized_size": sanitized_size,
                "max_allowed_size": self.max_size,
                "size_valid": is_valid,
                "sanitized_content": sanitized_content,
                "detection_method": "mcp_context_sanitizer",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if not is_valid:
                self.logger.warning(f"Context size exceeded: {sanitized_size} > {self.max_size}")
            
            return is_valid, validation_details
            
        except Exception as e:
            self.logger.error(f"Context validation failed: {e}")
            return False, {"error": str(e), "fail_safe": True}


class MCPResponseVerifier:
    """Agent-specific MCP response verification (keep existing implementation)."""
    
    def __init__(self, verify_signatures: bool = True, trust_unsigned: bool = False):
        self.verify_signatures = verify_signatures
        self.trust_unsigned = trust_unsigned
        self.logger = logging.getLogger("mcp_response_verifier")
        
    async def verify_response(self, mcp_response: Dict[str, Any], user_id: str, session_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Verify MCP response integrity and authenticity."""
        verification_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "response_verified": False,
            "signature_valid": False,
            "verification_details": {}
        }
        
        try:
            # Implementation depends on MCP response format
            # This is agent-specific verification logic
            if not isinstance(mcp_response, dict):
                return False, {"error": "Invalid response format"}
            
            # Check for required fields
            required_fields = ["result", "id"]
            for field in required_fields:
                if field not in mcp_response:
                    return False, {"error": f"Missing required field: {field}"}
            
            # Signature verification (if enabled)
            if self.verify_signatures:
                signature_valid = self._verify_signature(mcp_response)
                verification_results["signature_valid"] = signature_valid
                
                if not signature_valid and not self.trust_unsigned:
                    return False, verification_results
            
            verification_results["response_verified"] = True
            return True, verification_results
            
        except Exception as e:
            self.logger.error(f"MCP response verification failed: {e}")
            return False, {"error": str(e)}
    
    def _verify_signature(self, response: Dict[str, Any]) -> bool:
        """Verify response signature (placeholder implementation)."""
        # Implement actual signature verification logic
        return response.get("signature") is not None


class ResponseSanitizer:
    """Agent-specific response sanitization (delegates to ContextSanitizer for PII)."""
    
    def __init__(self, max_size: int = 50000):
        self.max_size = max_size
        self.context_sanitizer = ContextSanitizer()  # Reuse for PII redaction
        self.logger = logging.getLogger("response_sanitizer")
        
    async def sanitize_response(self, response: str, user_id: str, session_id: str) -> Tuple[str, Dict[str, Any]]:
        """Sanitize agent response using MCP ContextSanitizer for PII detection."""
        sanitization_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "original_length": len(response),
            "sanitization_applied": False,
            "pii_removed": False
        }
        
        try:
            # Size check
            if len(response) > self.max_size:
                response = response[:self.max_size] + "... [truncated]"
                sanitization_results["size_truncated"] = True
            
            # Use ContextSanitizer for comprehensive PII detection and removal
            # Create a proper context structure for the sanitizer
            response_context = {
                "response_text": response,
                "user_id": user_id,
                "session_id": session_id
            }
            
            sanitized_context = self.context_sanitizer.sanitize(response_context)
            sanitized_response = sanitized_context.get("response_text", response)
            
            # Check if sanitization was applied
            if sanitized_response != response:
                sanitization_results["sanitization_applied"] = True
                sanitization_results["pii_removed"] = True
            
            sanitization_results["final_length"] = len(sanitized_response)
            
            return sanitized_response, sanitization_results
            
        except Exception as e:
            self.logger.error(f"Response sanitization failed: {e}")
            # Return original response on error with warning
            return response, {"error": str(e), "sanitization_failed": True}


class SecurityAuditor:
    """Security audit logging (keep existing implementation)."""
    
    def __init__(self, enable_logging: bool = True):
        self.enable_logging = enable_logging
        self.logger = logging.getLogger("agent_security_audit")
        
        if enable_logging:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - AGENT_SECURITY_AUDIT - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    async def log_security_event(self, event_type: str, event_details: Dict[str, Any], 
                                user_id: str, session_id: str):
        """Log security events with structured format."""
        if not self.enable_logging:
            return
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "session_id": session_id,
            "details": event_details
        }
        
        self.logger.info(f"SECURITY_EVENT: {audit_entry}")


class ConsolidatedAgentSecurity:
    """
    Consolidated agent security implementation using MCP framework components.
    
    This implementation reduces code duplication by leveraging the comprehensive
    security controls from the MCP framework while maintaining agent-specific
    functionality and interfaces.
    """
    
    def __init__(self, config: ConsolidatedSecurityConfig = None):
        """Initialize consolidated security with shared MCP components."""
        self.config = config or ConsolidatedSecurityConfig()
        
        # Initialize agent-specific wrappers that delegate to MCP framework
        self.prompt_guard = AgentPromptGuard(self.config.prompt_injection_threshold) if self.config.enable_prompt_injection_protection else None
        self.context_validator = AgentContextValidator(self.config.max_context_size) if self.config.enable_context_size_validation else None
        self.mcp_verifier = MCPResponseVerifier(self.config.verify_mcp_signatures, self.config.trust_unsigned_responses) if self.config.enable_mcp_response_verification else None
        self.response_sanitizer = ResponseSanitizer(self.config.max_response_size) if self.config.enable_response_sanitization else None
        self.auditor = SecurityAuditor(self.config.enable_security_audit_logging) if self.config.enable_security_audit_logging else None
        
        self.logger = logging.getLogger("consolidated_agent_security")
        
        self.logger.info("Consolidated Agent Security initialized with MCP framework integration")
    
    async def validate_request(self, message: str, user_id: str, session_id: str, context: str = "") -> Tuple[bool, Dict[str, Any]]:
        """
        Validate incoming request using consolidated security controls.
        
        Args:
            message: User message
            user_id: User identifier
            session_id: Session identifier
            context: Additional context
            
        Returns:
            Tuple of (is_valid, validation_results)
        """
        validation_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "controls_executed": [],
            "violations": [],
            "security_metadata": {},
            "consolidation_info": "Using MCP framework components"
        }
        
        try:
            # Control 1: Prompt Injection Protection (using MCP InputSanitizer)
            if self.prompt_guard:
                is_injection, risk_score, injection_details = await self.prompt_guard.detect_injection(message)
                validation_results["controls_executed"].append("prompt_injection_protection_mcp")
                validation_results["security_metadata"]["prompt_injection"] = injection_details
                
                if is_injection:
                    validation_results["violations"].append("prompt_injection_detected")
                    if self.auditor:
                        await self.auditor.log_security_event(
                            "prompt_injection_detected",
                            injection_details,
                            user_id,
                            session_id
                        )
                    return False, validation_results
            
            # Control 2: Context Size Validation (using MCP ContextSanitizer)
            if self.context_validator:
                is_size_valid, size_details = await self.context_validator.validate_size(message, context)
                validation_results["controls_executed"].append("context_size_validation_mcp")
                validation_results["security_metadata"]["context_size"] = size_details
                
                if not is_size_valid:
                    validation_results["violations"].append("context_size_exceeded")
                    if self.auditor:
                        await self.auditor.log_security_event(
                            "context_size_exceeded",
                            size_details,
                            user_id,
                            session_id
                        )
                    return False, validation_results
            
            # All validations passed
            if self.auditor:
                await self.auditor.log_security_event(
                    "request_validation_passed",
                    validation_results,
                    user_id,
                    session_id
                )
            
            return True, validation_results
            
        except Exception as e:
            self.logger.error(f"Request validation failed: {e}")
            validation_results["error"] = str(e)
            return False, validation_results
    
    async def verify_mcp_response(self, mcp_response: Dict[str, Any], user_id: str, session_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Verify MCP response integrity."""
        if not self.mcp_verifier:
            return True, {"verification_disabled": True}
        
        return await self.mcp_verifier.verify_response(mcp_response, user_id, session_id)
    
    async def sanitize_response(self, response: str, user_id: str, session_id: str) -> Tuple[str, Dict[str, Any]]:
        """Sanitize agent response using MCP framework for PII detection."""
        if not self.response_sanitizer:
            return response, {"sanitization_disabled": True}
        
        return await self.response_sanitizer.sanitize_response(response, user_id, session_id)
    
    async def get_security_status(self) -> Dict[str, Any]:
        """Get current security configuration and status."""
        return {
            "framework": "consolidated_mcp_integration",
            "version": "1.0.0",
            "config": {
                "prompt_injection_protection": self.config.enable_prompt_injection_protection,
                "context_size_validation": self.config.enable_context_size_validation,
                "mcp_response_verification": self.config.enable_mcp_response_verification,
                "response_sanitization": self.config.enable_response_sanitization,
                "security_audit_logging": self.config.enable_security_audit_logging,
            },
            "mcp_integration": True,
            "components": {
                "prompt_guard": "AgentPromptGuard (delegates to MCP InputSanitizer)",
                "context_validator": "AgentContextValidator (delegates to MCP ContextSanitizer)",
                "mcp_verifier": "MCPResponseVerifier (agent-specific)",
                "response_sanitizer": "ResponseSanitizer (uses MCP ContextSanitizer for PII)",
                "auditor": "SecurityAuditor (agent-specific)"
            },
            "code_duplication_eliminated": True,
            "shared_threat_intelligence": True
        }


# Backward compatibility alias
OptimizedAgentSecurity = ConsolidatedAgentSecurity
OptimizedSecurityConfig = ConsolidatedSecurityConfig
