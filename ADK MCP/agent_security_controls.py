"""
Optimized AgentService Security Implementation

This module provides streamlined security controls for AgentService when deployed
behind Apigee API Gateway and communicating with a secure MCP Server.

Security Architecture:
- Apigee Gateway: Handles authentication, rate limiting, CORS, basic validation
- AgentService: Handles agent-specific threats (4 controls)
- MCP Server: Handles comprehensive tool security (12 controls)

Agent-Specific Security Controls:
1. Prompt Injection Protection - Agent behavior manipulation prevention
2. Context Size Validation - Agent resource protection
3. MCP Response Verification - Trust but verify MCP responses
4. Response Sanitization - Agent output protection
"""

import os
import re
import time
import hashlib
import logging
import json
import base64
import requests
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)

@dataclass
class OptimizedSecurityConfig:
    """Streamlined security configuration for AgentService"""
    # Agent-specific controls only
    enable_prompt_injection_protection: bool = True
    enable_context_size_validation: bool = True
    enable_mcp_response_verification: bool = True
    enable_response_sanitization: bool = True
    enable_security_audit_logging: bool = True
    
    # NEW: LLM Guard Protection
    enable_llm_input_guard: bool = True
    enable_llm_output_guard: bool = True
    
    # Thresholds and limits
    max_context_size: int = 10000  # tokens/characters
    prompt_injection_threshold: float = 0.7
    max_response_size: int = 50000
    
    # MCP verification settings
    verify_mcp_signatures: bool = True
    trust_unsigned_responses: bool = False  # Fail-safe default
    
    # LLM Guard settings
    llm_model_name: str = "gemini-1.5-flash"
    llm_guard_timeout: float = 4.0

class PromptInjectionGuard:
    """
    Agent-specific prompt injection detection using GCP Model Armor
    
    Focuses on threats that specifically target AI agent behavior at the agent layer.
    This complements MCP Server's prompt injection protection by providing
    agent-specific detection patterns and context-aware analysis.
    
    Defense-in-Depth Rationale:
    - Agent Layer: Detects agent behavior manipulation (role confusion, instruction override)
    - MCP Layer: Detects tool-specific injection patterns (parameter manipulation, command injection)
    - Both layers use Model Armor but analyze different threat vectors
    """
    
    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
        self.logger = logging.getLogger("agent_prompt_injection_guard")
        
        # Agent-specific fallback patterns for when Model Armor is unavailable
        self.agent_fallback_patterns = [
            # Role manipulation specific to agents
            r"(?i)ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|commands)",
            r"(?i)forget\s+everything\s+(?:before|I\s+told\s+you)",
            r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:different|new)\s+(?:assistant|AI|bot)",
            r"(?i)(?:act|pretend)\s+(?:as\s+)?(?:if\s+)?(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new)",
            
            # Agent instruction override
            r"(?i)(?:new|updated?)\s+(?:instructions?|rules?|commands?)[\s:]+",
            r"(?i)(?:developer|admin|system)\s+mode[\s:]*(?:on|enabled?|active)?",
            r"(?i)override\s+(?:your\s+)?(?:safety\s+)?(?:guidelines?|rules?|instructions?)",
            r"(?i)bypass\s+(?:your\s+)?(?:safety\s+)?(?:measures?|controls?|restrictions?)",
            
            # Agent system prompt extraction
            r"(?i)(?:tell|show|reveal)\s+me\s+your\s+(?:system\s+)?(?:prompt|instructions?)",
            r"(?i)what\s+(?:are\s+)?your\s+(?:original\s+)?(?:instructions?|rules?|guidelines?)",
            r"(?i)repeat\s+your\s+(?:system\s+)?(?:prompt|instructions?)"
        ]
        
        # Compile fallback patterns for performance
        self.compiled_fallback_patterns = [re.compile(pattern) for pattern in self.agent_fallback_patterns]
    
    async def detect_injection(self, message: str) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Detect agent-specific prompt injection attempts using GCP Model Armor
        
        Args:
            message: User input message to analyze
            
        Returns:
            Tuple of (is_injection, risk_score, details)
        """
        detection_details = {
            "detection_method": "model_armor_with_fallback",
            "model_armor_used": False,
            "patterns_matched": [],
            "risk_factors": [],
            "message_length": len(message),
            "detection_timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Try Model Armor API first for enterprise-grade security
            model_armor_result = await self._check_model_armor_agent_threats(message)
            
            if model_armor_result['success']:
                detection_details["model_armor_used"] = True
                detection_details["model_armor_response"] = model_armor_result
                
                # Use Model Armor's analysis results
                is_injection = model_armor_result['is_malicious']
                risk_score = model_armor_result['confidence_score']
                
                # Add Model Armor threat details
                if model_armor_result.get('threat_types'):
                    detection_details["threat_types"] = model_armor_result['threat_types']
                
                if is_injection:
                    self.logger.warning(f"Agent prompt injection detected by Model Armor with confidence {risk_score:.2f}")
                
                return is_injection, risk_score, detection_details
            
            else:
                # Fallback to local patterns if Model Armor is unavailable
                self.logger.warning(f"Model Armor unavailable ({model_armor_result['error']}), using agent fallback patterns")
                detection_details["model_armor_error"] = model_armor_result['error']
                
                return await self._detect_with_fallback_patterns(message, detection_details)
                
        except Exception as e:
            self.logger.error(f"Agent prompt injection detection failed: {e}")
            # Fail-safe: use fallback patterns on error
            detection_details["error"] = str(e)
            return await self._detect_with_fallback_patterns(message, detection_details)
    
    async def _check_model_armor_agent_threats(self, text: str) -> Dict[str, Any]:
        """
        Check text against Model Armor API with agent-specific threat focus
        
        This focuses on agent behavior manipulation threats specifically,
        complementing the MCP Server's tool-focused threat detection.
        """
        try:
            # Get Model Armor API credentials
            api_key = os.getenv('MODEL_ARMOR_API_KEY')
            if not api_key:
                return {
                    'success': False,
                    'error': 'Model Armor API key not configured',
                    'is_malicious': False,
                    'confidence_score': 0.0
                }
            
            # Model Armor API endpoint
            model_armor_url = "https://api.modelarmor.com/v1/analyze"
            
            # Agent-specific detection configuration
            payload = {
                "text": text,
                "detection_types": [
                    "prompt_injection",      # Primary focus for agent layer
                    "role_manipulation",     # Agent behavior modification
                    "instruction_override",  # System prompt bypassing
                    "jailbreak_attempts"     # Agent constraint bypassing
                ],
                "context": "ai_agent_interaction",  # Specify agent context
                "security_profile": "agent_protection",  # Agent-specific profile
                "analysis_depth": "deep"  # Comprehensive analysis for agent protection
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AgentService-Security/1.0"
            }
            
            # Call Model Armor API
            response = requests.post(
                model_armor_url,
                json=payload,
                headers=headers,
                timeout=3.0  # Faster timeout for agent layer (MCP has 5s)
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'is_malicious': result.get('is_malicious', False),
                    'threat_types': result.get('detected_threats', []),
                    'confidence_score': result.get('confidence', 0.0),
                    'model_armor_id': result.get('analysis_id'),
                    'agent_specific_threats': result.get('agent_threats', [])
                }
            elif response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Model Armor rate limit exceeded',
                    'is_malicious': False,
                    'confidence_score': 0.0
                }
            else:
                return {
                    'success': False,
                    'error': f'Model Armor API error: {response.status_code}',
                    'is_malicious': False,
                    'confidence_score': 0.0
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Model Armor API timeout',
                'is_malicious': False,
                'confidence_score': 0.0
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Model Armor network error: {str(e)}',
                'is_malicious': False,
                'confidence_score': 0.0
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Model Armor unexpected error: {str(e)}',
                'is_malicious': False,
                'confidence_score': 0.0
            }
    
    async def _detect_with_fallback_patterns(self, message: str, detection_details: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        """
        Fallback detection using agent-specific patterns when Model Armor is unavailable
        """
        # Pattern matching analysis for agent-specific threats
        matches = 0
        for i, pattern in enumerate(self.compiled_fallback_patterns):
            if pattern.search(message):
                matches += 1
                detection_details["patterns_matched"].append({
                    "pattern_index": i,
                    "pattern_description": self._get_pattern_description(i)
                })
        
        # Calculate base risk score
        pattern_risk = min(matches / len(self.compiled_fallback_patterns), 1.0)
        
        # Additional agent-specific risk factors
        additional_risk = 0.0
        
        # Excessive length (possible injection padding)
        if len(message) > 1000:
            additional_risk += 0.1
            detection_details["risk_factors"].append("excessive_length")
        
        # Multiple agent instruction keywords
        agent_keywords = ["ignore", "forget", "override", "bypass", "new", "different", "assistant", "AI", "bot"]
        keyword_count = sum(1 for keyword in agent_keywords if keyword.lower() in message.lower())
        if keyword_count >= 3:
            additional_risk += 0.2
            detection_details["risk_factors"].append("multiple_agent_keywords")
        
        # Agent-specific repetitive patterns
        if self._has_repetitive_patterns(message):
            additional_risk += 0.1
            detection_details["risk_factors"].append("repetitive_patterns")
        
        # Final risk score
        risk_score = min(pattern_risk + additional_risk, 1.0)
        is_injection = risk_score >= self.threshold
        
        # Lower threshold for high-risk agent manipulation patterns
        if pattern_risk > 0.05:
            high_risk_agent_patterns = ["ignore", "override", "developer", "assistant", "AI", "bot"]
            if any(keyword in message.lower() for keyword in high_risk_agent_patterns):
                is_injection = True
                risk_score = max(risk_score, 0.8)
        
        detection_details["risk_score"] = risk_score
        detection_details["threshold"] = self.threshold
        detection_details["fallback_used"] = True
        
        if is_injection:
            self.logger.warning(f"Agent prompt injection detected with fallback patterns, risk score {risk_score:.2f}")
        
        return is_injection, risk_score, detection_details
    
    def _get_pattern_description(self, pattern_index: int) -> str:
        """Get human-readable description of detected pattern"""
        descriptions = [
            "role_manipulation", "instruction_forgetting", "identity_change", "role_acting",
            "new_instructions", "developer_mode", "safety_override", "restriction_bypass",
            "prompt_extraction", "instruction_query", "prompt_repetition"
        ]
        return descriptions[pattern_index] if pattern_index < len(descriptions) else "unknown_pattern"
    
    def _has_repetitive_patterns(self, message: str) -> bool:
        """Check for repetitive patterns that might indicate obfuscation"""
        words = message.lower().split()
        if len(words) < 4:
            return False
        
        # Check for repeated phrases
        word_count = {}
        for word in words:
            word_count[word] = word_count.get(word, 0) + 1
        
        # If any word appears more than 3 times, consider it repetitive
        return any(count > 3 for count in word_count.values())

class LLMGuard:
    """
    Model Armor protection for LLM interactions
    
    This class provides comprehensive Model Armor protection for:
    1. Context sent to LLM (input sanitization)
    2. Responses from LLM (output validation)
    3. Context poisoning prevention
    4. Prompt leakage protection
    5. Model behavior monitoring
    
    This complements the prompt injection guard by providing LLM-level protection.
    """
    
    def __init__(self, model_name: str = "gemini-1.5-flash"):
        self.model_name = model_name
        self.logger = logging.getLogger("llm_guard")
        
        # Model Armor configuration for LLM protection
        self.input_protection_config = {
            "detection_types": [
                "prompt_injection",
                "context_poisoning", 
                "pii_leakage",
                "malicious_content",
                "data_extraction_attempts",
                "model_manipulation"
            ],
            "context": "llm_input_protection",
            "security_profile": "llm_input_guard",
            "sanitization_mode": "sanitize_and_flag",
            "analysis_depth": "comprehensive"
        }
        
        self.output_protection_config = {
            "detection_types": [
                "prompt_leakage",
                "system_information_disclosure",
                "pii_exposure",
                "harmful_content",
                "model_artifacts",
                "training_data_leakage"
            ],
            "context": "llm_output_protection", 
            "security_profile": "llm_output_guard",
            "sanitization_mode": "redact_and_warn",
            "analysis_depth": "comprehensive"
        }
    
    async def sanitize_llm_input(self, context: str, user_message: str, system_prompt: str = "") -> Tuple[bool, Dict[str, str], Dict[str, Any]]:
        """
        Sanitize input going to LLM using Model Armor
        
        Args:
            context: Conversation context
            user_message: Current user message
            system_prompt: System prompt (if any)
            
        Returns:
            Tuple of (is_safe, sanitized_content, protection_details)
        """
        protection_details = {
            "protection_layer": "llm_input_guard",
            "model_armor_used": False,
            "sanitization_applied": False,
            "threats_detected": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Combine all input content for analysis
            combined_input = f"SYSTEM: {system_prompt}\nCONTEXT: {context}\nUSER: {user_message}"
            
            # Check with Model Armor
            armor_result = await self._check_model_armor_llm_input(combined_input)
            
            if armor_result['success']:
                protection_details["model_armor_used"] = True
                protection_details["model_armor_response"] = armor_result
                
                if armor_result['threats_detected']:
                    protection_details["threats_detected"] = armor_result['threats_detected']
                    protection_details["sanitization_applied"] = True
                    
                    # Log detected threats
                    self.logger.warning(f"LLM input threats detected: {armor_result['threats_detected']}")
                    
                    # Return sanitized content
                    sanitized_content = {
                        "context": armor_result.get('sanitized_context', context),
                        "user_message": armor_result.get('sanitized_message', user_message),
                        "system_prompt": armor_result.get('sanitized_prompt', system_prompt)
                    }
                    
                    return True, sanitized_content, protection_details
                else:
                    # Content is safe, return original
                    sanitized_content = {
                        "context": context,
                        "user_message": user_message,
                        "system_prompt": system_prompt
                    }
                    
                    return True, sanitized_content, protection_details
            else:
                # Model Armor unavailable, apply basic sanitization
                self.logger.warning(f"Model Armor unavailable for LLM input: {armor_result['error']}")
                protection_details["model_armor_error"] = armor_result['error']
                
                sanitized_content = await self._basic_input_sanitization(context, user_message, system_prompt)
                protection_details["sanitization_applied"] = True
                
                return True, sanitized_content, protection_details
                
        except Exception as e:
            self.logger.error(f"LLM input sanitization failed: {e}")
            protection_details["error"] = str(e)
            
            # Fail-safe: return original content with warning
            sanitized_content = {
                "context": context,
                "user_message": user_message,
                "system_prompt": system_prompt
            }
            
            return False, sanitized_content, protection_details
    
    async def validate_llm_output(self, llm_response: str, original_context: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate and sanitize LLM output using Model Armor
        
        Args:
            llm_response: Response from LLM
            original_context: Original context for comparison
            
        Returns:
            Tuple of (is_safe, sanitized_response, validation_details)
        """
        validation_details = {
            "protection_layer": "llm_output_guard",
            "model_armor_used": False,
            "sanitization_applied": False,
            "threats_detected": [],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Check LLM output with Model Armor
            armor_result = await self._check_model_armor_llm_output(llm_response, original_context)
            
            if armor_result['success']:
                validation_details["model_armor_used"] = True
                validation_details["model_armor_response"] = armor_result
                
                if armor_result['threats_detected']:
                    validation_details["threats_detected"] = armor_result['threats_detected']
                    validation_details["sanitization_applied"] = True
                    
                    # Log detected threats
                    self.logger.warning(f"LLM output threats detected: {armor_result['threats_detected']}")
                    
                    # Return sanitized response
                    sanitized_response = armor_result.get('sanitized_response', llm_response)
                    return True, sanitized_response, validation_details
                else:
                    # Output is safe
                    return True, llm_response, validation_details
            else:
                # Model Armor unavailable, apply basic validation
                self.logger.warning(f"Model Armor unavailable for LLM output: {armor_result['error']}")
                validation_details["model_armor_error"] = armor_result['error']
                
                sanitized_response = await self._basic_output_sanitization(llm_response)
                validation_details["sanitization_applied"] = True
                
                return True, sanitized_response, validation_details
                
        except Exception as e:
            self.logger.error(f"LLM output validation failed: {e}")
            validation_details["error"] = str(e)
            
            # Fail-safe: return original response with warning
            return False, llm_response, validation_details
    
    async def _check_model_armor_llm_input(self, combined_input: str) -> Dict[str, Any]:
        """Check LLM input against Model Armor API"""
        try:
            api_key = os.getenv('MODEL_ARMOR_API_KEY')
            if not api_key:
                return {
                    'success': False,
                    'error': 'Model Armor API key not configured',
                    'threats_detected': []
                }
            
            model_armor_url = "https://api.modelarmor.com/v1/llm-guard/input"
            
            payload = {
                "content": combined_input,
                "model_target": self.model_name,
                **self.input_protection_config
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AgentService-LLMGuard/1.0"
            }
            
            response = requests.post(
                model_armor_url,
                json=payload,
                headers=headers,
                timeout=4.0  # Slightly longer for comprehensive analysis
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'threats_detected': result.get('detected_threats', []),
                    'sanitized_context': result.get('sanitized_content', {}).get('context', ''),
                    'sanitized_message': result.get('sanitized_content', {}).get('user_message', ''),
                    'sanitized_prompt': result.get('sanitized_content', {}).get('system_prompt', ''),
                    'confidence_score': result.get('confidence', 0.0),
                    'analysis_id': result.get('analysis_id')
                }
            else:
                return {
                    'success': False,
                    'error': f'Model Armor API error: {response.status_code}',
                    'threats_detected': []
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Model Armor LLM input check failed: {str(e)}',
                'threats_detected': []
            }
    
    async def _check_model_armor_llm_output(self, llm_response: str, original_context: str) -> Dict[str, Any]:
        """Check LLM output against Model Armor API"""
        try:
            api_key = os.getenv('MODEL_ARMOR_API_KEY')
            if not api_key:
                return {
                    'success': False,
                    'error': 'Model Armor API key not configured',
                    'threats_detected': []
                }
            
            model_armor_url = "https://api.modelarmor.com/v1/llm-guard/output"
            
            payload = {
                "llm_response": llm_response,
                "original_context": original_context,
                "model_source": self.model_name,
                **self.output_protection_config
            }
            
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "AgentService-LLMGuard/1.0"
            }
            
            response = requests.post(
                model_armor_url,
                json=payload,
                headers=headers,
                timeout=4.0
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'threats_detected': result.get('detected_threats', []),
                    'sanitized_response': result.get('sanitized_response', llm_response),
                    'confidence_score': result.get('confidence', 0.0),
                    'analysis_id': result.get('analysis_id')
                }
            else:
                return {
                    'success': False,
                    'error': f'Model Armor API error: {response.status_code}',
                    'threats_detected': []
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'Model Armor LLM output check failed: {str(e)}',
                'threats_detected': []
            }
    
    async def _basic_input_sanitization(self, context: str, user_message: str, system_prompt: str) -> Dict[str, str]:
        """Basic input sanitization when Model Armor is unavailable"""
        # Basic patterns to remove/redact
        dangerous_patterns = [
            (r'(?i)IGNORE\s+PREVIOUS\s+INSTRUCTIONS', '[INSTRUCTION_OVERRIDE_BLOCKED]'),
            (r'(?i)SYSTEM\s*:\s*[^\\n]+', '[SYSTEM_INJECTION_BLOCKED]'),
            (r'(?i)DEVELOPER\s+MODE', '[DEV_MODE_BLOCKED]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
            (r'\b[A-Za-z0-9]{32,}\b', '[TOKEN_REDACTED]')
        ]
        
        sanitized_context = context
        sanitized_message = user_message
        sanitized_prompt = system_prompt
        
        for pattern, replacement in dangerous_patterns:
            sanitized_context = re.sub(pattern, replacement, sanitized_context)
            sanitized_message = re.sub(pattern, replacement, sanitized_message)
            sanitized_prompt = re.sub(pattern, replacement, sanitized_prompt)
        
        return {
            "context": sanitized_context,
            "user_message": sanitized_message,
            "system_prompt": sanitized_prompt
        }
    
    async def _basic_output_sanitization(self, llm_response: str) -> str:
        """Basic output sanitization when Model Armor is unavailable"""
        # Basic patterns to redact from LLM output
        sensitive_patterns = [
            (r'(?i)my\s+system\s+prompt\s+is[^.]*', '[SYSTEM_PROMPT_REDACTED]'),
            (r'(?i)internal\s+instructions[^.]*', '[INTERNAL_INFO_REDACTED]'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
            (r'\b[A-Za-z0-9]{32,}\b', '[TOKEN_REDACTED]'),
            (r'(?:[A-Za-z]:\\|\/)[^\s<>"]*', '[PATH_REDACTED]')
        ]
        
        sanitized_response = llm_response
        
        for pattern, replacement in sensitive_patterns:
            sanitized_response = re.sub(pattern, replacement, sanitized_response)
        
        return sanitized_response

class ContextSizeValidator:
    """
    Agent-specific context size validation
    
    Protects agent from resource exhaustion and token limit violations.
    """
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.logger = logging.getLogger("context_validator")
    
    async def validate_size(self, message: str, context: str = "") -> Tuple[bool, Dict[str, Any]]:
        """
        Validate context size limits for agent processing
        
        Args:
            message: User message
            context: Additional context (if any)
            
        Returns:
            Tuple of (is_valid, validation_details)
        """
        total_size = len(message) + len(context)
        
        validation_details = {
            "message_size": len(message),
            "context_size": len(context),
            "total_size": total_size,
            "max_allowed": self.max_size,
            "validation_timestamp": datetime.utcnow().isoformat()
        }
        
        is_valid = total_size <= self.max_size
        
        if not is_valid:
            self.logger.warning(f"Context size limit exceeded: {total_size} > {self.max_size}")
            validation_details["violation"] = "size_limit_exceeded"
        
        return is_valid, validation_details

class MCPResponseVerifier:
    """
    Verify signed responses from MCP Server
    
    Implements "trust but verify" principle for MCP server responses.
    """
    
    def __init__(self, verify_signatures: bool = True, trust_unsigned: bool = False):
        self.verify_signatures = verify_signatures
        self.trust_unsigned = trust_unsigned
        self.logger = logging.getLogger("mcp_verifier")
    
    async def verify_response(self, mcp_response: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify MCP server response integrity and authenticity
        
        Args:
            mcp_response: Response from MCP server
            
        Returns:
            Tuple of (is_valid, verification_details)
        """
        verification_details = {
            "signature_present": False,
            "signature_valid": False,
            "verification_timestamp": datetime.utcnow().isoformat(),
            "trust_level": "unknown"
        }
        
        try:
            # Check for security metadata
            security_data = mcp_response.get("security_validation", {})
            signature = security_data.get("signature")
            
            if signature:
                verification_details["signature_present"] = True
                
                # Verify signature
                response_data = mcp_response.get("data", "")
                is_signature_valid = await self._verify_signature(response_data, signature)
                verification_details["signature_valid"] = is_signature_valid
                
                if is_signature_valid:
                    verification_details["trust_level"] = "high"
                    return True, verification_details
                else:
                    verification_details["trust_level"] = "none"
                    self.logger.error("MCP response signature verification failed")
                    return False, verification_details
            
            else:
                # No signature present
                if self.trust_unsigned:
                    verification_details["trust_level"] = "low"
                    self.logger.warning("MCP response has no signature but proceeding (trust_unsigned=True)")
                    return True, verification_details
                else:
                    verification_details["trust_level"] = "none"
                    self.logger.error("MCP response has no signature and trust_unsigned=False")
                    return False, verification_details
        
        except Exception as e:
            self.logger.error(f"MCP response verification failed: {e}")
            verification_details["error"] = str(e)
            verification_details["trust_level"] = "none"
            return False, verification_details
    
    async def _verify_signature(self, data: str, signature: str) -> bool:
        """
        Verify cryptographic signature
        
        Args:
            data: Response data to verify
            signature: Signature to verify against
            
        Returns:
            True if signature is valid
        """
        try:
            # In production, use proper cryptographic verification
            # This is a simplified implementation for demonstration
                        
            # Create expected signature
            data_hash = hashlib.sha256(data.encode()).digest()
            expected_signature = base64.b64encode(data_hash).decode()
            
            # Compare with provided signature (simplified check)
            return signature.startswith(expected_signature[:16])
            
        except Exception as e:
            self.logger.error(f"Signature verification error: {e}")
            return False

class ResponseSanitizer:
    """
    Sanitize agent responses to prevent information leakage
    
    Removes sensitive information that might accidentally be included
    in agent responses.
    """
    
    def __init__(self, max_response_size: int = 50000):
        self.max_response_size = max_response_size
        self.logger = logging.getLogger("response_sanitizer")
        
        # Patterns for sensitive information
        self.sanitization_patterns = [
            # File paths
            (r'(?:[A-Za-z]:\\|\/)[^\s<>"]*', '[PATH_REDACTED]'),
            
            # API keys and tokens (32+ alphanumeric characters)
            (r'\b[A-Za-z0-9]{32,}\b', '[TOKEN_REDACTED]'),
            
            # Email addresses
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]'),
            
            # Phone numbers
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE_REDACTED]'),
            
            # Credit card numbers
            (r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD_REDACTED]'),
            
            # IP addresses
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]'),
            
            # Internal error messages
            (r'(?i)error:\s*.*?(?:file|line|function|module)', '[INTERNAL_ERROR]'),
            
            # System information
            (r'(?i)(?:windows|linux|macos|system)\s+(?:version|build)', '[SYSTEM_INFO]'),
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = [(re.compile(pattern), replacement) 
                                for pattern, replacement in self.sanitization_patterns]
    
    async def sanitize_response(self, response: str, user_id: str = "unknown") -> Tuple[str, Dict[str, Any]]:
        """
        Sanitize agent response to remove sensitive information
        
        Args:
            response: Agent response to sanitize
            user_id: User identifier for logging
            
        Returns:
            Tuple of (sanitized_response, sanitization_details)
        """
        sanitization_details = {
            "original_length": len(response),
            "patterns_applied": [],
            "size_truncated": False,
            "sanitization_timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            sanitized = response
            
            # Apply sanitization patterns
            for pattern, replacement in self.compiled_patterns:
                matches_before = len(pattern.findall(sanitized))
                if matches_before > 0:
                    sanitized = pattern.sub(replacement, sanitized)
                    sanitization_details["patterns_applied"].append({
                        "pattern_type": replacement,
                        "matches_found": matches_before
                    })
            
            # Truncate if too long
            if len(sanitized) > self.max_response_size:
                sanitized = sanitized[:self.max_response_size] + "\n\n[RESPONSE_TRUNCATED]"
                sanitization_details["size_truncated"] = True
            
            sanitization_details["final_length"] = len(sanitized)
            sanitization_details["changes_made"] = len(sanitization_details["patterns_applied"]) > 0 or sanitization_details["size_truncated"]
            
            # Log if sanitization was applied
            if sanitization_details["changes_made"]:
                self.logger.info(f"Response sanitized for user {user_id}: {len(sanitization_details['patterns_applied'])} patterns applied")
            
            return sanitized, sanitization_details
            
        except Exception as e:
            self.logger.error(f"Response sanitization failed: {e}")
            # Return original response if sanitization fails
            sanitization_details["error"] = str(e)
            return response, sanitization_details

class SecurityAuditor:
    """
    Security event logging for compliance and monitoring
    
    Logs agent-specific security events for analysis and incident response.
    """
    
    def __init__(self, enable_logging: bool = True):
        self.enable_logging = enable_logging
        self.logger = logging.getLogger("agent_security_audit")
        
        if enable_logging:
            # Configure structured logging
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - AGENT_SECURITY_AUDIT - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    async def log_security_event(self, event_type: str, details: Dict[str, Any], user_id: str = "unknown", session_id: str = "unknown"):
        """
        Log security events for monitoring and compliance
        
        Args:
            event_type: Type of security event
            details: Event details
            user_id: User identifier
            session_id: Session identifier
        """
        if not self.enable_logging:
            return
        
        audit_entry = {
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "session_id": session_id,
            "severity": self._get_event_severity(event_type),
            "details": details
        }
        
        # Log based on severity
        severity = audit_entry["severity"]
        log_message = f"AGENT_SECURITY_EVENT: {json.dumps(audit_entry, indent=None)}"
        
        if severity == "HIGH":
            self.logger.error(log_message)
        elif severity == "MEDIUM":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _get_event_severity(self, event_type: str) -> str:
        """Determine severity level for security events"""
        high_severity = [
            "prompt_injection_detected",
            "mcp_signature_verification_failed",
            "context_size_violation",
            "llm_input_threats_detected",
            "llm_output_threats_detected"
        ]
        
        medium_severity = [
            "response_sanitized",
            "unsigned_mcp_response",
            "security_check_error",
            "llm_input_guard_error",
            "llm_output_guard_error"
        ]
        
        if event_type in high_severity:
            return "HIGH"
        elif event_type in medium_severity:
            return "MEDIUM"
        else:
            return "LOW"

class OptimizedAgentSecurity:
    """
    Streamlined security implementation for AgentService with LLM Guard
    
    Implements 6 essential security controls (4 original + 2 LLM guards) needed when
    Apigee handles gateway security and MCP Server handles tool security.
    
    Enhanced Security Controls:
    1. Prompt Injection Protection (Agent Layer)
    2. Context Size Validation (Agent Layer)
    3. MCP Response Verification (Agent Layer) 
    4. Response Sanitization (Agent Layer)
    5. LLM Input Guard (LLM Layer) - NEW
    6. LLM Output Guard (LLM Layer) - NEW
    """
    
    def __init__(self, config: OptimizedSecurityConfig = None):
        """Initialize optimized security with LLM guard configuration"""
        self.config = config or OptimizedSecurityConfig()
        
        # Initialize security components based on configuration
        self.prompt_guard = PromptInjectionGuard(self.config.prompt_injection_threshold) if self.config.enable_prompt_injection_protection else None
        self.context_validator = ContextSizeValidator(self.config.max_context_size) if self.config.enable_context_size_validation else None
        self.mcp_verifier = MCPResponseVerifier(self.config.verify_mcp_signatures, self.config.trust_unsigned_responses) if self.config.enable_mcp_response_verification else None
        self.response_sanitizer = ResponseSanitizer(self.config.max_response_size) if self.config.enable_response_sanitization else None
        self.auditor = SecurityAuditor(self.config.enable_security_audit_logging) if self.config.enable_security_audit_logging else None
        
        # NEW: Initialize LLM Guard
        self.llm_guard = LLMGuard(self.config.llm_model_name) if (self.config.enable_llm_input_guard or self.config.enable_llm_output_guard) else None
        
        self.logger = logging.getLogger("optimized_agent_security")
    
    async def validate_request(self, message: str, user_id: str, session_id: str, context: str = "") -> Tuple[bool, Dict[str, Any]]:
        """
        Validate incoming request with agent-specific security controls
        
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
            "security_metadata": {}
        }
        
        try:
            # Control 1: Prompt Injection Protection
            if self.prompt_guard:
                is_injection, risk_score, injection_details = await self.prompt_guard.detect_injection(message)
                validation_results["controls_executed"].append("prompt_injection_protection")
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
            
            # Control 2: Context Size Validation
            if self.context_validator:
                is_size_valid, size_details = await self.context_validator.validate_size(message, context)
                validation_results["controls_executed"].append("context_size_validation")
                validation_results["security_metadata"]["context_size"] = size_details
                
                if not is_size_valid:
                    validation_results["violations"].append("context_size_exceeded")
                    if self.auditor:
                        await self.auditor.log_security_event(
                            "context_size_violation",
                            size_details,
                            user_id,
                            session_id
                        )
                    return False, validation_results
            
            # All validations passed
            return True, validation_results
            
        except Exception as e:
            self.logger.error(f"Request validation failed: {e}")
            validation_results["violations"].append("security_check_error")
            validation_results["error"] = str(e)
            
            if self.auditor:
                await self.auditor.log_security_event(
                    "security_check_error",
                    {"error": str(e), "phase": "request_validation"},
                    user_id,
                    session_id
                )
            
            return False, validation_results
    
    async def verify_mcp_response(self, mcp_response: Dict[str, Any], user_id: str, session_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify MCP server response integrity
        
        Args:
            mcp_response: Response from MCP server
            user_id: User identifier
            session_id: Session identifier
            
        Returns:
            Tuple of (is_valid, verification_results)
        """
        verification_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "control": "mcp_response_verification",
            "verification_metadata": {}
        }
        
        try:
            # Control 3: MCP Response Verification
            if self.mcp_verifier:
                is_valid, verify_details = await self.mcp_verifier.verify_response(mcp_response)
                verification_results["verification_metadata"] = verify_details
                
                if not is_valid:
                    if self.auditor:
                        await self.auditor.log_security_event(
                            "mcp_signature_verification_failed",
                            verify_details,
                            user_id,
                            session_id
                        )
                    return False, verification_results
                
                # Log successful verification if signature was present
                if verify_details.get("signature_present") and self.auditor:
                    await self.auditor.log_security_event(
                        "mcp_signature_verified",
                        {"trust_level": verify_details.get("trust_level")},
                        user_id,
                        session_id
                    )
            
            return True, verification_results
            
        except Exception as e:
            self.logger.error(f"MCP response verification failed: {e}")
            verification_results["error"] = str(e)
            
            if self.auditor:
                await self.auditor.log_security_event(
                    "mcp_verification_error",
                    {"error": str(e)},
                    user_id,
                    session_id
                )
            
            return False, verification_results
    
    async def sanitize_response(self, response: str, user_id: str, session_id: str) -> Tuple[str, Dict[str, Any]]:
        """
        Sanitize agent response
        
        Args:
            response: Agent response to sanitize
            user_id: User identifier
            session_id: Session identifier
            
        Returns:
            Tuple of (sanitized_response, sanitization_results)
        """
        sanitization_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "control": "response_sanitization",
            "sanitization_metadata": {}
        }
        
        try:
            # Control 4: Response Sanitization
            if self.response_sanitizer:
                sanitized_response, sanitize_details = await self.response_sanitizer.sanitize_response(response, user_id)
                sanitization_results["sanitization_metadata"] = sanitize_details
                
                # Log if changes were made
                if sanitize_details.get("changes_made") and self.auditor:
                    await self.auditor.log_security_event(
                        "response_sanitized",
                        sanitize_details,
                        user_id,
                        session_id
                    )
                
                return sanitized_response, sanitization_results
            else:
                # No sanitization configured
                return response, sanitization_results
                
        except Exception as e:
            self.logger.error(f"Response sanitization failed: {e}")
            sanitization_results["error"] = str(e)
            
            if self.auditor:
                await self.auditor.log_security_event(
                    "sanitization_error",
                    {"error": str(e)},
                    user_id,
                    session_id
                )
            
            # Return original response if sanitization fails
            return response, sanitization_results
    
    async def guard_llm_input(self, context: str, user_message: str, system_prompt: str = "") -> Tuple[bool, Dict[str, str], Dict[str, Any]]:
        """
        Guard LLM input using Model Armor protection
        
        Args:
            context: Conversation context
            user_message: Current user message  
            system_prompt: System prompt
            
        Returns:
            Tuple of (is_safe, sanitized_content, guard_results)
        """
        guard_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "control": "llm_input_guard",
            "guard_metadata": {}
        }
        
        try:
            # Control 5: LLM Input Guard
            if self.llm_guard and self.config.enable_llm_input_guard:
                is_safe, sanitized_content, guard_details = await self.llm_guard.sanitize_llm_input(
                    context, user_message, system_prompt
                )
                guard_results["guard_metadata"] = guard_details
                
                # Log if threats were detected
                if guard_details.get("threats_detected") and self.auditor:
                    await self.auditor.log_security_event(
                        "llm_input_threats_detected",
                        guard_details,
                        "system",
                        "llm_guard"
                    )
                
                return is_safe, sanitized_content, guard_results
            else:
                # No LLM input guard configured
                sanitized_content = {
                    "context": context,
                    "user_message": user_message,
                    "system_prompt": system_prompt
                }
                return True, sanitized_content, guard_results
                
        except Exception as e:
            self.logger.error(f"LLM input guard failed: {e}")
            guard_results["error"] = str(e)
            
            if self.auditor:
                await self.auditor.log_security_event(
                    "llm_input_guard_error",
                    {"error": str(e)},
                    "system", 
                    "llm_guard"
                )
            
            # Return original content if guard fails
            sanitized_content = {
                "context": context,
                "user_message": user_message,
                "system_prompt": system_prompt
            }
            return False, sanitized_content, guard_results
    
    async def guard_llm_output(self, llm_response: str, original_context: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Guard LLM output using Model Armor protection
        
        Args:
            llm_response: Response from LLM
            original_context: Original context for comparison
            
        Returns:
            Tuple of (is_safe, sanitized_response, guard_results)
        """
        guard_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "control": "llm_output_guard", 
            "guard_metadata": {}
        }
        
        try:
            # Control 6: LLM Output Guard
            if self.llm_guard and self.config.enable_llm_output_guard:
                is_safe, sanitized_response, guard_details = await self.llm_guard.validate_llm_output(
                    llm_response, original_context
                )
                guard_results["guard_metadata"] = guard_details
                
                # Log if threats were detected
                if guard_details.get("threats_detected") and self.auditor:
                    await self.auditor.log_security_event(
                        "llm_output_threats_detected",
                        guard_details,
                        "system",
                        "llm_guard"
                    )
                
                return is_safe, sanitized_response, guard_results
            else:
                # No LLM output guard configured
                return True, llm_response, guard_results
                
        except Exception as e:
            self.logger.error(f"LLM output guard failed: {e}")
            guard_results["error"] = str(e)
            
            if self.auditor:
                await self.auditor.log_security_event(
                    "llm_output_guard_error", 
                    {"error": str(e)},
                    "system",
                    "llm_guard"
                )
            
            # Return original response if guard fails
            return False, llm_response, guard_results
    
    async def get_security_status(self) -> Dict[str, Any]:
        """Get current security configuration and status including LLM guard"""
        return {
            "security_level": "optimized_with_llm_guard",
            "active_controls": [
                "prompt_injection_protection" if self.config.enable_prompt_injection_protection else None,
                "context_size_validation" if self.config.enable_context_size_validation else None,
                "mcp_response_verification" if self.config.enable_mcp_response_verification else None,
                "response_sanitization" if self.config.enable_response_sanitization else None,
                "llm_input_guard" if self.config.enable_llm_input_guard else None,
                "llm_output_guard" if self.config.enable_llm_output_guard else None
            ],
            "configuration": {
                "max_context_size": self.config.max_context_size,
                "prompt_injection_threshold": self.config.prompt_injection_threshold,
                "verify_mcp_signatures": self.config.verify_mcp_signatures,
                "trust_unsigned_responses": self.config.trust_unsigned_responses,
                "max_response_size": self.config.max_response_size,
                "llm_model_name": self.config.llm_model_name,
                "llm_guard_timeout": self.config.llm_guard_timeout
            },
            "architecture": "apigee_gateway + agent_service + llm_guard + mcp_server"
        }
