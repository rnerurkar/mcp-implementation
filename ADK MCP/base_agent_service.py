"""
Base Agent Service Implementation with Comprehensive Security Controls

This module provides the foundational security architecture for AI Agent services.
It implements a secure request processing pipeline that protects against various
security threats while maintaining the flexibility needed for different agent implementations.

Key Security Features:
- Optimized 4-control security architecture (no redundancy with Apigee/MCP)
- Model Armor integration for AI-specific threat detection
- LLM Guard protection for input/output validation
- Prompt injection detection and prevention
- Context size validation and resource protection
- Response sanitization and information leakage prevention
- Template Method pattern for extensible security

For Agent Service developers:
This base class should be inherited by your concrete agent service implementations.
It provides all the security middleware and validation logic, so you can focus
on implementing your specific agent behavior and tool integrations.

Architecture Pattern:
This follows the Template Method pattern - the base class defines the security
pipeline, and subclasses implement the specific agent functionality.

Security Architecture:
┌─────────────────────────────────────────────────────────────────┐
│                    3-Layer Security Architecture                 │
├─────────────────────────────────────────────────────────────────┤
│ Apigee Gateway → Agent Service (This) → MCP Server → Tools      │
│ (4 controls)    (4 controls)          (12 controls)            │
├─────────────────────────────────────────────────────────────────┤
│ Agent Layer Responsibilities:                                   │
│ • Prompt Injection Protection (Model Armor + fallback)         │
│ • Context Size Validation (resource protection)                │
│ • MCP Response Verification (trust but verify)                 │
│ • Response Sanitization (information leakage prevention)       │
└─────────────────────────────────────────────────────────────────┘
"""

# Core Python libraries for abstract base classes and type hints
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple
import logging
import uuid
from datetime import datetime

# FastAPI for HTTP exception handling
from fastapi import HTTPException, Request

# Pydantic models for data validation
from pydantic import BaseModel, Field

# Security controls
from agent_security_controls import OptimizedAgentSecurity, OptimizedSecurityConfig

# Base MCP Client for tool integration
from base_mcp_client import BaseMCPClient

# ===== PYDANTIC MODELS =====

class GreetingRequest(BaseModel):
    """
    Data model for incoming greeting requests with security enhancements
    """
    message: str = Field(..., description="The message to send to the agent", min_length=1)
    user_id: Optional[str] = Field(default=None, description="Optional user ID for session tracking")
    session_id: Optional[str] = Field(default=None, description="Optional session ID for conversation continuity")
    signed_context: Optional[str] = Field(default=None, description="Optional signed context from MCP server")

class GreetingResponse(BaseModel):
    """
    Data model for greeting responses sent back to the client with security metadata
    """
    response: str = Field(..., description="The agent's response")
    user_id: str = Field(..., description="User ID used for the session")
    session_id: str = Field(..., description="Session ID used for the conversation")
    success: bool = Field(..., description="Whether the request was successful")
    security_validation: Optional[Dict[str, Any]] = Field(default=None, description="Security validation metadata")

class BaseAgentServiceConfig(BaseModel):
    """
    Configuration model for base agent service
    """
    model: str = Field(default="gemini-1.5-flash", description="The LLM model to use")
    name: str = Field(default="Enhanced Agent", description="Display name for the agent")
    instruction: str = Field(default="You are a helpful AI assistant with secure access to tools.", description="System prompt for the agent")
    mcp_server_url: str = Field(..., description="URL of the MCP server")
    security_config: Optional[OptimizedSecurityConfig] = Field(default=None, description="Security configuration")

# ===== BASE AGENT SERVICE =====

class BaseAgentService(ABC):
    """
    Abstract base class for secure AI Agent services
    
    This class provides a complete security framework for Agent services including:
    - Optimized 4-control security architecture
    - Model Armor integration for AI-specific threats
    - LLM Guard protection for input/output validation
    - Template Method pattern for extensible processing
    - Integration with MCP servers for tool access
    
    Security Architecture:
    The class implements an optimized defense strategy with agent-specific controls:
    1. Prompt injection protection (Model Armor + fallback patterns)
    2. Context size validation (resource exhaustion prevention)
    3. MCP response verification (trust but verify external responses)
    4. Response sanitization (information leakage prevention)
    
    Design Pattern:
    This follows the Template Method pattern - this base class defines the
    security pipeline and workflow, while subclasses implement the specific
    agent behavior and tool integrations.
    
    For Agent Service Integration:
    Your concrete agent service class should inherit from this base class
    and implement the abstract methods. The base class handles all security
    concerns, allowing you to focus on your agent implementations.
    """
    
    def __init__(self, config: BaseAgentServiceConfig):
        """
        Initialize the base agent service with comprehensive security controls
        
        Args:
            config: Configuration for the agent service including security settings
        """
        self.config = config
        self.model = config.model
        self.name = config.name
        self.instruction = config.instruction
        self.mcp_server_url = config.mcp_server_url
        
        # Initialize security system
        self.security_config = config.security_config or OptimizedSecurityConfig()
        self.security = OptimizedAgentSecurity(self.security_config)
        self.logger = logging.getLogger("base_agent_service")
        
        # State tracking
        self.is_initialized = False
        self.initialization_error = None
        
        # Will be set by subclasses
        self.mcp_client: Optional[BaseMCPClient] = None
        
        print(f"🛡️ Initializing Base Agent Service: {self.name}")
        print(f"🗂️ Security Architecture: Optimized 4-control agent protection")
    
    async def initialize(self) -> bool:
        """
        Initialize the agent service with security validation
        
        This is a template method that orchestrates the initialization process:
        1. Initialize MCP client and tools
        2. Initialize the concrete agent implementation
        3. Validate security configuration
        4. Perform health checks
        
        Returns:
            bool: True if initialization successful, False otherwise
        """
        try:
            print(f"🚀 Initializing {self.name}...")
            
            # Step 1: Initialize security system
            await self._initialize_security()
            
            # Step 2: Initialize MCP client (implemented by subclass)
            await self._initialize_mcp_client()
            
            # Step 3: Initialize agent (implemented by subclass)
            await self._initialize_agent()
            
            # Step 4: Perform health checks
            await self._perform_health_checks()
            
            self.is_initialized = True
            
            # Log successful initialization
            security_status = await self.security.get_security_status()
            active_controls = [c for c in security_status['active_controls'] if c is not None]
            print(f"✅ {self.name} initialized successfully")
            print(f"🛡️ Security Controls Active: {len(active_controls)}/4")
            print(f"🏗️ Architecture: {security_status['architecture']}")
            
            return True
            
        except Exception as e:
            self.initialization_error = str(e)
            print(f"❌ Failed to initialize {self.name}: {e}")
            return False
    
    async def process_request(self, request: GreetingRequest, fastapi_request: Request) -> Dict[str, Any]:
        """
        Template method for processing agent requests with security
        
        This method implements the Template Method pattern:
        1. Pre-processing security validation
        2. Agent processing (implemented by subclass)
        3. Post-processing security validation
        4. Response preparation
        
        Args:
            request: The incoming greeting request
            fastapi_request: FastAPI request object for context
            
        Returns:
            Dict containing the processed response with security metadata
        """
        if not self.is_initialized:
            raise HTTPException(status_code=503, detail="Agent service not initialized")
        
        # Generate IDs if not provided
        user_id = request.user_id or f"user_{uuid.uuid4().hex[:8]}"
        session_id = request.session_id or f"session_{uuid.uuid4().hex[:8]}"
        
        try:
            # Phase 1: Pre-processing Security Validation
            validation_start = datetime.utcnow()
            request_valid, validation_results = await self._validate_request_security(
                message=request.message,
                user_id=user_id,
                session_id=session_id,
                context=request.signed_context or "",
                fastapi_request=fastapi_request
            )
            
            if not request_valid:
                violations = validation_results.get("violations", [])
                await self._handle_security_violation(violations, user_id, session_id)
            
            # Phase 2: Agent Processing (implemented by subclass)
            processing_start = datetime.utcnow()
            agent_result = await self._process_agent_request(
                message=request.message,
                user_id=user_id,
                session_id=session_id,
                context=request.signed_context,
                validation_context=validation_results
            )
            
            # Phase 3: Post-processing Security Validation
            postprocessing_start = datetime.utcnow()
            verified_result = await self._validate_response_security(
                agent_result=agent_result,
                user_id=user_id,
                session_id=session_id,
                original_request=request
            )
            
            # Phase 4: Response Preparation
            final_response = await self._prepare_final_response(
                verified_result=verified_result,
                user_id=user_id,
                session_id=session_id,
                request=request,
                processing_metadata={
                    "validation_time_ms": int((processing_start - validation_start).total_seconds() * 1000),
                    "processing_time_ms": int((postprocessing_start - processing_start).total_seconds() * 1000),
                    "postprocessing_time_ms": int((datetime.utcnow() - postprocessing_start).total_seconds() * 1000)
                }
            )
            
            return final_response
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Request processing failed: {e}")
            raise HTTPException(status_code=500, detail="Internal processing error")
    
    async def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status"""
        base_status = await self.security.get_security_status()
        
        # Add agent-specific status
        agent_status = await self._get_agent_specific_status()
        
        return {
            **base_status,
            "agent_status": agent_status,
            "initialization_status": {
                "initialized": self.is_initialized,
                "error": self.initialization_error
            }
        }
    
    async def cleanup(self):
        """
        Clean up resources when the service shuts down
        Template method for cleanup operations
        """
        try:
            # Cleanup agent-specific resources
            await self._cleanup_agent_resources()
            
            # Cleanup MCP client
            if self.mcp_client:
                await self.mcp_client.close()
                
            print(f"🧹 {self.name} resources cleaned up")
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
    
    # ===== TEMPLATE METHOD HOOKS =====
    
    async def _initialize_security(self):
        """Initialize security controls"""
        # Security system is already initialized in __init__
        # This hook allows subclasses to add additional security setup
        pass
    
    async def _validate_request_security(self, message: str, user_id: str, session_id: str, 
                                       context: str, fastapi_request: Request) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate incoming request with security controls
        
        Returns:
            Tuple of (is_valid, validation_results)
        """
        return await self.security.validate_request(
            message=message,
            user_id=user_id,
            session_id=session_id,
            context=context
        )
    
    async def _handle_security_violation(self, violations: list, user_id: str, session_id: str):
        """Handle security violations with appropriate HTTP responses"""
        if "prompt_injection_detected" in violations:
            raise HTTPException(
                status_code=400,
                detail="Content policy violation: Prompt injection detected"
            )
        elif "context_size_exceeded" in violations:
            raise HTTPException(
                status_code=413,
                detail="Request too large: Context size exceeded"
            )
        else:
            raise HTTPException(
                status_code=400,
                detail="Request validation failed"
            )
    
    async def _validate_response_security(self, agent_result: Dict[str, Any], user_id: str, 
                                        session_id: str, original_request: GreetingRequest) -> Dict[str, Any]:
        """
        Validate agent response with security controls
        
        Args:
            agent_result: Result from agent processing
            user_id: User identifier
            session_id: Session identifier
            original_request: Original request for context
            
        Returns:
            Validated and potentially modified result
        """
        # Verify MCP response integrity
        mcp_valid, verification_results = await self.security.verify_mcp_response(
            mcp_response=agent_result,
            user_id=user_id,
            session_id=session_id
        )
        
        if not mcp_valid:
            raise HTTPException(
                status_code=502,
                detail="MCP server response validation failed"
            )
        
        # Sanitize response
        agent_response = agent_result.get("response", "")
        sanitized_response, sanitization_results = await self.security.sanitize_response(
            response=agent_response,
            user_id=user_id,
            session_id=session_id
        )
        
        # Update result with sanitized response
        enhanced_result = {
            **agent_result,
            "response": sanitized_response,
            "security_validation": {
                "mcp_verification_passed": True,
                "response_sanitized": sanitization_results["sanitization_metadata"].get("changes_made", False),
                "verification_results": verification_results,
                "sanitization_results": sanitization_results
            }
        }
        
        return enhanced_result
    
    async def _prepare_final_response(self, verified_result: Dict[str, Any], user_id: str, 
                                    session_id: str, request: GreetingRequest, 
                                    processing_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare the final response with all metadata
        
        Args:
            verified_result: Security-validated result
            user_id: User identifier
            session_id: Session identifier
            request: Original request
            processing_metadata: Timing and processing information
            
        Returns:
            Final response dictionary
        """
        security_validation = verified_result.get("security_validation", {})
        
        return {
            "response": verified_result.get("response", ""),
            "user_id": user_id,
            "session_id": session_id,
            "success": True,
            "security_validation": {
                "agent_controls_passed": True,
                "mcp_verification_passed": security_validation.get("mcp_verification_passed", True),
                "response_sanitized": security_validation.get("response_sanitized", False),
                "validation_timestamp": datetime.utcnow().isoformat(),
                "processing_times": processing_metadata
            }
        }
    
    # ===== ABSTRACT METHODS FOR SUBCLASS IMPLEMENTATION =====
    
    @abstractmethod
    async def _initialize_mcp_client(self):
        """
        Initialize MCP client for tool discovery and communication
        
        This method should:
        1. Create and configure the MCP client
        2. Connect to MCP servers
        3. Discover available tools
        4. Set up tool communication
        
        The base class will call this during initialization.
        """
        pass
    
    @abstractmethod
    async def _initialize_agent(self):
        """
        Initialize the concrete agent implementation
        
        This method should:
        1. Create the LLM agent with discovered tools
        2. Configure agent behavior and instructions
        3. Set up session management
        4. Prepare agent for request processing
        
        The base class will call this during initialization.
        """
        pass
    
    @abstractmethod
    async def _process_agent_request(self, message: str, user_id: str, session_id: str, 
                                   context: Optional[str], validation_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process the agent request with the concrete agent implementation
        
        This is the core method where subclasses implement their specific
        agent behavior. The base class has already validated the request
        for security, so this method can focus on agent processing.
        
        Args:
            message: The user's message/question
            user_id: User identifier for session management
            session_id: Session identifier for conversation continuity
            context: Optional signed context from MCP server
            validation_context: Results from security validation
            
        Returns:
            Dictionary containing:
            - response: The agent's response text
            - success: Whether processing was successful
            - Any additional metadata from agent processing
        """
        pass
    
    @abstractmethod
    async def _get_agent_specific_status(self) -> Dict[str, Any]:
        """
        Get agent-specific status information
        
        This method should return status information specific to the
        concrete agent implementation, such as:
        - Agent readiness state
        - Tool availability
        - Model status
        - Session statistics
        
        Returns:
            Dictionary with agent-specific status information
        """
        pass
    
    @abstractmethod
    async def _cleanup_agent_resources(self):
        """
        Clean up agent-specific resources
        
        This method should clean up resources specific to the concrete
        agent implementation, such as:
        - Agent instances
        - Tool connections
        - Session services
        - Model resources
        
        The base class will call this during shutdown.
        """
        pass
    
    @abstractmethod
    async def _perform_health_checks(self):
        """
        Perform agent-specific health checks
        
        This method should verify that the agent implementation is
        healthy and ready to process requests. It should check:
        - Agent initialization status
        - Tool connectivity
        - Model availability
        - Resource availability
        
        Should raise an exception if health checks fail.
        """
        pass
