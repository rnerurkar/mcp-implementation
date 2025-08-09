# Import necessary libraries for the Agent Service
import asyncio  # For asynchronous programming support
import os  # For environment variable access
import uuid  # For generating unique identifiers
import logging  # For application logging
from typing import Any, Dict, Optional  # For type hints and better code documentation
from contextlib import asynccontextmanager  # For managing application lifecycle
from datetime import datetime  # For timestamp generation
from dotenv import load_dotenv  # For loading environment variables from .env file
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request  # FastAPI web framework components
from fastapi.middleware.cors import CORSMiddleware  # For Cross-Origin Resource Sharing
from fastapi.responses import JSONResponse  # For custom JSON responses
from pydantic import BaseModel, Field  # For data validation and API documentation
from google.adk.agents.llm_agent import LlmAgent  # Google ADK LLM Agent
from google.adk.runners import Runner  # Google ADK Runner for executing agent tasks
from google.adk.sessions import InMemorySessionService  # Session management for conversations
from google.genai import types  # Google GenAI types for message handling
from rich import print  # Enhanced printing with colors and formatting
from base_mcp_client import BaseMCPClient  # Our custom MCP client for tool discovery
from agent_security_controls import OptimizedAgentSecurity, OptimizedSecurityConfig  # Security controls
from base_agent_service import BaseAgentService, BaseAgentServiceConfig, GreetingRequest, GreetingResponse  # Base class

# Load environment variables from .env file (if it exists)
# This allows us to configure the service without hardcoding values
load_dotenv()

# Global variable to store the initialized agent service
# This allows us to share the same agent instance across all HTTP requests
# for better performance and consistency
global_agent_service: Optional['EnhancedAgentService'] = None

# Configure logging
logging.basicConfig(level=logging.INFO)

# ===== ADDITIONAL PYDANTIC MODELS =====

class HealthResponse(BaseModel):
    """
    Data model for health check responses
    This helps monitoring systems understand if our service is working properly
    """
    status: str = Field(..., description="Service status")
    agent_initialized: bool = Field(..., description="Whether the agent is properly initialized")
    version: str = Field(..., description="Service version")
    security_status: Optional[Dict[str, Any]] = Field(default=None, description="Security system status")

class SecurityStatusResponse(BaseModel):
    """Security status response for monitoring"""
    security_level: str
    active_controls: list
    configuration: Dict[str, Any]
    architecture: str

# ===== ENHANCED AGENT SERVICE =====

# ===== ENHANCED AGENT SERVICE =====

class EnhancedAgentService(BaseAgentService):
    """
    Concrete implementation of BaseAgentService with Google ADK integration
    
    This class inherits from BaseAgentService and implements the abstract methods
    to provide a complete agent service with:
    - Google ADK LLM Agent integration
    - MCP tool discovery and usage
    - Session management with InMemorySessionService
    - Enhanced security through the base class template methods
    
    The base class handles all security controls, allowing this class to focus
    on the specific agent implementation and tool integration.
    """
    
    def __init__(self, config: BaseAgentServiceConfig):
        """
        Initialize the Enhanced Agent Service
        
        Args:
            config: Configuration for the agent service
        """
        super().__init__(config)
        
        # Google ADK specific components
        self.agent = None  # The actual LLM agent instance
        self.toolset = None  # Collection of tools from MCP servers
        self.session_service = None  # Manages conversation sessions
        self.app_name = "enhanced_greeting_app"  # Internal app identifier
    
    # ===== IMPLEMENTATION OF ABSTRACT METHODS =====
    
    async def _initialize_mcp_client(self):
        """Initialize MCP client for tool discovery"""
        self.mcp_client = BaseMCPClient(
            mcp_url=self.mcp_server_url,
            target_audience=self.mcp_server_url
        )
        
        print(f"🔗 Connecting to MCP server: {self.mcp_server_url}")
    
    async def _initialize_agent(self):
        """Initialize the Google ADK agent with tools"""
        # Connect to MCP server and get available tools
        tools, toolset = await self.mcp_client.get_toolset()
        self.toolset = toolset
        
        # Create the LLM Agent with the discovered tools
        self.agent = LlmAgent(
            model=self.model,
            name=self.name,
            instruction=self.instruction,
            tools=tools,
        )
        
        # Initialize session service for managing conversations
        self.session_service = InMemorySessionService()
        
        print(f"🤖 Agent initialized with {len(tools)} tools")
    
    async def _process_agent_request(self, message: str, user_id: str, session_id: str, 
                                   context: Optional[str], validation_context: Dict[str, Any]) -> Dict[str, Any]:
        """Process the agent request using Google ADK"""
        try:
            # Create or retrieve an existing conversation session
            session = await self.session_service.create_session(
                app_name=self.app_name,
                user_id=user_id,
                session_id=session_id
            )
            
            # Create a Runner to execute the agent's processing
            runner = Runner(
                agent=self.agent,
                app_name=self.app_name,
                session_service=self.session_service
            )
            
            # Convert the user's message into the format expected by the LLM
            content = types.Content(role='user', parts=[types.Part(text=message)])
            
            # Process the message through the agent
            all_events = []
            async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
                print(f"  [Event] Author: {event.author}, Type: {type(event).__name__}, Final: {event.is_final_response()}")
                all_events.append(event)
            
            # Extract the final response from all the events
            final_response_events = [e for e in all_events if e.is_final_response()]
            final_response_text = ""
            
            # Combine all parts of the final response into a single string
            for final_response_event in final_response_events:
                if final_response_event and final_response_event.content and final_response_event.content.parts:
                    final_response_text += "".join(part.text for part in final_response_event.content.parts if part.text)
            
            # Fallback response if something went wrong with the agent processing
            if not final_response_text:
                final_response_text = "Hello! I'm here to help you. How can I assist you today?"
            
            print(f"<<< Agent Response: {final_response_text}")
            
            return {
                "response": final_response_text,
                "success": True,
                "events_processed": len(all_events),
                "final_events": len(final_response_events)
            }
            
        except Exception as e:
            print(f"❌ Error processing agent request: {e}")
            raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")
    
    async def _get_agent_specific_status(self) -> Dict[str, Any]:
        """Get Google ADK agent specific status"""
        return {
            "agent_type": "google_adk_llm_agent",
            "model": self.model,
            "tools_available": len(self.toolset.tools) if self.toolset else 0,
            "session_service_active": self.session_service is not None,
            "agent_ready": self.agent is not None,
            "mcp_client_connected": self.mcp_client is not None
        }
    
    async def _cleanup_agent_resources(self):
        """Clean up Google ADK specific resources"""
        if self.toolset:
            await self.toolset.close()
        
        # Session service cleanup (if needed)
        self.session_service = None
        self.agent = None
        
        print("🧹 Google ADK agent resources cleaned up")
    
    async def _perform_health_checks(self):
        """Perform health checks for Google ADK components"""
        if not self.agent:
            raise Exception("Agent not initialized")
        
        if not self.toolset:
            raise Exception("Toolset not available")
        
        if not self.session_service:
            raise Exception("Session service not initialized")
        
        if not self.mcp_client:
            raise Exception("MCP client not initialized")
        
        print("✅ All health checks passed")
    
    # ===== LEGACY COMPATIBILITY METHODS =====
    
    async def greet_user(self, message: str, user_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Legacy compatibility method for direct agent processing
        
        This method provides backward compatibility with the original interface
        while using the new template method pattern internally.
        """
        # Create a request object
        request = GreetingRequest(
            message=message,
            user_id=user_id,
            session_id=session_id
        )
        
        # Create a mock FastAPI request for compatibility
        class MockRequest:
            def __init__(self):
                self.headers = {}
                self.client = None
        
        mock_request = MockRequest()
        
        # Process through the template method
        result = await self.process_request(request, mock_request)
        
        # Return in legacy format
        return {
            "response": result["response"],
            "user_id": result["user_id"],
            "session_id": result["session_id"],
            "success": result["success"]
        }
    
    async def secure_greet_user(self, request: GreetingRequest, fastapi_request: Request) -> Dict[str, Any]:
        """
        Legacy compatibility method for secure processing
        
        This method now delegates to the base class template method.
        """
        return await self.process_request(request, fastapi_request)

# ===== FASTAPI APPLICATION LIFESPAN =====

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the FastAPI application lifespan with enhanced security initialization
    """
    global global_agent_service
    try:
        # === STARTUP PHASE ===
        print("🚀 Starting Enhanced Agent Service...")
        print("🗂️ Architecture: Apigee Gateway + Agent Service + MCP Server")
        
        # Initialize enhanced security configuration
        security_config = OptimizedSecurityConfig(
            enable_prompt_injection_protection=os.getenv("ENABLE_PROMPT_PROTECTION", "true").lower() == "true",
            enable_context_size_validation=os.getenv("ENABLE_CONTEXT_VALIDATION", "true").lower() == "true",
            enable_mcp_response_verification=os.getenv("ENABLE_MCP_VERIFICATION", "true").lower() == "true",
            enable_response_sanitization=os.getenv("ENABLE_RESPONSE_SANITIZATION", "true").lower() == "true",
            max_context_size=int(os.getenv("MAX_CONTEXT_SIZE", "10000")),
            prompt_injection_threshold=float(os.getenv("PROMPT_INJECTION_THRESHOLD", "0.7")),
            verify_mcp_signatures=os.getenv("VERIFY_MCP_SIGNATURES", "true").lower() == "true",
            trust_unsigned_responses=os.getenv("TRUST_UNSIGNED_RESPONSES", "false").lower() == "true"
        )
        
        # Create configuration for the agent service
        mcp_server_url = os.getenv("MCP_SERVER_URL", "https://your-mcp-server-abc123-uc.a.run.app")
        agent_config = BaseAgentServiceConfig(
            model=os.getenv("AGENT_MODEL", "gemini-1.5-flash"),
            name=os.getenv("AGENT_NAME", "Enhanced MCP Agent"),
            instruction=os.getenv("AGENT_INSTRUCTION",
                "You are a helpful AI assistant with access to secure MCP tools. "
                "Be conversational, helpful, and use the available tools when appropriate. "
                "Always maintain security best practices."),
            mcp_server_url=mcp_server_url,
            security_config=security_config
        )
        
        # Create and initialize our enhanced agent service
        global_agent_service = EnhancedAgentService(agent_config)
        
        # Perform the expensive initialization (tool discovery, agent creation)
        initialization_success = await global_agent_service.initialize()
        
        if not initialization_success:
            raise Exception("Failed to initialize Enhanced Agent Service")
        
        print("✅ Enhanced Agent Service startup complete")
        
        # === APPLICATION RUNS HERE ===
        yield  # This is where FastAPI serves requests
        
    except Exception as e:
        print(f"❌ Failed to start Enhanced Agent Service: {e}")
        raise  # Prevent the service from starting if initialization fails
    finally:
        # === SHUTDOWN PHASE ===
        print("🛑 Shutting down Enhanced Agent Service...")
        if global_agent_service:
            await global_agent_service.cleanup()
        print("✅ Enhanced Agent Service shutdown complete")

# ===== FASTAPI APPLICATION SETUP =====

app = FastAPI(
    title="Enhanced Agent Service with Template Method Security",
    description="""
    AI Agent Service implementing Template Method design pattern for security
    
    Architecture Pattern:
    ┌─────────────────────────────────────────────────────────────────┐
    │                  Template Method Pattern                        │
    ├─────────────────────────────────────────────────────────────────┤
    │ BaseAgentService (Abstract)                                     │
    │ ├── process_request() - Template method orchestrates security   │
    │ ├── _validate_request_security() - Pre-processing controls      │
    │ ├── _process_agent_request() - Abstract (implemented by subclass) │
    │ ├── _validate_response_security() - Post-processing controls    │
    │ └── _prepare_final_response() - Response preparation            │
    │                                                                 │
    │ EnhancedAgentService (Concrete)                                 │
    │ ├── _initialize_mcp_client() - Google ADK MCP integration       │
    │ ├── _initialize_agent() - LLM Agent setup                      │
    │ ├── _process_agent_request() - Core agent processing           │
    │ ├── _get_agent_specific_status() - Status reporting            │
    │ └── _cleanup_agent_resources() - Resource management           │
    └─────────────────────────────────────────────────────────────────┘
    
    Security Controls:
    ├── Layer 1: Apigee API Gateway (External)
    │   ├── Authentication & Authorization
    │   ├── Rate Limiting & Throttling  
    │   ├── CORS Policy Enforcement
    │   └── Basic Input Validation
    │
    ├── Layer 2: Agent Service (Template Method)
    │   ├── Prompt Injection Protection (Model Armor + fallback)
    │   ├── Context Size Validation (resource protection)
    │   ├── MCP Response Verification (trust but verify)
    │   └── Response Sanitization (leakage prevention)
    │
    └── Layer 3: MCP Server (External)
        └── Comprehensive Tool Security (12 controls)
    
    Benefits:
    • Template Method ensures consistent security across all requests
    • Abstract base class allows easy extension with new agent types
    • Clear separation between security (base) and functionality (concrete)
    • Eliminates security redundancy while maintaining defense-in-depth
    """,
    version="2.0.0-template-method",
    lifespan=lifespan
)

# Add CORS middleware (Apigee handles production CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Apigee handles origin restriction
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== API ENDPOINTS =====

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Enhanced health check endpoint with security status
    """
    global global_agent_service
    
    security_status = None
    if global_agent_service and global_agent_service.is_initialized:
        try:
            security_status = await global_agent_service.get_security_status()
        except Exception as e:
            print(f"Warning: Could not get security status: {e}")
    
    return HealthResponse(
        status="healthy" if global_agent_service and global_agent_service.is_initialized else "unhealthy",
        agent_initialized=global_agent_service.is_initialized if global_agent_service else False,
        version="2.0.0-enhanced",
        security_status=security_status
    )

@app.post("/greet", response_model=GreetingResponse)
async def greet_user_endpoint(request: GreetingRequest, fastapi_request: Request):
    """
    Enhanced greeting endpoint with template method security
    
    Security Flow (Template Method Pattern):
    1. BaseAgentService.process_request() orchestrates the entire flow
    2. Pre-processing: Validates prompt injection, context size
    3. Agent Processing: EnhancedAgentService._process_agent_request()
    4. Post-processing: Verifies MCP response, sanitizes output
    5. Response Preparation: Adds security metadata and timing
    
    This endpoint now uses the Template Method pattern where the base class
    manages the security pipeline and calls the concrete implementation
    for agent-specific processing.
    
    Example request:
    ```json
    {
        "message": "Hello, can you help me?",
        "user_id": "user123",
        "session_id": "session456",
        "signed_context": "optional_signed_context"
    }
    ```
    """
    global global_agent_service
    if not global_agent_service:
        raise HTTPException(status_code=503, detail="Agent service not available")
    
    # Process with template method pattern - base class handles security
    result = await global_agent_service.process_request(request, fastapi_request)
    return GreetingResponse(**result)

@app.get("/security/status", response_model=SecurityStatusResponse)
async def get_security_status():
    """
    Get security status and configuration
    
    Returns information about:
    - Security architecture level
    - Active agent-specific controls
    - Configuration parameters
    - Integration architecture
    """
    global global_agent_service
    if not global_agent_service:
        raise HTTPException(status_code=503, detail="Agent service not available")
    
    status = await global_agent_service.get_security_status()
    return SecurityStatusResponse(**status)

@app.get("/")
async def root():
    """
    Root endpoint with enhanced service information
    """
    global global_agent_service
    return {
        "service": "Enhanced Agent Service with Template Method Security",
        "version": "2.0.0-enhanced",
        "status": "running",
        "agent_initialized": global_agent_service.is_initialized if global_agent_service else False,
        "architecture": {
            "type": "template_method_pattern",
            "pattern": "BaseAgentService (abstract) -> EnhancedAgentService (concrete)",
            "security_flow": "Template method orchestrates security pipeline",
            "layers": {
                "gateway": "Apigee API Gateway",
                "agent": "Agent Service (4 controls via template method)",
                "tools": "MCP Server (12 controls)"
            },
            "benefits": [
                "Template Method pattern for extensible security",
                "Clear separation of concerns (base vs concrete)",
                "Consistent security pipeline across all requests",
                "Easy to extend with new agent implementations"
            ]
        },
        "endpoints": {
            "health": "/health",
            "greet": "/greet",
            "security_status": "/security/status",
            "docs": "/docs"
        }
    }

# Custom exception handler for enhanced error responses
@app.exception_handler(HTTPException)
async def enhanced_exception_handler(request: Request, exc: HTTPException):
    """Enhanced exception handler with security-aware logging"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request.headers.get("x-request-id", "unknown")
        }
    )

# ===== LEGACY COMPATIBILITY =====

class Agent:
    """
    Legacy Agent class for backward compatibility
    This maintains compatibility with older code that might expect the original Agent interface.
    It wraps our new EnhancedAgentService to provide the same API as before.
    """
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str):
        """Initialize legacy agent wrapper"""
        # Create configuration for the new agent service
        config = BaseAgentServiceConfig(
            model=model,
            name=name,
            instruction=instruction,
            mcp_server_url=mcp_client.mcp_url if hasattr(mcp_client, 'mcp_url') else "http://localhost:8000"
        )
        self.service = EnhancedAgentService(config)
        # Set the MCP client directly for compatibility
        self.service.mcp_client = mcp_client
    
    async def setup(self):
        """Initialize the underlying agent service"""
        await self.service.initialize()
    
    async def run(self, query: str):
        """Run a query through the agent and return the response"""
        result = await self.service.greet_user(query)
        print(f"<<< Agent Response: {result['response']}")
        return result

# ===== APPLICATION ENTRY POINT =====

if __name__ == "__main__":
    """
    Entry point for running the enhanced service
    """
    import uvicorn
    
    # Get configuration from environment variables with sensible defaults
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    
    print(f"🚀 Starting Enhanced Agent Service on {host}:{port}")
    print(f"🗂️ Architecture: Layered Security (Apigee + Agent + MCP)")
    print(f"📚 API Documentation: http://{host}:{port}/docs")
    print(f"🏥 Health Check: http://{host}:{port}/health")
    print(f"🛡️ Security Status: http://{host}:{port}/security/status")
    print("⚡ Performance: Optimized for minimal latency")
    
    # Start the enhanced server
    uvicorn.run(
        "agent_service:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )
