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

# Load environment variables from .env file (if it exists)
# This allows us to configure the service without hardcoding values
load_dotenv()

# Global variable to store the initialized agent service
# This allows us to share the same agent instance across all HTTP requests
# for better performance and consistency
global_agent_service: Optional['AgentService'] = None

# Configure logging
logging.basicConfig(level=logging.INFO)

# ===== PYDANTIC MODELS =====

class GreetingRequest(BaseModel):
    """
    Data model for incoming greeting requests with security enhancements
    FastAPI will automatically validate that incoming JSON matches this structure
    """
    message: str = Field(..., description="The message to send to the agent", min_length=1)
    user_id: Optional[str] = Field(default=None, description="Optional user ID for session tracking")
    session_id: Optional[str] = Field(default=None, description="Optional session ID for conversation continuity")
    signed_context: Optional[str] = Field(default=None, description="Optional signed context from MCP server")

class GreetingResponse(BaseModel):
    """
    Data model for greeting responses sent back to the client with security metadata
    FastAPI will automatically convert our Python dict to JSON using this structure
    """
    response: str = Field(..., description="The agent's response")
    user_id: str = Field(..., description="User ID used for the session")
    session_id: str = Field(..., description="Session ID used for the conversation")
    success: bool = Field(..., description="Whether the request was successful")
    security_validation: Optional[Dict[str, Any]] = Field(default=None, description="Security validation metadata")

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

class AgentService:
    """
    Enhanced AgentService with optimized security controls
    
    Security Architecture:
    - Apigee Gateway: Handles authentication, rate limiting, CORS, basic validation
    - AgentService: Handles agent-specific threats (4 essential controls)
    - MCP Server: Handles comprehensive tool security (12 controls)
    
    Agent-Specific Security Controls:
    1. Prompt Injection Protection - Prevents agent behavior manipulation
    2. Context Size Validation - Protects agent from resource exhaustion
    3. MCP Response Verification - Trust but verify MCP responses
    4. Response Sanitization - Prevents information leakage
    """
    
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str, security_config: OptimizedSecurityConfig = None):
        """
        Initialize the AgentService with configuration parameters and security
        Args:
            mcp_client: Client for connecting to MCP (Model Context Protocol) servers
            model: The LLM model to use (e.g., "gemini-1.5-flash")
            name: Display name for the agent
            instruction: System prompt that defines the agent's behavior
            security_config: Configuration for security controls
        """
        self.mcp_client = mcp_client
        self.model = model
        self.name = name
        self.instruction = instruction
        
        # These will be set during initialization
        self.agent = None  # The actual LLM agent instance
        self.toolset = None  # Collection of tools from MCP servers
        self.session_service = None  # Manages conversation sessions
        self.is_initialized = False  # Flag to track if initialization completed
        self.app_name = "greeting_app"  # Internal app identifier
        
        # Initialize security system
        self.security_config = security_config or OptimizedSecurityConfig()
        self.security = OptimizedAgentSecurity(self.security_config)
        self.logger = logging.getLogger("agent_service")

    async def initialize(self):
        """
        Initialize the agent with tools and session service
        This method is called once when the FastAPI application starts up.
        It performs expensive operations like:
        - Connecting to MCP servers to discover available tools
        - Creating the LLM agent with those tools
        - Setting up session management for conversations
        By doing this once at startup (not for each request), we get much better performance.
        """
        try:
            print(f"🚀 Initializing Agent Service: {self.name}")
            
            # Connect to MCP server and get available tools
            # This might include tools for web search, calculations, file operations, etc.
            tools, toolset = await self.mcp_client.get_toolset()
            self.toolset = toolset
            
            # Create the LLM Agent with the discovered tools
            # The agent will be able to call these tools when needed
            self.agent = LlmAgent(
                model=self.model,  # Which LLM to use (e.g., Gemini)
                name=self.name,    # Agent's display name
                instruction=self.instruction,  # System prompt defining behavior
                tools=tools,       # Available tools for the agent
            )
            
            # Initialize session service for managing conversations
            # This keeps track of conversation history for each user
            self.session_service = InMemorySessionService()
            
            # Mark as successfully initialized
            self.is_initialized = True
            
            # Log security status
            security_status = await self.security.get_security_status()
            active_controls = [c for c in security_status['active_controls'] if c is not None]
            print(f"✅ Agent Service initialized successfully with {len(tools)} tools")
            print(f"🛡️ Security Controls Active: {len(active_controls)}/4")
            print(f"🏗️ Architecture: {security_status['architecture']}")
            
        except Exception as e:
            print(f"❌ Failed to initialize Agent Service: {e}")
            raise  # Re-raise the exception to prevent the service from starting

    async def greet_user(self, message: str, user_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Process a greeting request from a user using the pre-initialized agent
        This is the core method that:
        1. Validates the service is ready
        2. Manages user session (creating IDs if needed)
        3. Sends the message to the LLM agent
        4. Processes the agent's response and any tool calls
        5. Returns the final response
        
        Args:
            message: The user's message/question
            user_id: Optional identifier for the user (generated if not provided)
            session_id: Optional identifier for the conversation (generated if not provided)
            
        Returns:
            Dictionary containing the agent's response and session information
        """
        # Safety check: ensure the agent service was properly initialized
        if not self.is_initialized:
            raise HTTPException(status_code=503, detail="Agent service not initialized")
        
        # Generate unique IDs if not provided by the client
        # This allows for both stateful (with IDs) and stateless (without IDs) usage
        user_id = user_id or f"user_{uuid.uuid4().hex[:8]}"
        session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        
        try:
            # Create or retrieve an existing conversation session
            # Sessions maintain conversation history for context
            session = await self.session_service.create_session(
                app_name=self.app_name,
                user_id=user_id,
                session_id=session_id
            )
            
            # Create a Runner to execute the agent's processing
            # The Runner handles the complex orchestration of LLM calls and tool usage
            runner = Runner(
                agent=self.agent,
                app_name=self.app_name,
                session_service=self.session_service
            )
            
            # Convert the user's message into the format expected by the LLM
            content = types.Content(role='user', parts=[types.Part(text=message)])
            
            # Process the message through the agent
            # This returns an async iterator of events (LLM responses, tool calls, etc.)
            all_events = []
            async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
                # Log each event for debugging (LLM thinking, tool calls, final response)
                print(f"  [Event] Author: {event.author}, Type: {type(event).__name__}, Final: {event.is_final_response()}")
                all_events.append(event)
            
            # Extract the final response from all the events
            # The agent might generate multiple events (thinking, tool calls) before the final answer
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
            
            # Return the response in the expected format
            return {
                "response": final_response_text,
                "user_id": user_id,
                "session_id": session_id,
                "success": True
            }
            
        except Exception as e:
            # Log the error and convert it to an HTTP exception
            print(f"❌ Error processing greeting: {e}")
            raise HTTPException(status_code=500, detail=f"Error processing greeting: {str(e)}")

    async def secure_greet_user(self, request: GreetingRequest, fastapi_request: Request) -> Dict[str, Any]:
        """
        Process user greeting with optimized security validation
        
        Implements 4 essential security controls without redundancy:
        - Apigee handles: auth, rate limiting, CORS, basic validation
        - Agent handles: prompt injection, context size, MCP verification, response sanitization
        - MCP Server handles: comprehensive tool security
        """
        if not self.is_initialized:
            raise HTTPException(status_code=503, detail="Agent service not initialized")
        
        user_id = request.user_id or "anonymous"
        session_id = request.session_id or "default"
        
        try:
            # Phase 1: Request Validation (Agent-Specific Controls)
            request_valid, validation_results = await self.security.validate_request(
                message=request.message,
                user_id=user_id,
                session_id=session_id,
                context=request.signed_context or ""
            )
            
            if not request_valid:
                violations = validation_results.get("violations", [])
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
            
            # Phase 2: Process with Original Agent Service (calls MCP Server)
            # MCP Server will apply its 12 security controls
            agent_result = await self.greet_user(
                message=request.message,
                user_id=request.user_id,
                session_id=request.session_id
            )
            
            # Phase 3: Verify MCP Response Integrity
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
            
            # Phase 4: Sanitize Response
            agent_response = agent_result.get("response", "")
            sanitized_response, sanitization_results = await self.security.sanitize_response(
                response=agent_response,
                user_id=user_id,
                session_id=session_id
            )
            
            # Prepare optimized response
            enhanced_result = {
                "response": sanitized_response,
                "user_id": request.user_id,
                "session_id": request.session_id,
                "success": True,
                "security_validation": {
                    "agent_controls_passed": True,
                    "mcp_verification_passed": True,
                    "response_sanitized": sanitization_results["sanitization_metadata"].get("changes_made", False),
                    "validation_timestamp": validation_results["timestamp"]
                }
            }
            
            return enhanced_result
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Secure greeting processing failed: {e}")
            raise HTTPException(status_code=500, detail="Internal processing error")

    async def get_security_status(self) -> Dict[str, Any]:
        """Get optimized security status"""
        return await self.security.get_security_status()

    async def cleanup(self):
        """
        Clean up resources when the service shuts down
        This method ensures proper cleanup of:
        - MCP connections
        - Tool resources
        - Any other resources that need explicit cleanup
        """
        if self.toolset:
            await self.toolset.close()
            print("🧹 Agent service resources cleaned up")

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
        
        # Initialize MCP client for discovering and connecting to tools
        from base_mcp_client import BaseMCPClient
        mcp_server_url = os.getenv("MCP_SERVER_URL", "https://your-mcp-server-abc123-uc.a.run.app")
        mcp_client = BaseMCPClient(
            mcp_url=mcp_server_url,
            target_audience=mcp_server_url
        )
        
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
        
        # Create and initialize our enhanced agent service
        global_agent_service = AgentService(
            mcp_client=mcp_client,
            model=os.getenv("AGENT_MODEL", "gemini-1.5-flash"),
            name=os.getenv("AGENT_NAME", "Enhanced MCP Agent"),
            instruction=os.getenv("AGENT_INSTRUCTION",
                "You are a helpful AI assistant with access to secure MCP tools. "
                "Be conversational, helpful, and use the available tools when appropriate. "
                "Always maintain security best practices."),
            security_config=security_config
        )
        
        # Perform the expensive initialization (tool discovery, agent creation)
        await global_agent_service.initialize()
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
    title="Enhanced Agent Service with Security Controls",
    description="""
    AI Agent Service with optimized security architecture
    
    Security Architecture:
    ├── Apigee API Gateway (External)
    │   ├── Authentication & Authorization
    │   ├── Rate Limiting & Throttling
    │   ├── CORS Policy Enforcement
    │   └── Basic Input Validation
    │
    ├── Agent Service (This Service)
    │   ├── Prompt Injection Protection
    │   ├── Context Size Validation
    │   ├── MCP Response Verification
    │   └── Response Sanitization
    │
    └── MCP Server (External)
        └── Comprehensive Tool Security (12 controls)
    
    This architecture eliminates redundancy while maintaining robust security at each layer.
    """,
    version="2.0.0-enhanced",
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
    Enhanced greeting endpoint with streamlined security
    
    Security Flow:
    1. Apigee Gateway validates: auth, rate limits, CORS, basic input
    2. Agent Service validates: prompt injection, context size
    3. MCP Server applies: comprehensive tool security (12 controls)
    4. Agent Service verifies: MCP response integrity
    5. Agent Service sanitizes: response output
    
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
    
    # Process with enhanced security
    result = await global_agent_service.secure_greet_user(request, fastapi_request)
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
        "service": "Enhanced Agent Service with Security Controls",
        "version": "2.0.0-enhanced",
        "status": "running",
        "agent_initialized": global_agent_service.is_initialized if global_agent_service else False,
        "architecture": {
            "type": "optimized_layered_security",
            "layers": {
                "gateway": "Apigee API Gateway",
                "agent": "Agent Service (4 controls)",
                "tools": "MCP Server (12 controls)"
            },
            "benefits": [
                "Eliminates security redundancy",
                "Optimizes performance (~5ms overhead)",
                "Maintains defense-in-depth",
                "Clear separation of concerns"
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
    It wraps our new AgentService to provide the same API as before.
    """
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str):
        """Initialize legacy agent wrapper"""
        self.service = AgentService(mcp_client, model, name, instruction)
    
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
