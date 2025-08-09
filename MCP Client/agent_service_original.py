# Import necessary libraries for the Agent Service
import asyncio  # For asynchronous programming support
import os  # For environment variable access
import uuid  # For generating unique identifiers
from typing import Any, Dict, Optional  # For type hints and better code documentation
from contextlib import asynccontextmanager  # For managing application lifecycle
from dotenv import load_dotenv  # For loading environment variables from .env file
from fastapi import FastAPI, HTTPException, BackgroundTasks  # FastAPI web framework components
from fastapi.middleware.cors import CORSMiddleware  # For Cross-Origin Resource Sharing
from pydantic import BaseModel, Field  # For data validation and API documentation
from google.adk.agents.llm_agent import LlmAgent  # Google ADK LLM Agent
from google.adk.runners import Runner  # Google ADK Runner for executing agent tasks
from google.adk.sessions import InMemorySessionService  # Session management for conversations
from google.genai import types  # Google GenAI types for message handling
from rich import print  # Enhanced printing with colors and formatting
from base_mcp_client import BaseMCPClient  # Our custom MCP client for tool discovery

# Load environment variables from .env file (if it exists)
# This allows us to configure the service without hardcoding values
load_dotenv()

# Global variable to store the initialized agent service
# This allows us to share the same agent instance across all HTTP requests
# for better performance and consistency
global_agent_service: Optional['AgentService'] = None

# Pydantic models define the structure of API requests and responses
# These models automatically validate incoming data and generate API documentation

class GreetingRequest(BaseModel):
    """
    Data model for incoming greeting requests
    FastAPI will automatically validate that incoming JSON matches this structure
    """
    message: str = Field(..., description="The message to send to the agent", min_length=1)
    user_id: Optional[str] = Field(default=None, description="Optional user ID for session tracking")
    session_id: Optional[str] = Field(default=None, description="Optional session ID for conversation continuity")

class GreetingResponse(BaseModel):
    """
    Data model for greeting responses sent back to the client
    FastAPI will automatically convert our Python dict to JSON using this structure
    """
    response: str = Field(..., description="The agent's response")
    user_id: str = Field(..., description="User ID used for the session")
    session_id: str = Field(..., description="Session ID used for the conversation")
    success: bool = Field(..., description="Whether the request was successful")

class HealthResponse(BaseModel):
    """
    Data model for health check responses
    This helps monitoring systems understand if our service is working properly
    """
    status: str = Field(..., description="Service status")
    agent_initialized: bool = Field(..., description="Whether the agent is properly initialized")
    version: str = Field(..., description="Service version")

class AgentService:
    """
    Main service class that manages our AI agent and its interactions
    
    This class encapsulates all the logic for:
    - Initializing the agent with tools from MCP servers
    - Managing user sessions and conversations
    - Processing user messages and generating responses
    - Handling cleanup when the service shuts down
    """
    
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str):
        """
        Initialize the AgentService with configuration parameters
        
        Args:
            mcp_client: Client for connecting to MCP (Model Context Protocol) servers
            model: The LLM model to use (e.g., "gemini-1.5-flash")
            name: Display name for the agent
            instruction: System prompt that defines the agent's behavior
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
            print(f"✅ Agent Service initialized successfully with {len(tools)} tools")
            
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the FastAPI application lifespan
    
    This is a special FastAPI feature that allows us to run code:
    - Once when the application starts up (before accepting any requests)
    - Once when the application shuts down (after all requests are done)
    
    This pattern is crucial for:
    - Expensive initialization that should happen once
    - Proper cleanup of resources
    - Ensuring the service is ready before accepting traffic
    """
    global global_agent_service
    
    try:
        # === STARTUP PHASE ===
        print("🚀 Starting Agent Service...")
        
        # Initialize MCP client for discovering and connecting to tools
        # Configure for Google Cloud Run service-to-service authentication
        from base_mcp_client import BaseMCPClient
        
        mcp_server_url = os.getenv("MCP_SERVER_URL", "https://your-mcp-server-abc123-uc.a.run.app")
        
        mcp_client = BaseMCPClient(
            mcp_url=mcp_server_url,
            target_audience=mcp_server_url  # For Cloud Run, audience is typically the service URL
        )
        
        # Create and initialize our agent service with configuration from environment variables
        # This allows deployment-time configuration without code changes
        global_agent_service = AgentService(
            mcp_client=mcp_client,
            model=os.getenv("AGENT_MODEL", "gemini-1.5-flash"),  # LLM model to use
            name=os.getenv("AGENT_NAME", "GreetingAgent"),       # Agent display name
            instruction=os.getenv("AGENT_INSTRUCTION",           # Agent behavior instructions
                "You are a friendly greeting agent. Welcome users warmly and help them with their requests. "
                "Be conversational, helpful, and use the available tools when appropriate.")
        )
        
        # Perform the expensive initialization (tool discovery, agent creation)
        await global_agent_service.initialize()
        print("✅ Agent Service startup complete")
        
        # === APPLICATION RUNS HERE ===
        yield  # This is where FastAPI serves requests
        
    except Exception as e:
        print(f"❌ Failed to start Agent Service: {e}")
        raise  # Prevent the service from starting if initialization fails
    finally:
        # === SHUTDOWN PHASE ===
        print("🛑 Shutting down Agent Service...")
        if global_agent_service:
            await global_agent_service.cleanup()
        print("✅ Agent Service shutdown complete")

# ===== FASTAPI APPLICATION SETUP =====

# Create the FastAPI application instance
# FastAPI is a modern web framework that automatically:
# - Validates request/response data using our Pydantic models
# - Generates interactive API documentation
# - Handles async operations efficiently
# - Provides built-in support for JSON APIs
app = FastAPI(
    title="Agent Greeting Service",                                    # Shown in API docs
    description="ADK Agent service with MCP tool integration for greeting users",  # Detailed description
    version="1.0.0",                                                  # API version
    lifespan=lifespan                                                 # Lifecycle management function
)

# Add CORS (Cross-Origin Resource Sharing) middleware
# This allows web browsers to make requests to our API from different domains
# Essential for web applications that need to call our API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Allow requests from any domain (configure for production)
    allow_credentials=True,        # Allow cookies and authentication headers
    allow_methods=["*"],          # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],          # Allow all headers
)

# ===== API ENDPOINTS =====

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint for monitoring and load balancers
    
    This endpoint is used by:
    - Cloud Run to determine if the service is ready to receive traffic
    - Monitoring systems to check service health
    - Load balancers to route traffic only to healthy instances
    
    Returns:
        HealthResponse: Status information about the service
    """
    global global_agent_service
    
    return HealthResponse(
        status="healthy" if global_agent_service and global_agent_service.is_initialized else "unhealthy",
        agent_initialized=global_agent_service.is_initialized if global_agent_service else False,
        version="1.0.0"
    )

@app.post("/greet", response_model=GreetingResponse)
async def greet_user(request: GreetingRequest):
    """
    Main API endpoint for interacting with the AI agent
    
    This endpoint:
    1. Receives a JSON request with a user message (and optional IDs)
    2. Validates the request data automatically (thanks to Pydantic)
    3. Passes the message to our pre-initialized agent
    4. Returns the agent's response as JSON
    
    The agent can use available MCP tools during processing (web search, calculations, etc.)
    
    Example request:
    POST /greet
    {
        "message": "Hello, can you help me with math?",
        "user_id": "user123",
        "session_id": "session456"
    }
    
    Args:
        request: The validated request data from the client
        
    Returns:
        GreetingResponse: The agent's response with session information
    """
    global global_agent_service
    
    # Safety check: ensure the agent service is available
    if not global_agent_service:
        raise HTTPException(status_code=503, detail="Agent service not available")
    
    # Process the request using our agent service
    result = await global_agent_service.greet_user(
        message=request.message,
        user_id=request.user_id,
        session_id=request.session_id
    )
    
    # FastAPI automatically converts our dict to JSON using the response model
    return GreetingResponse(**result)

@app.get("/")
async def root():
    """
    Root endpoint providing service information
    
    This endpoint gives an overview of the service and its capabilities.
    Useful for:
    - Quick service verification
    - Discovering available endpoints
    - Checking if the agent is properly initialized
    
    Returns:
        dict: Service metadata and endpoint information
    """
    global global_agent_service
    
    return {
        "service": "Agent Greeting Service",
        "version": "1.0.0",
        "status": "running",
        "agent_initialized": global_agent_service.is_initialized if global_agent_service else False,
        "endpoints": {
            "health": "/health",          # Health check for monitoring
            "greet": "/greet",           # Main agent interaction endpoint
            "docs": "/docs"              # Interactive API documentation
        }
    }

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
    Entry point for running the service directly
    
    This code runs when you execute: python agent_service.py
    It starts a development server using Uvicorn (ASGI server)
    
    For production deployment, this is typically handled by the deployment infrastructure
    (Docker, Cloud Run, etc.) rather than running this script directly.
    """
    import uvicorn
    
    # Get configuration from environment variables with sensible defaults
    host = os.getenv("HOST", "0.0.0.0")    # Listen on all interfaces
    port = int(os.getenv("PORT", "8080"))   # Default port for Cloud Run
    
    print(f"🚀 Starting Agent Service on {host}:{port}")
    print(f"📚 API Documentation will be available at: http://{host}:{port}/docs")
    print(f"🏥 Health Check will be available at: http://{host}:{port}/health")
    
    # Start the server
    # - "agent_service:app" tells Uvicorn to import the 'app' object from this file
    # - reload=False for production stability (set to True for development)
    # - log_level="info" provides good balance of logging detail
    uvicorn.run(
        "agent_service:app",              # Application to serve
        host=host,                        # Host interface to bind to
        port=port,                        # Port to listen on
        reload=False,                     # Auto-reload on code changes (development only)
        log_level="info"                  # Logging verbosity
    )