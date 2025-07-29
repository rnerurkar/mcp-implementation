import asyncio
import os
import uuid
from typing import Any, Dict, Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich import print
from base_mcp_client import BaseMCPClient

load_dotenv()

# Global variable to hold the initialized agent
global_agent_service: Optional['AgentService'] = None

class GreetingRequest(BaseModel):
    """Request model for greeting endpoint"""
    message: str = Field(..., description="The message to send to the agent", min_length=1)
    user_id: Optional[str] = Field(default=None, description="Optional user ID for session tracking")
    session_id: Optional[str] = Field(default=None, description="Optional session ID for conversation continuity")

class GreetingResponse(BaseModel):
    """Response model for greeting endpoint"""
    response: str = Field(..., description="The agent's response")
    user_id: str = Field(..., description="User ID used for the session")
    session_id: str = Field(..., description="Session ID used for the conversation")
    success: bool = Field(..., description="Whether the request was successful")

class HealthResponse(BaseModel):
    """Response model for health check"""
    status: str = Field(..., description="Service status")
    agent_initialized: bool = Field(..., description="Whether the agent is properly initialized")
    version: str = Field(..., description="Service version")

class AgentService:
    """Enhanced Agent service with pre-initialization and FastAPI integration"""
    
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str):
        self.mcp_client = mcp_client
        self.model = model
        self.name = name
        self.instruction = instruction
        self.agent = None
        self.toolset = None
        self.session_service = None
        self.is_initialized = False
        self.app_name = "greeting_app"

    async def initialize(self):
        """Initialize the agent with tools and session service - called once at startup"""
        try:
            print(f"🚀 Initializing Agent Service: {self.name}")
            
            # Get tools from MCP client
            tools, toolset = await self.mcp_client.get_toolset()
            self.toolset = toolset
            
            # Create LLM Agent
            self.agent = LlmAgent(
                model=self.model,
                name=self.name,
                instruction=self.instruction,
                tools=tools,
            )
            
            # Initialize session service
            self.session_service = InMemorySessionService()
            
            self.is_initialized = True
            print(f"✅ Agent Service initialized successfully with {len(tools)} tools")
            
        except Exception as e:
            print(f"❌ Failed to initialize Agent Service: {e}")
            raise

    async def greet_user(self, message: str, user_id: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Process greeting request using pre-initialized agent"""
        if not self.is_initialized:
            raise HTTPException(status_code=503, detail="Agent service not initialized")
        
        # Generate IDs if not provided
        user_id = user_id or f"user_{uuid.uuid4().hex[:8]}"
        session_id = session_id or f"session_{uuid.uuid4().hex[:8]}"
        
        try:
            # Create or get session
            session = await self.session_service.create_session(
                app_name=self.app_name,
                user_id=user_id,
                session_id=session_id
            )
            
            # Create runner
            runner = Runner(
                agent=self.agent,
                app_name=self.app_name,
                session_service=self.session_service
            )
            
            # Create message content
            content = types.Content(role='user', parts=[types.Part(text=message)])
            
            # Process message and collect events
            all_events = []
            async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
                print(f"  [Event] Author: {event.author}, Type: {type(event).__name__}, Final: {event.is_final_response()}")
                all_events.append(event)
            
            # Extract final response
            final_response_events = [e for e in all_events if e.is_final_response()]
            final_response_text = ""
            
            for final_response_event in final_response_events:
                if final_response_event and final_response_event.content and final_response_event.content.parts:
                    final_response_text += "".join(part.text for part in final_response_event.content.parts if part.text)
            
            if not final_response_text:
                final_response_text = "Hello! I'm here to help you. How can I assist you today?"
            
            print(f"<<< Agent Response: {final_response_text}")
            
            return {
                "response": final_response_text,
                "user_id": user_id,
                "session_id": session_id,
                "success": True
            }
            
        except Exception as e:
            print(f"❌ Error processing greeting: {e}")
            raise HTTPException(status_code=500, detail=f"Error processing greeting: {str(e)}")

    async def cleanup(self):
        """Cleanup resources"""
        if self.toolset:
            await self.toolset.close()
            print("🧹 Agent service resources cleaned up")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - initialize agent on startup, cleanup on shutdown"""
    global global_agent_service
    
    try:
        # Startup
        print("🚀 Starting Agent Service...")
        
        # Initialize MCP client (you'll need to import and configure this)
        from base_mcp_client import BaseMCPClient
        mcp_client = BaseMCPClient()  # Configure as needed
        
        # Create and initialize agent service
        global_agent_service = AgentService(
            mcp_client=mcp_client,
            model=os.getenv("AGENT_MODEL", "gemini-1.5-flash"),
            name=os.getenv("AGENT_NAME", "GreetingAgent"),
            instruction=os.getenv("AGENT_INSTRUCTION", 
                "You are a friendly greeting agent. Welcome users warmly and help them with their requests. "
                "Be conversational, helpful, and use the available tools when appropriate.")
        )
        
        await global_agent_service.initialize()
        print("✅ Agent Service startup complete")
        
        yield  # Application runs here
        
    except Exception as e:
        print(f"❌ Failed to start Agent Service: {e}")
        raise
    finally:
        # Shutdown
        print("🛑 Shutting down Agent Service...")
        if global_agent_service:
            await global_agent_service.cleanup()
        print("✅ Agent Service shutdown complete")

# Create FastAPI app with lifespan management
app = FastAPI(
    title="Agent Greeting Service",
    description="ADK Agent service with MCP tool integration for greeting users",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    global global_agent_service
    
    return HealthResponse(
        status="healthy" if global_agent_service and global_agent_service.is_initialized else "unhealthy",
        agent_initialized=global_agent_service.is_initialized if global_agent_service else False,
        version="1.0.0"
    )

@app.post("/greet", response_model=GreetingResponse)
async def greet_user(request: GreetingRequest):
    """
    Greet a user using the pre-initialized ADK agent
    
    - **message**: The message to send to the agent
    - **user_id**: Optional user ID for session tracking
    - **session_id**: Optional session ID for conversation continuity
    """
    global global_agent_service
    
    if not global_agent_service:
        raise HTTPException(status_code=503, detail="Agent service not available")
    
    result = await global_agent_service.greet_user(
        message=request.message,
        user_id=request.user_id,
        session_id=request.session_id
    )
    
    return GreetingResponse(**result)

@app.get("/")
async def root():
    """Root endpoint with service information"""
    global global_agent_service
    
    return {
        "service": "Agent Greeting Service",
        "version": "1.0.0",
        "status": "running",
        "agent_initialized": global_agent_service.is_initialized if global_agent_service else False,
        "endpoints": {
            "health": "/health",
            "greet": "/greet",
            "docs": "/docs"
        }
    }

# Legacy function for backward compatibility
class Agent:
    """Legacy Agent class for backward compatibility"""
    def __init__(self, mcp_client: BaseMCPClient, model: str, name: str, instruction: str):
        self.service = AgentService(mcp_client, model, name, instruction)

    async def setup(self):
        await self.service.initialize()

    async def run(self, query: str):
        result = await self.service.greet_user(query)
        print(f"<<< Agent Response: {result['response']}")
        return result

if __name__ == "__main__":
    import uvicorn
    
    # Configuration from environment variables
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    
    print(f"🚀 Starting Agent Service on {host}:{port}")
    
    uvicorn.run(
        "agent_service:app",
        host=host,
        port=port,
        reload=False,  # Set to True for development
        log_level="info"
    )