import os
from pydantic import BaseModel
import httpx
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from rich import print
from contextlib import AsyncExitStack
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams

load_dotenv()
app = FastAPI()

class Agent:
    def __init__(self):
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self.scope = os.getenv("AZURE_SCOPE")
        self.token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        self.mcp_client_url = os.getenv("MCP_CLIENT_URL")
        self.mcp_url = os.getenv("MCP_SERVER_URL")
        self.model = os.getenv("AGENT_MODEL", "gemini-2.0-flash")
        self.name = os.getenv("AGENT_NAME", "greeter")
        self.instruction = os.getenv("AGENT_INSTRUCTION", "You are a greeting agent")
        self.agent = None
        self.toolset = None
    async def get_azure_ad_token(self):
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.token_url, data=data)
            resp.raise_for_status()
            return resp.json()["access_token"]

    async def get_tools_from_mcp_client(self):
        access_token = await self.get_azure_ad_token()
        # Instantiate the toolset locally for later cleanup
        self.toolset = MCPToolset(
            connection_params=SseServerParams(
                url=self.mcp_url,
                # Add headers or token as needed
            )
        )
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.mcp_client_url}/get_toolset",
                headers={"Authorization": f"Bearer {access_token}"},
                json={
                    "mcp_url": self.mcp_url,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
            )
            resp.raise_for_status()
            tools = resp.json()["tools"]
            return tools, self.toolset

    
    async def setup(self):
        tools, toolset = await self.get_tools_from_mcp_client()
        self.toolset = toolset
        # Here, you would need to reconstruct the actual tool objects if needed.
        # For demonstration, we'll assume tools is a list of tool names.
        # In a real implementation, you may need to fetch tool metadata or instantiate tool objects.
        """
        Creates an ADK Agent equipped with tools from the MCP Server.
        It  initializes an LlmAgent with a specified model, name, instruction,
        and the fetched tools.
        """
        self.agent = LlmAgent(
            model=self.model,
            name=self.name,
            instruction=self.instruction,
            tools=tools,  # This should be a list of tool objects, not just names, in real code
        )

    async def run(self, query: str):
        """
        Main asynchronous function to run the agent with a given query.
        It sets up the agent, session, and runner, then processes the query
        and prints the agent's final response. It ensures that toolset.close() is called 
        when exiting the main function, preventing resource leaks. 
        """
        async with AsyncExitStack() as cleanup_stack:
            # Ensure the agent is set up with tools
            await self.setup()
            # Register cleanup for the toolset to close it properly
            cleanup_stack.push_async_callback(self.toolset.close)
            # Initialize an in-memory session service for managing conversation context
            session_service = InMemorySessionService()
            # Define constants for identifying the interaction context
            # APP_NAME identifies the application, USER_ID identifies the user,
            # and SESSION_ID identifies a specific conversation session.
            # Using a fixed SESSION_ID here simplifies the example but in a real application, 
            # it would typically be dynamically generated.
            APP_NAME = "greeting_app"
            USER_ID = "user_1"
            SESSION_ID = "session_001"
            # Create the specific session where the conversation will happen
            session = await session_service.create_session(
                app_name=APP_NAME,
                user_id=USER_ID,
                session_id=SESSION_ID
            )
            # Initialize the Runner to execute the agent. The Runner is responsible for 
            # orchestrating the agent's execution, managing sessions, and handling the flow of messages.
            runner = Runner(
                agent=self.agent,
                app_name=APP_NAME,
                session_service=session_service
            )
            # Creates a Content object representing the user's input message.
            # ADK uses types.Content to encapsulate messages, including their 
            # role (e.g., 'user', 'agent') and parts (e.g., text, tool calls).
            content = types.Content(role='user', parts=[types.Part(text=query)])
            # Store all events from the agent's run
            all_events = []
            # Asynchronously run the agent with the new message and iterate through events.
            # The loop prints each event, showing its author, type, whether it’s a final response, and its content.
            # All events are collected in the all_events list.
            async for event in runner.run_async(user_id=USER_ID, session_id=SESSION_ID, new_message=content):
                print(f"  [Event] Author: {event.author}, Type: {type(event).__name__}, Final: {event.is_final_response()}, Content: {event.content}")
                all_events.append(event)
            # After the async for loop completes, the code iterates through all_events to 
            # find events marked as is_final_response(). It then extracts and concatenates 
            # the text from these final response events.
            final_response_events = [e for e in all_events if e.is_final_response()]
            final_response_text = ""
            for final_response_event in final_response_events:
                if final_response_event and final_response_event.content and final_response_event.content.parts:
                    # Concatenate text from all parts of the final response
                    final_response_text += "".join(part.text for part in final_response_event.content.parts if part.text)
                else:
                    final_response_text = "No final response found or an error occurred."
            # Print the final response text from the agent
            return {"response": final_response_text}


class AgentQuery(BaseModel):
    query: str

@app.post("/run_agent")
async def run_agent(query: AgentQuery):
    #
    agent = Agent()
    # This block ensures that the agent is executed when the API /run_agent is invoked from a consuming application.
    return await agent.run(query.query)

