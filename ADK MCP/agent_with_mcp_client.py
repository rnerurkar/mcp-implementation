import asyncio
from typing import Any
from dotenv import load_dotenv
from google.adk.agents.llm_agent import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseServerParams
from google.genai import types
from rich import print
from contextlib import AsyncExitStack

load_dotenv()

class MCPClient:
    def __init__(self, mcp_url: str, client_id: str, client_secret: str, token_url: str):
        self.mcp_url = mcp_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.toolset = None

    async def authenticate(self):
        # Implement OAuth 2.1 Client Credentials flow here
        # Use httpx or requests-oauthlib to fetch access token
        # Store the token for use in headers
        pass

    async def get_toolset(self):
        # Ensure authentication is done and token is valid
        await self.authenticate()
        # Pass the token in headers or as required by SseServerParams
        self.toolset = MCPToolset(
            connection_params=SseServerParams(
                url=self.mcp_url,
                # Add headers or token as needed
            )
        )
        tools = await self.toolset.get_tools()
        return tools, self.toolset

    async def close(self):
        if self.toolset:
            await self.toolset.close()

class Agent:
    def __init__(self, mcp_client: MCPClient, model: str, name: str, instruction: str):
        self.mcp_client = mcp_client
        self.model = model
        self.name = name
        self.instruction = instruction
        self.agent = None
        self.toolset = None

    async def setup(self):
        tools, toolset = await self.mcp_client.get_toolset()
        self.toolset = toolset
        self.agent = LlmAgent(
            model=self.model,
            name=self.name,
            instruction=self.instruction,
            tools=tools,
        )

    async def run(self, query: str):
        async with AsyncExitStack() as cleanup_stack:
            await self.setup()
            cleanup_stack.push_async_callback(self.toolset.close)
            session_service = InMemorySessionService()
            APP_NAME = "greeting_app"
            USER_ID = "user_1"
            SESSION_ID = "session_001"
            session = await session_service.create_session(
                app_name=APP_NAME,
                user_id=USER_ID,
                session_id=SESSION_ID
            )
            runner = Runner(
                agent=self.agent,
                app_name=APP_NAME,
                session_service=session_service
            )
            content = types.Content(role='user', parts=[types.Part(text=query)])
            all_events = []
            async for event in runner.run_async(user_id=USER_ID, session_id=SESSION_ID, new_message=content):
                print(f"  [Event] Author: {event.author}, Type: {type(event).__name__}, Final: {event.is_final_response()}, Content: {event.content}")
                all_events.append(event)
            final_response_events = [e for e in all_events if e.is_final_response()]
            final_response_text = ""
            for final_response_event in final_response_events:
                if final_response_event and final_response_event.content and final_response_event.content.parts:
                    final_response_text += "".join(part.text for part in final_response_event.content.parts if part.text)
                else:
                    final_response_text = "No final response found or an error occurred."
            print(f"<<< Agent Response: {final_response_text}")

if __name__ == "__main__":
    # Example usage
    mcp_client = MCPClient(
        mcp_url="http://localhost:8000/mcp-server/mcp",
        client_id="YOUR_CLIENT_ID",
        client_secret="YOUR_CLIENT_SECRET",
        token_url="YOUR_TOKEN_URL"
    )
    agent = Agent(
        mcp_client=mcp_client,
        model="gemini-2.0-flash",
        name="greeter",
        instruction="You are a greeting agent"
    )
    asyncio.run(agent.run("I am Rajesh Nerurkar, an AI Engineer. Can you greet me?"))