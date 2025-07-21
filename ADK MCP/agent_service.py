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
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.mcp_client_url}/get_toolset",
                json={
                    "mcp_url": self.mcp_url,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "token_url": self.token_url
                }
            )
            resp.raise_for_status()
            return resp.json()["tools"]
    
    async def setup(self):
        tools = await self.get_tools_from_mcp_client()
        # Here, you would need to reconstruct the actual tool objects if needed.
        # For demonstration, we'll assume tools is a list of tool names.
        # In a real implementation, you may need to fetch tool metadata or instantiate tool objects.
        self.agent = LlmAgent(
            model=self.model,
            name=self.name,
            instruction=self.instruction,
            tools=tools,  # This should be a list of tool objects, not just names, in real code
        )

    async def run(self, query: str):
        async with AsyncExitStack() as cleanup_stack:
            await self.setup()
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
            return {"response": final_response_text}


class AgentQuery(BaseModel):
    query: str

@app.post("/run_agent")
async def run_agent(query: AgentQuery):
    agent = Agent()
    return await agent.run(query.query)

