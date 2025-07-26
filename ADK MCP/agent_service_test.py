import asyncio
from base_mcp_client import BaseMCPClient
from agent_service import Agent


def test_agent():
    """Test function for the Agent class"""
    # Example usage
    mcp_client = BaseMCPClient(
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


if __name__ == "__main__":
    test_agent()
