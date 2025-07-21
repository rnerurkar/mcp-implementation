from fastapi.testclient import TestClient
from agent_service import app

client = TestClient(app)

def test_run_agent():
    response = client.post("/run_agent", json={"query": "Hello, Agent!"})
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    print(data["response"])

if __name__ == "__main__":
    test_run_agent()