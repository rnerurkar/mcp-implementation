import unittest
from fastapi.testclient import TestClient
from mcp_server_service import app

class TestMCPServer(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_openapi(self):
        # Test OpenAPI endpoint for tool discovery
        response = self.client.get("/mcp-server/openapi.json")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Check if the OpenAPI spec contains the expected tool paths
        self.assertIn("paths", data)
        # Check if the hello tool is registered
        self.assertIn("/mcp-server/tools/hello/invoke", data["paths"])

    def test_hello_tool(self):
        # Test the hello tool invocation
        response = self.client.post(
            "/mcp-server/tools/hello/invoke",
            json={"name": "Rajesh"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # The response structure may depend on FastMCP, adjust as needed
        self.assertIn("result", data)
        self.assertEqual(data["result"], "Hello, Rajesh!")

if __name__ == "__main__":
    unittest.main()