"""
Test script for the Agent Greeting Service
"""

import asyncio
import json
import os
import requests
from typing import Dict, Any

class AgentServiceTester:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
    
    def test_health_check(self) -> bool:
        """Test the health check endpoint"""
        try:
            response = requests.get(f"{self.base_url}/health")
            response.raise_for_status()
            data = response.json()
            
            print(f"✅ Health Check: {data}")
            return data.get('agent_initialized', False)
        except Exception as e:
            print(f"❌ Health Check Failed: {e}")
            return False
    
    def test_greeting(self, message: str, user_id: str = None, session_id: str = None) -> Dict[str, Any]:
        """Test the greeting endpoint"""
        try:
            payload = {"message": message}
            if user_id:
                payload["user_id"] = user_id
            if session_id:
                payload["session_id"] = session_id
            
            response = requests.post(
                f"{self.base_url}/greet",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            data = response.json()
            
            print(f"✅ Greeting Response: {data}")
            return data
        except Exception as e:
            print(f"❌ Greeting Test Failed: {e}")
            return {}
    
    def test_conversation(self) -> bool:
        """Test a multi-turn conversation"""
        try:
            session_id = "test_conversation_001"
            user_id = "test_user"
            
            # First message
            response1 = self.test_greeting(
                "Hello, I'm new here. Can you help me?",
                user_id=user_id,
                session_id=session_id
            )
            
            # Second message in same session
            response2 = self.test_greeting(
                "What can you do for me?",
                user_id=user_id,
                session_id=session_id
            )
            
            return bool(response1 and response2)
        except Exception as e:
            print(f"❌ Conversation Test Failed: {e}")
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("🧪 Testing Agent Greeting Service")
        print("=" * 50)
        
        # Test 1: Health Check
        print("\n1. Testing Health Check...")
        health_ok = self.test_health_check()
        
        if not health_ok:
            print("❌ Service not ready, skipping other tests")
            return False
        
        # Test 2: Simple Greeting
        print("\n2. Testing Simple Greeting...")
        greeting_response = self.test_greeting("Hello, how are you today?")
        
        # Test 3: Greeting with IDs
        print("\n3. Testing Greeting with User/Session IDs...")
        id_response = self.test_greeting(
            "Hi there!",
            user_id="test_user_123",
            session_id="test_session_456"
        )
        
        # Test 4: Conversation
        print("\n4. Testing Multi-turn Conversation...")
        conversation_ok = self.test_conversation()
        
        # Summary
        print("\n" + "=" * 50)
        print("📊 Test Summary:")
        print(f"Health Check: {'✅' if health_ok else '❌'}")
        print(f"Simple Greeting: {'✅' if greeting_response else '❌'}")
        print(f"Greeting with IDs: {'✅' if id_response else '❌'}")
        print(f"Conversation: {'✅' if conversation_ok else '❌'}")
        
        all_passed = all([health_ok, greeting_response, id_response, conversation_ok])
        print(f"\nOverall: {'🎉 ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
        
        return all_passed

def main():
    """Main test function"""
    # Get service URL from environment or use default
    service_url = os.getenv("AGENT_SERVICE_URL", "http://localhost:8080")
    
    tester = AgentServiceTester(service_url)
    success = tester.run_all_tests()
    
    if success:
        print("\n🎯 Service is working correctly!")
        print(f"🌐 Try the interactive docs at: {service_url}/docs")
    else:
        print("\n⚠️ Some tests failed. Check the service logs.")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
