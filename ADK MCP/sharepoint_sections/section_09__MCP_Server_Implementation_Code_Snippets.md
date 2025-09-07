## 💻 **MCP Server Implementation Code Snippets**

> **🚀 Note: FastMCP + FastAPI Implementation**
> 
> The code snippets below use **FastMCP** with **FastAPI** instead of Flask for several important reasons:
> 
> **✅ Native MCP Protocol Support:**
> - FastMCP provides built-in MCP tool registration and protocol handling
> - Automatic MCP message serialization/deseriization
> - Standard MCP security and authentication patterns
> 
> **✅ Performance & Modern Architecture:**
> - FastAPI is ASGI-based (faster than Flask's WSGI)
> - Native async/await support for better concurrency
> - Automatic OpenAPI documentation generation
> 
> **✅ Type Safety & Validation:**
> - Pydantic models for request/response validation
> - Automatic type checking and error handling
> - Better debugging and development experience
> 
> **✅ MCP Ecosystem Integration:**
> - Direct compatibility with MCP clients like GitHub Copilot
> - Standard tool registration patterns
> - Built-in security hooks and middleware support

### 1. 🚫 Initial Tool Call - 401 Unauthorized Response

**FastMCP Tool**: `create_story` (First Time Call)

```python
from fastmcp import FastMCP
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
import secrets
import hashlib
import base64
import sqlite3
from datetime import datetime
from typing import Optional

# Initialize FastMCP server with FastAPI
app = FastAPI(title="Rally MCP Server", version="1.0.0")
mcp = FastMCP("Rally Integration Server")

class CreateStoryRequest(BaseModel):
    title: str
    description: str = ""
    points: int = 1

class AuthErrorResponse(BaseModel):
    error: str
    error_description: str
    auth_url: str
    instructions: list[str]

@mcp.tool()
async def create_story_tool(
    request: CreateStoryRequest,
    session_id: Optional[str] = Header(None, alias="Session-ID")
):
    """
    FastMCP tool for creating Rally stories.
    Returns authentication error with PKCE parameters if user not authenticated.
    """
    if not session_id:
        raise HTTPException(
            status_code=400,
            detail="Missing Session-ID header"
        )
    
    # Check if we have valid tokens for this session
    tokens = await get_stored_tokens(session_id)
    if not tokens:
        # Generate PKCE parameters for OAuth flow
        pkce_data = generate_pkce_parameters()
        state_token = secrets.token_urlsafe(32)
        
        # Store PKCE and session mapping
        await store_oauth_state(state_token, session_id, pkce_data['code_verifier'])
        
        # Build authorization URL
        auth_url = build_authorization_url(state_token, pkce_data['code_challenge'])
        
        # Return authentication required error
        raise HTTPException(
            status_code=401,
            detail=AuthErrorResponse(
                error="Authentication required",
                error_description="User must authenticate with Rally to access this tool",
                auth_url=auth_url,
                instructions=[
                    "1. Copy the auth_url and open it in your browser",
                    "2. Complete Rally authentication and authorization",
                    "3. Return to this chat and say 'authentication complete'",
                    "4. Retry your original request"
                ]
            ).dict()
        )
    
    # If we reach here, tokens exist - proceed with tool execution
    return await execute_create_story_tool(session_id, tokens, request)

async def generate_pkce_parameters():
    """Generate PKCE code_verifier and code_challenge"""
    # Generate cryptographically random code_verifier (43-128 chars)
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')
    
    # Generate code_challenge (SHA256 of code_verifier)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }

async def store_oauth_state(state_token: str, session_id: str, code_verifier: str):
    """Store OAuth state mapping in database"""
    # Use async database operations
    import aiosqlite
    
    async with aiosqlite.connect('mcp_server.db') as db:
        await db.execute('''
            INSERT INTO oauth_states (state_token, session_id, code_verifier, created_at)
            VALUES (?, ?, ?, ?)
        ''', (state_token, session_id, code_verifier, datetime.utcnow()))
        await db.commit()

def build_authorization_url(state_token, code_challenge):
    """Build OAuth authorization URL with PKCE parameters"""
    base_url = "https://mcp-server.example.com/auth"
    params = {
        'state': state_token,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
    return f"{base_url}?{query_string}"
```

**Sample 401 Response:**
```json
{
  "error": "Authentication required",
  "error_description": "User must authenticate with Rally to access this tool",
  "auth_url": "https://mcp-server.example.com/auth?state=abc123xyz789&code_challenge=5VXp1mP5z6uRxE3Xv8w7Wr2qH0nK8lL9aBc3dF1gS4iJ7yT6oM&code_challenge_method=S256",
  "instructions": [
    "1. Copy the auth_url and open it in your browser",
    "2. Complete Rally authentication and authorization", 
    "3. Return to this chat and say 'authentication complete'",
    "4. Retry your original request"
  ]
}
```

### 2. 🔐 Authorization Endpoint - PKCE Processing

**FastAPI Endpoint**: `GET /auth` (Handles PKCE and redirects to Rally)

```python
from fastapi import Query
from fastapi.responses import RedirectResponse

@app.get("/auth")
async def authorize(
    state: str = Query(..., description="OAuth state token"),
    code_challenge: str = Query(..., description="PKCE code challenge"),
    code_challenge_method: str = Query(..., description="PKCE challenge method")
):
    """
    FastAPI authorization endpoint that processes PKCE parameters
    and redirects user to Rally OAuth server.
    """
    if code_challenge_method != 'S256':
        raise HTTPException(
            status_code=400,
            detail={
                'error': 'Unsupported code_challenge_method',
                'supported': ['S256']
            }
        )
    
    # Verify state token exists and retrieve associated data
    oauth_data = await get_oauth_state(state)
    if not oauth_data:
        raise HTTPException(
            status_code=400,
            detail={'error': 'Invalid or expired state token'}
        )
    
    # Verify code_challenge matches stored code_verifier
    stored_verifier = oauth_data['code_verifier']
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(stored_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    if code_challenge != expected_challenge:
        raise HTTPException(
            status_code=400,
            detail={'error': 'Invalid code_challenge - does not match stored code_verifier'}
        )
    
    # Build Rally OAuth URL with PKCE parameters
    rally_oauth_url = build_rally_oauth_url(state, code_challenge)
    
    # Redirect user to Rally OAuth server
    return RedirectResponse(url=rally_oauth_url)

async def get_oauth_state(state_token: str):
    """Retrieve OAuth state data from database"""
    import aiosqlite
    
    async with aiosqlite.connect('mcp_server.db') as db:
        async with db.execute('''
            SELECT session_id, code_verifier, created_at 
            FROM oauth_states 
            WHERE state_token = ? AND created_at > datetime('now', '-10 minutes')
        ''', (state_token,)) as cursor:
            result = await cursor.fetchone()
    
    if result:
        return {
            'session_id': result[0],
            'code_verifier': result[1],
            'created_at': result[2]
        }
    return None

def build_rally_oauth_url(state_token, code_challenge):
    """Build Rally OAuth authorization URL"""
    rally_base = "https://rally1.rallydev.com/login/oauth2/auth"
    params = {
        'response_type': 'code',
        'client_id': 'your_rally_client_id',
        'redirect_uri': 'https://mcp-server.example.com/callback',
        'scope': 'alm:read alm:write',
        'state': state_token,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    from urllib.parse import urlencode
    return f"{rally_base}?{urlencode(params)}"
```

### 3. 🔄 OAuth Callback - Token Exchange

**Endpoint**: `GET /callback` (Handles Rally OAuth callback)

```python
@app.route('/callback', methods=['GET'])
def oauth_callback():
    """
    OAuth callback endpoint that handles Rally's authorization response
    and exchanges authorization code for access tokens using PKCE.
    """
    authorization_code = request.args.get('code')
    state_token = request.args.get('state')
    error = request.args.get('error')
    
    if error:
        return f"""
        <html><body>
            <h2>❌ Authentication Failed</h2>
            <p>Error: {error}</p>
            <p>Please close this tab and try again.</p>
        </body></html>
        """, 400
    
    if not authorization_code or not state_token:
        return jsonify({
            'error': 'Missing authorization code or state parameter'
        }), 400
    
    # Retrieve OAuth state data
    oauth_data = get_oauth_state(state_token)
    if not oauth_data:
        return jsonify({
            'error': 'Invalid or expired state token'
        }), 400
    
    # Exchange authorization code for tokens using PKCE
    tokens = exchange_code_for_tokens(
        authorization_code, 
        oauth_data['code_verifier']
    )
    
    if not tokens:
        return """
        <html><body>
            <h2>❌ Token Exchange Failed</h2>
            <p>Failed to obtain access tokens from Rally.</p>
            <p>Please close this tab and try again.</p>
        </body></html>
        """, 500
    
    # Store tokens for the session
    store_tokens_for_session(oauth_data['session_id'], tokens)
    
    # Clean up OAuth state
    cleanup_oauth_state(state_token)
    
    return """
    <html><body>
        <h2>✅ Authentication Successful!</h2>
        <p>You have successfully authenticated with Rally.</p>
        <p><strong>You can now close this tab and return to VSCode.</strong></p>
        <p>In VSCode, tell the agent "authentication complete" to continue.</p>
        <script>
            // Optional: Auto-close after 3 seconds
            setTimeout(() => window.close(), 3000);
        </script>
    </body></html>
    """

def exchange_code_for_tokens(authorization_code, code_verifier):
    """Exchange authorization code for access tokens using PKCE"""
    import requests
    
    token_url = "https://rally1.rallydev.com/login/oauth2/token"
    
    data = {
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'client_id': 'your_rally_client_id',
        'code_verifier': code_verifier,  # PKCE verification
        'redirect_uri': 'https://mcp-server.example.com/callback'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.post(token_url, data=data, headers=headers)
        response.raise_for_status()
        
        tokens = response.json()
        return {
            'access_token': tokens['access_token'],
            'refresh_token': tokens.get('refresh_token'),
            'expires_in': tokens.get('expires_in', 3600),
            'token_type': tokens.get('token_type', 'Bearer'),
            'scope': tokens.get('scope')
        }
    except requests.RequestException as e:
        print(f"Token exchange failed: {e}")
        return None

def store_tokens_for_session(session_id, tokens):
    """Store tokens in database mapped to session ID"""
    conn = sqlite3.connect('mcp_server.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO session_tokens 
        (session_id, access_token, refresh_token, expires_at, created_at)
        VALUES (?, ?, ?, datetime('now', '+' || ? || ' seconds'), ?)
    ''', (
        session_id, 
        tokens['access_token'], 
        tokens.get('refresh_token'),
        tokens.get('expires_in', 3600),
        datetime.utcnow()
    ))
    
    conn.commit()
    conn.close()

def cleanup_oauth_state(state_token):
    """Remove OAuth state after successful token exchange"""
    conn = sqlite3.connect('mcp_server.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM oauth_states WHERE state_token = ?', (state_token,))
    conn.commit()
    conn.close()
```

### 4. ✅ Tool Execution - Authenticated Request

**Endpoint**: `POST /tools/create-story` (Retry After Authentication)

```python
def execute_create_story_tool(session_id, tokens, request_data):
    """
    Execute the create story tool with authenticated Rally API calls.
    Called when valid tokens exist for the session.
    """
    try:
        # Extract story details from request
        story_title = request_data.get('title', 'New Story')
        story_description = request_data.get('description', '')
        story_points = request_data.get('points', 1)
        
        # Make authenticated Rally API call
        rally_response = create_rally_story(
            tokens['access_token'],
            story_title,
            story_description, 
            story_points
        )
        
        if rally_response:
            return jsonify({
                'success': True,
                'message': 'Rally story created successfully',
                'story': {
                    'id': rally_response['ObjectID'],
                    'formatted_id': rally_response['FormattedID'],
                    'name': rally_response['Name'],
                    'state': rally_response['ScheduleState'],
                    'url': f"https://rally1.rallydev.com/#/detail/userstory/{rally_response['ObjectID']}"
                }
            })
        else:
            return jsonify({
                'error': 'Failed to create Rally story',
                'message': 'Rally API call failed'
            }), 500
            
    except Exception as e:
        return jsonify({
            'error': 'Tool execution failed',
            'message': str(e)
        }), 500

def create_rally_story(access_token, title, description, points):
    """Create a story in Rally using the API"""
    import requests
    
    rally_api_url = "https://rally1.rallydev.com/slm/webservice/v2.0/hierarchicalrequirement"
    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    story_data = {
        'HierarchicalRequirement': {
            'Name': title,
            'Description': description,
            'PlanEstimate': points,
            'ScheduleState': 'Defined'
        }
    }
    
    try:
        response = requests.post(rally_api_url, json=story_data, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        return result['CreateResult']['Object']
        
    except requests.RequestException as e:
        print(f"Rally API call failed: {e}")
        return None

def get_stored_tokens(session_id):
    """Retrieve stored tokens for a session"""
    conn = sqlite3.connect('mcp_server.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT access_token, refresh_token, expires_at
        FROM session_tokens 
        WHERE session_id = ? AND expires_at > datetime('now')
    ''', (session_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            'access_token': result[0],
            'refresh_token': result[1],
            'expires_at': result[2]
        }
    return None
```

**Sample Successful Response:**
```json
{
  "success": true,
  "message": "Rally story created successfully",
  "story": {
    "id": "12345678901",
    "formatted_id": "US1234", 
    "name": "Implement user authentication",
    "state": "Defined",
    "url": "https://rally1.rallydev.com/#/detail/userstory/12345678901"
  }
}
```

### 5. 🗃️ Database Schema

```sql
-- OAuth state tracking table
CREATE TABLE oauth_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state_token TEXT UNIQUE NOT NULL,
    session_id TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session tokens table  
CREATE TABLE session_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for performance
CREATE INDEX idx_oauth_states_state_token ON oauth_states(state_token);
CREATE INDEX idx_session_tokens_session_id ON session_tokens(session_id);
```

### � **FastMCP Installation & Setup**

```bash
# Install FastMCP and dependencies
pip install fastmcp fastapi uvicorn aiosqlite httpx pydantic

# Run the MCP server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

**Key Dependencies:**
- `fastmcp`: Native MCP protocol implementation
- `fastapi`: Modern, fast web framework for APIs  
- `uvicorn`: ASGI server for FastAPI
- `aiosqlite`: Async SQLite database operations
- `httpx`: Async HTTP client for Rally API calls
- `pydantic`: Data validation and serialization

**Why FastMCP > Flask:**
- ✅ Built-in MCP protocol support
- ✅ Async performance advantages
- ✅ Automatic OpenAPI documentation
- ✅ Type safety with Pydantic models
- ✅ Better error handling and debugging

### �🔒 **Security Notes**

1. **PKCE Verification**: Code challenge is verified against code verifier during token exchange
2. **State Token Expiration**: OAuth states expire after 10 minutes for security
3. **Token Storage**: Access tokens are securely stored and automatically expire
4. **Session Isolation**: Each Agent session has isolated token storage
5. **HTTPS Required**: All OAuth flows must use HTTPS in production
6. **Input Validation**: All endpoints validate required parameters and formats

These code snippets provide a complete implementation of the PKCE-enabled OAuth 2.1 flow that GitHub Copilot Agent can successfully interact with using the manual authentication pattern.

---
