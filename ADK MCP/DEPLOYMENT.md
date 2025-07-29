# MCP Implementation Deployment Architecture

## Service Deployment Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Google Cloud Run                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐     ┌─────────────────────┐           │
│  │   Agent Service     │     │    MCP Server       │           │
│  │                     │     │                     │           │
│  │ • FastAPI App       │◄────┤ • Tool Provider     │           │
│  │ • Port: 8080        │     │ • Port: 8000        │           │
│  │ • /greet endpoint   │     │ • /mcp-server/*     │           │
│  │ • Session mgmt      │     │ • /invoke endpoint  │           │
│  │ • Pre-init agents   │     │ • Security controls │           │
│  │                     │     │ • OAuth 2.1 auth   │           │
│  └─────────────────────┘     └─────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Commands

### Agent Service
```bash
# Build and deploy Agent Service
./deploy_agent.sh your-project-id us-central1

# Test Agent Service
python test_agentservice.py
```

### MCP Server
```bash
# Build and deploy MCP Server
./deploy_mcpserver.sh your-project-id us-central1

# Test MCP Server
python test_mcpserver.py
```

## Service URLs After Deployment

- **Agent Service**: `https://agent-greeting-service-[hash]-uc.a.run.app`
  - Health: `GET /health`
  - Greet: `POST /greet`
  - Docs: `GET /docs`

- **MCP Server**: `https://mcp-server-service-[hash]-uc.a.run.app`
  - Health: `GET /health`
  - MCP Health: `GET /mcp-server/health`
  - Tool Invoke: `POST /invoke`
  - MCP Endpoint: `GET /mcp-server/*`

## Configuration

Update Agent Service to connect to deployed MCP Server:
```env
MCP_URL=https://mcp-server-service-[hash]-uc.a.run.app/mcp-server
```

## Security

Both services support:
- Azure AD authentication
- Google Cloud KMS encryption
- OPA policy enforcement
- Input sanitization
- Secure credential management
