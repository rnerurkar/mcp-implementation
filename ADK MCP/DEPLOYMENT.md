# MCP Zero-Trust Security Architecture Deployment Guide

## Service Deployment Overview with Zero-Trust Security

```
┌────────────────────────────────────────────────────────────────┐
│                     Google Cloud Run                           │
│              🔒 Zero-Trust Security Architecture 🔒           │
├────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐     ┌─────────────────────┐           │
│  │   Agent Service     │     │    MCP Server       │           │
│  │                     │     │                     │           │
│  │ • FastAPI App       │◄────┤ • Tool Provider     │           │
│  │ • Port: 8080        │     │ • Port: 8000        │           │
│  │ • /greet endpoint   │     │ • /mcp-server/*     │           │
│  │ • Session mgmt      │     │ • /invoke endpoint  │           │
│  │ • Pre-init agents   │     │ • 12 Security Ctrls │           │
│  │ • Security Pipeline │     │ • Zero-Trust Auth   │           │
│  └─────────────────────┘     └─────────────────────┘           │
│                                                                │
│  🔒 Zero-Trust Security Controls (12 Total):                   
│  ├─ Core Controls: Input/Context/Auth/Schema/Creds/Policy      │
│  └─ Advanced: Installer/Server/Remote/Tool/Semantic            │
└────────────────────────────────────────────────────────────────┘
```

## Zero-Trust Security Configuration

Before deployment, ensure all security controls are properly configured:

### Required Environment Variables
```bash
# Core security configuration
SECURITY_LEVEL=zero-trust
CLOUD_RUN_AUDIENCE=your-service-audience
GCP_PROJECT=your-project-id

# Zero-trust specific configuration
TRUSTED_REGISTRIES=https://registry.npmjs.org,https://pypi.org,https://github.com
INSTALLER_SIGNATURE_KEYS={"npm":"key1","pypi":"key2"}
REGISTRY_BACKEND=memory
TRUSTED_CA_CERTS=["ca-cert-1","ca-cert-2"]
DEFAULT_TOOL_POLICY=deny
SEMANTIC_MODELS={"model1":"config1"}
```

## Deployment Commands

### Agent Service
```bash
# Build and deploy Agent Service
./deploy_agent.sh your-project-id us-central1

# Alternative: PowerShell deployment
.\deploy_agent.ps1 your-project-id us-central1

# Test Agent Service
python test_agentservice.py
```

### MCP Server
```bash
# Build and deploy MCP Server
./deploy_mcpserver.sh your-project-id us-central1

# Alternative: PowerShell deployment
.\deploy_mcpserver.ps1 your-project-id us-central1

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
- Google Cloud Run service-to-service authentication with IAM roles and ID tokens
- Google Cloud KMS encryption
- OPA policy enforcement
- Input sanitization
- Secure credential management
