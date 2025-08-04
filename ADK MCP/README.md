# Model Context Protocol (MCP) Implementation with Google ADK

A comprehensive implementation of the Model Context Protocol (MCP) with Google ADK integration, featuring secure agent services, FastAPI endpoints, and Cloud Run deployment capabilities.

## 🎯 **Overview**

This project implements a complete MCP workflow that enables:
- **Dynamic Tool Discovery**: Agents can discover and use tools from MCP servers
- **Secure Communication**: OAuth 2.1, Azure AD integration, and OPA policy enforcement
- **Production Deployment**: FastAPI service ready for Google Cloud Run
- **Agent Orchestration**: Pre-initialized agents with session management
- **Security Controls**: Input sanitization, context security, and credential management

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │    │   Agent Service  │    │   MCP Server    │
│  (ADK Agent)    │◄──►│   (FastAPI)      │◄──►│  (Tool Provider)│
│   Port: 8080    │    │   Port: 8080     │    │   Port: 8000    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Google ADK      │    │ Cloud Run        │    │ Security Layer  │
│ (LLM + Tools)   │    │ (Scalable Host)  │    │ (OPA + Auth)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **Dual-Service Architecture**

This implementation supports two separate deployments:

1. **Agent Service** (`agent_service.py` on port 8080):
   - FastAPI service with pre-initialized ADK agents
   - Provides `/greet` endpoint for user interactions
   - Consumes tools from MCP Server
   - Handles session management and user conversations

2. **MCP Server** (`mcp_server_service.py` on port 8000):
   - Secure tool provider with FastMCP integration
   - Exposes tools via `/mcp-server` endpoint
   - Implements security controls and policy enforcement
   - Provides `/invoke` endpoint for direct tool execution

## 📁 **Project Structure**

```
ADK MCP/
├── Core Components
│   ├── agent_service.py           # FastAPI service with pre-initialized agents
│   ├── base_mcp_client.py         # MCP client base class for tool discovery
│   ├── base_mcp_server.py         # Secure MCP server foundation
│   └── mcp_server_service.py      # Concrete MCP server implementation
│
├── Security & Controls
│   ├── mcp_security_controls.py   # Comprehensive security framework
│   ├── start_server.py           # Server initialization with security
│   └── .env.example              # Environment configuration template
│
├── Testing & Validation
│   ├── agent_service_test.py      # Agent service unit tests
│   ├── mcp_server_test.py         # MCP server integration tests
│   ├── test_agentservice.py       # Agent Service deployment testing
│   ├── test_mcpserver.py          # MCP Server deployment testing
│   └── test_import.py             # Package import validation
│
├── Deployment Infrastructure
│   ├── Dockerfile.agentservice   # Agent Service container build
│   ├── Dockerfile.mcpserver      # MCP Server container build
│   ├── cloudrun-agentservice.yaml # Agent Service Cloud Run config
│   ├── cloudrun-mcpserver.yaml   # MCP Server Cloud Run config
│   ├── deploy_agent.sh           # Agent Service deployment script
│   ├── deploy_agent.ps1          # Agent Service deployment (PowerShell)
│   ├── deploy_mcpserver.sh       # MCP Server deployment script
│   ├── deploy_mcpserver.ps1      # MCP Server deployment (PowerShell)
│   └── requirements.txt          # Complete dependency list
│
└── Documentation
    ├── README.md                 # This comprehensive guide
    └── .env                      # Environment configuration (local)
```

## 🚀 **Core Features**

### **1. Agent Service (FastAPI)**
- ✅ **Pre-initialized Agents**: Load once at startup for optimal performance
- ✅ **Session Management**: Track users and conversations across requests
- ✅ **Tool Integration**: Dynamic discovery and execution of MCP tools
- ✅ **Health Monitoring**: Built-in health checks for Cloud Run
- ✅ **API Documentation**: Automatic OpenAPI docs at `/docs`

### **2. MCP Client**
- ✅ **OAuth 2.1 Authentication**: Secure client credentials flow
- ✅ **Tool Discovery**: Automatic detection of available tools
- ✅ **Connection Management**: Persistent connections with reconnection logic
- ✅ **Error Handling**: Robust error recovery and logging

### **3. MCP Server**
- ✅ **Security Pipeline**: Input sanitization, validation, and authorization
- ✅ **Policy Enforcement**: OPA (Open Policy Agent) integration
- ✅ **Credential Management**: Google Cloud Secret Manager integration
- ✅ **Context Security**: Encryption and secure context handling

### **4. Security Framework**
- ✅ **Input Sanitization**: XSS, injection, and malformed input protection
- ✅ **Azure AD Integration**: Token validation and scope enforcement
- ✅ **Schema Validation**: JSON schema validation for all inputs
- ✅ **Context Encryption**: KMS-based encryption for sensitive data

## 🛠️ **Setup and Installation**

### **Prerequisites**
- Python 3.11+
- Google Cloud SDK (for deployment)
- Docker (for containerization)
- Azure AD app registration (for authentication)

### **1. Local Development Setup**

```bash
# Clone and navigate to the project
cd "c:\Users\rneru\OneDrive\MCP\MCP Server\ADK MCP"

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration values
```

### **2. Environment Configuration**

Create a `.env` file with the following variables:

```env
# Service Configuration
HOST=0.0.0.0
PORT=8080
AGENT_MODEL=gemini-1.5-flash
AGENT_NAME=MCPAgent

# Google Cloud Configuration
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=path/to/service-account.json

# Azure AD Configuration
AZURE_AUDIENCE=your-app-audience
AZURE_ISSUER=https://login.microsoftonline.com/your-tenant-id/v2.0
AZURE_SCOPES=api://your-app-id/.default

# MCP Configuration
MCP_URL=http://localhost:8000
MCP_CLIENT_ID=your-client-id
MCP_CLIENT_SECRET=your-client-secret
MCP_TOKEN_URL=https://login.microsoftonline.com/your-tenant-id/oauth2/v2.0/token

# Security Configuration
OPA_URL=http://localhost:8181
KMS_KEY_PATH=projects/your-project/locations/global/keyRings/your-ring/cryptoKeys/your-key
SECURITY_LEVEL=standard
```

### **3. Running the Services**

#### **Start MCP Server**
```bash
python start_server.py
```

#### **Start Agent Service (FastAPI)**
```bash
python agent_service.py
```

#### **Test the Implementation**
```bash
python test_agentservice.py
```

## 🌐 **API Endpoints**

### **Health Check**
```http
GET /health
```
**Response:**
```json
{
  "status": "healthy",
  "agent_initialized": true,
  "tools_available": 5,
  "version": "1.0.0"
}
```

### **Agent Greeting**
```http
POST /greet
Content-Type: application/json

{
  "message": "Hello, I need help with data analysis",
  "user_id": "user123",
  "session_id": "session456"
}
```
**Response:**
```json
{
  "response": "Hello! I can help you with data analysis. I have access to several tools including data processing, visualization, and statistical analysis capabilities. What specific task would you like assistance with?",
  "user_id": "user123",
  "session_id": "session456",
  "tools_used": ["data_analyzer", "visualization_tool"],
  "success": true
}
```

### **Interactive API Documentation**
- **Swagger UI**: `http://localhost:8080/docs`
- **ReDoc**: `http://localhost:8080/redoc`
- **OpenAPI Schema**: `http://localhost:8080/openapi.json`

## 🧪 **Testing**

### **1. Unit Tests**
```bash
# Test agent service functionality
python agent_service_test.py

# Test MCP server implementation
python mcp_server_test.py

# Test package imports
python test_import.py
```

### **3. Integration Tests**
```bash
# Test Agent Service integration
python test_agentservice.py

# Test MCP Server integration
python test_mcpserver.py

# Test with custom service URLs
AGENT_SERVICE_URL=https://your-agent-service-url.run.app python test_agentservice.py
MCP_SERVER_URL=https://your-mcp-server-url.run.app python test_mcpserver.py
```

### **4. Manual Testing**
```bash
# Test Agent Service endpoints
curl http://localhost:8080/health
curl -X POST "http://localhost:8080/greet" \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, can you help me?", "user_id": "test_user"}'

# Test MCP Server endpoints
curl http://localhost:8000/health
curl http://localhost:8000/mcp-server/health
curl -X POST "http://localhost:8000/invoke" \
  -H "Content-Type: application/json" \
  -d '{"tool": "hello", "parameters": {"name": "TestUser"}}'
```

## ☁️ **Google Cloud Run Deployment Pipeline**

This project implements a comprehensive 4-tier deployment pipeline for production-ready Google Cloud Run services with secure service-to-service authentication.

### **🏗️ Deployment Architecture Overview**

```
┌─────────────────────────────────────────────────────────────┐
│                 Complete Deployment Pipeline                │
├─────────────────────────────────────────────────────────────┤
│ 1. 🐳 Dockerfile.* ──► Build Container Images               │
│ 2. 🚀 deploy_*.sh ──► Deploy Services to Cloud Run         │
│ 3. ⚙️  cloudrun-*.yaml ──► Configure Service Specifications │
│ 4. 🔐 cloud-run-iam-setup.md ──► Configure Authentication  │
└─────────────────────────────────────────────────────────────┘
```

### **📋 Deployment Pipeline Components**

#### **1. 🐳 Container Build Configuration**

| File | Purpose | Key Features |
|------|---------|--------------|
| `Dockerfile.mcpserver` | MCP Server container | Python 3.11, port 8000, health checks, non-root user |
| `Dockerfile.agentservice` | Agent Service container | Python 3.11, port 8080, health checks, optimized layers |

**Container Architecture Flow:**
```
┌─────────────────────┐    ┌──────────────────────┐
│ requirements.txt    │───▶│ Dockerfile.mcpserver │
└─────────────────────┘    └──────────────────────┘
                                      │
                                      ▼
┌─────────────────────┐    ┌──────────────────────┐
│ mcp_server_service  │───▶│ Docker Image Build   │
│ mcp_security_controls│    └──────────────────────┘
│ (Python code)       │                │
└─────────────────────┘                ▼
                           ┌──────────────────────┐
                           │ Google Container     │
                           │ Registry (GCR)       │
                           └──────────────────────┘
```

#### **2. 🚀 Automated Deployment Scripts**

| Script | Platform | Purpose | Automation Level |
|--------|----------|---------|------------------|
| `deploy_mcpserver.sh` | Linux/macOS | Full MCP Server deployment | Complete pipeline |
| `deploy_mcpserver.ps1` | Windows | MCP Server deployment | PowerShell automation |
| `deploy_agent.sh` | Linux/macOS | Agent Service deployment | Streamlined process |
| `deploy_agent.ps1` | Windows | Agent Service deployment | Cross-platform support |

**Deployment Script Workflow:**
```bash
# deploy_mcpserver.sh execution flow:
1. 📋 Configure gcloud project
2. 🔧 Enable Cloud Run & Container Registry APIs  
3. 👤 Create service account with IAM roles
4. 🔨 Build Docker image using Dockerfile.mcpserver
5. 📤 Push image to Google Container Registry
6. 📝 Template cloudrun-mcpserver.yaml with PROJECT_ID
7. 🚀 Deploy using: gcloud run services replace
8. ✅ Output service URL and endpoints
```

#### **3. ⚙️ Cloud Run Service Configurations**

| YAML File | Service | Configuration Focus |
|-----------|---------|-------------------|
| `cloudrun-mcpserver.yaml` | MCP Server | Security, scaling, health probes |
| `cloudrun-agentservice.yaml` | Agent Service | Performance, AI model settings |

**YAML Configuration Features:**

**MCP Server (cloudrun-mcpserver.yaml):**
```yaml
# Production-ready configuration
annotations:
  run.googleapis.com/min-scale: "1"        # Keep warm
  run.googleapis.com/max-scale: "20"       # Scale limit
  run.googleapis.com/memory: "2Gi"         # Resource allocation
  run.googleapis.com/execution-environment: gen2

# Security settings
serviceAccountName: mcp-server-sa@PROJECT_ID.iam.gserviceaccount.com
env:
- name: EXPECTED_AUDIENCE
  value: "https://mcp-server-service-xyz.run.app"
- name: SECURITY_LEVEL 
  value: "high"

# Health monitoring
startupProbe:
  httpGet:
    path: /mcp-server/health
    port: 8000
```

**Agent Service (cloudrun-agentservice.yaml):**
```yaml
# AI-optimized configuration  
annotations:
  run.googleapis.com/cpu-throttling: "false"  # No CPU throttling
  run.googleapis.com/startup-cpu-boost: "true" # Faster startup

env:
- name: AGENT_MODEL
  value: "gemini-1.5-flash"
- name: AGENT_INSTRUCTION
  value: "You are a friendly greeting agent..."

# Health monitoring
startupProbe:
  httpGet:
    path: /health
    port: 8080
```

#### **4. 🔐 IAM Security Configuration**

**`cloud-run-iam-setup.md`** provides the **critical security layer** that other files don't address:

**Security Configuration Flow:**
```
┌──────────────────────┐    ┌─────────────────────┐
│ Service Accounts     │───▶│ IAM Role Assignment │
│ Created              │    │ & Permissions       │
└──────────────────────┘    └─────────────────────┘
          │                            │
          ▼                            ▼
┌──────────────────────┐    ┌─────────────────────┐
│ ID Token Generation  │◄──▶│ Service-to-Service  │
│ Authentication       │    │ Authorization       │
└──────────────────────┘    └─────────────────────┘
```

**Essential IAM Commands:**
```bash
# 1. Create service accounts
gcloud iam service-accounts create mcp-client-sa
gcloud iam service-accounts create mcp-server-sa

# 2. Grant ID token creation permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:mcp-client-sa@PROJECT.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# 3. Configure service-to-service access
gcloud run services add-iam-policy-binding mcp-server-service \
    --member="serviceAccount:mcp-client-sa@PROJECT.iam.gserviceaccount.com" \
    --role="roles/run.invoker" \
    --region=$REGION
```

### **🔗 File Relationships and Data Flow**

```
requirements.txt
    │
    ▼
Dockerfile.mcpserver ──► Docker Image ──► Container Registry
    │                                            │
    ▼                                            ▼
deploy_mcpserver.sh ────────────────────► gcloud run deploy
    │                                            │
    ▼                                            ▼
cloudrun-mcpserver.yaml ─────────────────► Cloud Run Service
    │                                            │
    ▼                                            ▼
cloud-run-iam-setup.md ──► IAM Configuration ──► Secure Authentication
```

### **🚀 Production Deployment Workflow**

#### **Step 1: Prerequisites Setup**
```bash
# Install required tools
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
docker --version

# Set environment variables
export PROJECT_ID="your-project-id"
export REGION="us-central1"
```

#### **Step 2: IAM Security Configuration (CRITICAL FIRST STEP)**
```bash
# Follow commands in cloud-run-iam-setup.md
# This configures service accounts and permissions
source cloud-run-iam-setup.md
```

#### **Step 3: Deploy MCP Server**
```bash
# Linux/macOS
chmod +x deploy_mcpserver.sh
./deploy_mcpserver.sh $PROJECT_ID $REGION

# Windows PowerShell
.\deploy_mcpserver.ps1 $PROJECT_ID $REGION
```

#### **Step 4: Deploy Agent Service**
```bash
# Linux/macOS  
chmod +x deploy_agent.sh
./deploy_agent.sh $PROJECT_ID $REGION

# Windows PowerShell
.\deploy_agent.ps1 $PROJECT_ID $REGION
```

#### **Step 5: Verify Deployment**
```bash
# Test authentication flow
curl -H "Authorization: Bearer $(gcloud auth print-identity-token --audiences=$SERVER_URL)" \
     "$SERVER_URL/mcp-server/health"

# Test agent service
curl -X POST "$AGENT_URL/greet" \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello!"}'
```

### **📊 Deployment Pipeline Benefits**

| Component | Benefit | Production Impact |
|-----------|---------|------------------|
| **Dockerfiles** | Consistent environments | Eliminates "works on my machine" |
| **Deploy scripts** | Automated deployment | Reduces human error, faster releases |
| **YAML configs** | Infrastructure as code | Version-controlled infrastructure |
| **IAM setup** | Security by design | Zero-trust architecture |

### **🔧 Environment-Specific Configurations**

#### **Development**
```bash
# Local development without IAM complexity
docker build -f Dockerfile.mcpserver -t mcp-server .
docker run -p 8000:8000 mcp-server
```

#### **Staging**
```bash
# Deploy with reduced resources
./deploy_mcpserver.sh staging-project us-central1
# Modify YAML: min-scale: 0, max-scale: 5
```

#### **Production**
```bash
# Full security and scaling configuration
./deploy_mcpserver.sh production-project us-central1
# Use all security features from cloud-run-iam-setup.md
```

### **🚨 Critical Security Notes**

**⚠️ Without `cloud-run-iam-setup.md`:**
```
❌ Services deploy but can't authenticate with each other
❌ ID token validation fails  
❌ No secure service-to-service communication
❌ Potential security vulnerabilities
```

**✅ With complete pipeline:**
```
✅ Proper service account permissions
✅ ID token-based authentication working
✅ Secure service-to-service communication  
✅ Production-ready security configuration
✅ Monitoring and troubleshooting capabilities
```

### **📈 Scaling and Performance Optimizations**

The YAML configurations include production optimizations:

```yaml
# High-performance settings
run.googleapis.com/cpu: "2"                    # Dedicated CPU
run.googleapis.com/memory: "4Gi"               # Adequate memory  
run.googleapis.com/min-scale: "1"              # Reduce cold starts
run.googleapis.com/startup-cpu-boost: "true"   # Faster initialization
run.googleapis.com/execution-environment: gen2 # Latest runtime
```

## 🔒 **Security Features**

### **1. Input Sanitization**
- XSS protection and HTML encoding
- SQL injection prevention
- Command injection blocking
- File path traversal protection

### **2. Authentication & Authorization**
- OAuth 2.1 client credentials flow
- Azure AD token validation
- Scope-based access control
- JWT token verification

### **3. Policy Enforcement**
- Open Policy Agent (OPA) integration
- Dynamic policy evaluation
- Context-aware security rules
- Audit logging and compliance

### **4. Data Protection**
- Google Cloud KMS encryption
- Secure credential management
- Context data sanitization
- PII detection and masking

## 📊 **Monitoring and Observability**

### **Health Checks**
The service includes comprehensive health monitoring:
- **Startup Probe**: Ensures agent initialization before traffic
- **Liveness Probe**: Monitors service health during operation
- **Readiness Probe**: Verifies service readiness for requests

### **Logging**
Structured logging throughout the application:
```python
print(f"🚀 Initializing MCP Agent Service: {agent_name}")
print(f"🔧 Discovered {len(tools)} tools from MCP server")
print(f"✅ Agent Service ready with session management")
```

### **Metrics**
Monitor these key metrics in Cloud Run:
- **Request Count**: API call volume
- **Response Time**: End-to-end latency
- **Error Rate**: Failed request percentage
- **Tool Usage**: MCP tool execution frequency
- **Security Events**: Authentication and authorization events

## 🔧 **Configuration Options**

### **Agent Customization**
```python
# Modify agent behavior in agent_service.py
global_agent_service = AgentService(
    mcp_client=mcp_client,
    model="gemini-1.5-pro",  # Use different model
    name="CustomMCPAgent",
    instruction="You are a specialized agent with access to MCP tools..."
)
```

### **Security Profiles**
```python
# Adjust security levels in configuration
security_config = {
    "input_sanitizer_profile": "strict",  # default, strict, permissive
    "security_level": "high",             # standard, high, maximum
    "context_encryption": True,
    "audit_logging": True
}
```

### **Tool Discovery**
```python
# Configure MCP client for different servers
mcp_clients = [
    BaseMCPClient("http://server1:8000", client_id, secret, token_url),
    BaseMCPClient("http://server2:8000", client_id, secret, token_url),
]
```

## 🐛 **Troubleshooting**

### **Common Issues**

#### **1. Agent Initialization Failures**
```python
# Check MCP client configuration
print("MCP URL:", os.getenv("MCP_URL"))
print("Client ID:", os.getenv("MCP_CLIENT_ID"))

# Verify tool discovery
tools, toolset = await mcp_client.get_toolset()
print(f"Discovered tools: {[tool.name for tool in tools]}")
```

#### **2. Authentication Errors**
```python
# Validate Azure AD configuration
print("Azure Audience:", os.getenv("AZURE_AUDIENCE"))
print("Azure Issuer:", os.getenv("AZURE_ISSUER"))

# Test token validation
token_validator = AzureTokenValidator(
    expected_audience=azure_audience,
    issuer=azure_issuer
)
```

#### **3. Tool Execution Issues**
```python
# Debug tool execution
try:
    result = await agent.run("Test message")
    print(f"Agent response: {result}")
except Exception as e:
    print(f"Tool execution error: {e}")
```

### **Debug Mode**
Enable detailed logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable ADK debug mode
os.environ["ADK_DEBUG"] = "true"
```

## 📈 **Performance Optimization**

### **Agent Pre-initialization**
- **Cold Start Reduction**: Agent loads once at startup
- **Consistent Response Times**: No per-request initialization overhead
- **Resource Efficiency**: Shared agent instance across requests
- **Tool Caching**: MCP tools discovered and cached at startup

### **Scaling Configuration**
```yaml
# cloudrun-agentservice.yaml / cloudrun-mcpserver.yaml optimizations
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/min-scale: "1"      # Keep warm instances
        run.googleapis.com/max-scale: "50"     # Scale limit
        run.googleapis.com/cpu: "2"            # CPU allocation
        run.googleapis.com/memory: "4Gi"       # Memory allocation
        run.googleapis.com/startup-probe-timeout: "120s"
```

## 🔄 **Legacy Compatibility**

The implementation maintains backward compatibility:

```python
# Legacy Agent class usage still works
from agent_service import Agent

agent = Agent(mcp_client, model, name, instruction)
await agent.setup()
result = await agent.run("Hello!")

# New AgentService class provides enhanced features
agent_service = AgentService(mcp_client, model, name, instruction)
await agent_service.initialize()
result = await agent_service.process_request("Hello!", user_id, session_id)
```

## 🚀 **Next Steps and Roadmap**

### **Immediate Enhancements**
1. **Advanced Authentication**: Multi-tenant support with custom claims
2. **Rate Limiting**: Request throttling and quota management
3. **Caching Layer**: Redis integration for response caching
4. **Metrics Dashboard**: Custom monitoring and alerting
5. **WebSocket Support**: Real-time agent interactions

### **Future Development**
1. **Multi-Model Support**: Support for different LLM providers
2. **Tool Marketplace**: Dynamic tool discovery and installation
3. **Workflow Orchestration**: Complex multi-agent workflows
4. **Edge Deployment**: CDN and edge computing integration
5. **Advanced Security**: Zero-trust architecture implementation

## 📚 **Resources and Documentation**

### **External Documentation**
- [Model Context Protocol Specification](https://github.com/modelcontextprotocol/specification)
- [Google ADK Documentation](https://cloud.google.com/adk)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Google Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Azure AD Authentication](https://docs.microsoft.com/en-us/azure/active-directory/)

### **Project Resources**
- **API Documentation**: Available at `/docs` when service is running
- **Test Scripts**: Comprehensive testing in `test_agentservice.py` and `test_mcpserver.py`
- **Configuration Examples**: Template files in `.env.example`
- **Deployment Scripts**: Automated deployment in `deploy_agent.sh` and `deploy_mcpserver.sh`

### **🚀 Deployment Pipeline Quick Reference**

| File Type | Files | Purpose | When to Use |
|-----------|-------|---------|-------------|
| **🐳 Container** | `Dockerfile.mcpserver`<br>`Dockerfile.agentservice` | Build production images | Every deployment |
| **🚀 Deployment** | `deploy_mcpserver.sh/.ps1`<br>`deploy_agent.sh/.ps1` | Automated deployment | CI/CD & manual deploys |
| **⚙️ Configuration** | `cloudrun-mcpserver.yaml`<br>`cloudrun-agentservice.yaml` | Service specifications | Infrastructure changes |
| **🔐 Security** | `cloud-run-iam-setup.md` | IAM & authentication | Initial setup & security reviews |

**Deployment Command Summary:**
```bash
# Complete production deployment (run in order):
1. source cloud-run-iam-setup.md     # Security setup
2. ./deploy_mcpserver.sh PROJECT_ID  # Deploy MCP Server  
3. ./deploy_agent.sh PROJECT_ID       # Deploy Agent Service
4. curl $SERVICE_URL/health          # Verify deployment
```

### **Support and Contributing**
For questions, issues, or contributions:
1. Review the comprehensive test suite for examples
2. Check the deployment scripts for Cloud Run best practices
3. Examine the security controls for compliance requirements
4. Use the health checks for monitoring and alerting

---

**This MCP implementation provides a production-ready foundation for building scalable, secure, and maintainable agent services with dynamic tool discovery and comprehensive security controls.**
