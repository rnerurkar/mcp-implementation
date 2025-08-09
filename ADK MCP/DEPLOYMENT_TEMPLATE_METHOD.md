# MCP Template Method Security Architecture Deployment Guide

## Service Deployment Overview with Template Method Pattern

```
┌─────────────────────────────────────────────────────────────────┐
│                     Google Cloud Run                            │
│            🏛️ Template Method Security Architecture 🏛️           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────     ┌─────────────────────────────  │
│  │   Agent Service     │     │    MCP Server       │           │
│  │ (Template Method)   │     │                     │           │
│  │ • BaseAgentService  │◄────┤ • Tool Provider     │           │
│  │ • EnhancedAgent     │     │ • Port: 8000        │           │
│  │ • Port: 8080        │     │ • /mcp-server/*     │           │
│  │ • /greet endpoint   │     │ • /invoke endpoint  │           │
│  │ • 4 Security Ctrls  │     │ • 12 Security Ctrls │           │
│  │ • Template Pattern  │     │ • Zero-Trust Auth   │           │
│  └─────────────────────────     └─────────────────────────────  │
│                                                                 │
│  🏛️ Template Method Pattern (NEW):                              │
│  ├─ BaseAgentService (Abstract) - Security Framework            │
│  ├─ EnhancedAgentService (Concrete) - Google ADK Integration    │
│  ├─ Security Pipeline: Pre/Post Processing Hooks               │
│  └─ 4 Agent Controls + 12 MCP Controls = 16 Total Controls     │
└─────────────────────────────────────────────────────────────────┘
```

## Template Method Security Configuration

Before deployment, ensure all Template Method security controls are properly configured:

### Required Environment Variables for Template Method

```bash
# Core Agent Configuration (unchanged)
AGENT_MODEL=gemini-1.5-flash
AGENT_NAME=GreetingAgent
AGENT_INSTRUCTION=You are a friendly greeting agent with secure access to tools.
MCP_SERVER_URL=https://your-mcp-server-abc123-uc.a.run.app

# Template Method Security Configuration (NEW - REQUIRED)
ENABLE_PROMPT_PROTECTION=true
ENABLE_CONTEXT_VALIDATION=true
ENABLE_MCP_VERIFICATION=true
ENABLE_RESPONSE_SANITIZATION=true
ENABLE_SECURITY_AUDIT_LOGGING=true

# Security Control Thresholds
MAX_CONTEXT_SIZE=10000
PROMPT_INJECTION_THRESHOLD=0.7
MAX_RESPONSE_SIZE=50000

# MCP Response Security
VERIFY_MCP_SIGNATURES=true
TRUST_UNSIGNED_RESPONSES=false

# Model Armor Integration (optional)
MODEL_ARMOR_API_KEY=your-model-armor-api-key

# LLM Guard Configuration
LLM_MODEL_NAME=gemini-1.5-flash
LLM_GUARD_TIMEOUT=4.0
ENABLE_LLM_INPUT_GUARD=true
ENABLE_LLM_OUTPUT_GUARD=true

# Core Infrastructure (unchanged)
SECURITY_LEVEL=zero-trust
CLOUD_RUN_AUDIENCE=your-service-audience
GCP_PROJECT=your-project-id

# Zero-trust MCP Server Configuration
TRUSTED_REGISTRIES=https://registry.npmjs.org,https://pypi.org,https://github.com
INSTALLER_SIGNATURE_KEYS={"npm":"key1","pypi":"key2"}
REGISTRY_BACKEND=memory
TRUSTED_CA_CERTS=["ca-cert-1","ca-cert-2"]
DEFAULT_TOOL_POLICY=deny
SEMANTIC_MODELS={"model1":"config1"}
```

## Updated Deployment Commands for Template Method

### Agent Service with Template Method Security

```bash
# PowerShell deployment (enhanced for Template Method)
.\deploy_agent.ps1 YOUR_PROJECT_ID us-central1

# Bash deployment (enhanced for Template Method)
./deploy_agent.sh YOUR_PROJECT_ID us-central1
```

## Cloud Run Configuration Updates

### Updated cloudrun-agentservice.yaml

The Cloud Run configuration has been enhanced to support Template Method security:

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: agent-greeting-service
  annotations:
    run.googleapis.com/ingress: all
    run.googleapis.com/execution-environment: gen2
spec:
  template:
    metadata:
      annotations:
        # Enhanced resource allocation for Template Method pattern
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/memory: "2Gi"
        run.googleapis.com/cpu: "1"
        run.googleapis.com/max-scale: "10"
        run.googleapis.com/min-scale: "1"
        run.googleapis.com/startup-cpu-boost: "true"
    spec:
      serviceAccountName: your-service-account@your-project.iam.gserviceaccount.com
      containers:
      - image: gcr.io/YOUR_PROJECT_ID/agent-greeting-service:latest
        ports:
        - containerPort: 8080
        env:
        # Core Agent Configuration
        - name: PORT
          value: "8080"
        - name: AGENT_MODEL
          value: "gemini-1.5-flash"
        - name: AGENT_NAME
          value: "GreetingAgent"
        - name: AGENT_INSTRUCTION
          value: "You are a friendly greeting agent with secure access to tools."
        - name: MCP_SERVER_URL
          value: "https://your-mcp-server-abc123-uc.a.run.app"
        
        # Template Method Security Configuration (NEW)
        - name: ENABLE_PROMPT_PROTECTION
          value: "true"
        - name: ENABLE_CONTEXT_VALIDATION
          value: "true"
        - name: ENABLE_MCP_VERIFICATION
          value: "true"
        - name: ENABLE_RESPONSE_SANITIZATION
          value: "true"
        - name: MAX_CONTEXT_SIZE
          value: "10000"
        - name: PROMPT_INJECTION_THRESHOLD
          value: "0.7"
        - name: VERIFY_MCP_SIGNATURES
          value: "true"
        - name: TRUST_UNSIGNED_RESPONSES
          value: "false"
        
        resources:
          limits:
            memory: "2Gi"
            cpu: "1"
          requests:
            memory: "1Gi"
            cpu: "0.5"
        
        # Enhanced probes for Template Method health checking
        startupProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 6
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60
          periodSeconds: 30
          timeoutSeconds: 5
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
```

## Updated Deployment Scripts

### Enhanced deploy_agent.ps1

The PowerShell deployment script now includes Template Method security configuration:

```powershell
# PowerShell script to deploy Template Method Agent Service to Cloud Run
# Usage: .\deploy_agent.ps1 [PROJECT_ID] [REGION]
param(
    [string]$ProjectId = "your-project-id",
    [string]$Region = "us-central1"
)

# Configuration
$SERVICE_NAME = "agent-greeting-service"
$IMAGE_NAME = "gcr.io/$ProjectId/$SERVICE_NAME"
$DOCKERFILE = "Dockerfile.agentservice"

Write-Host "🏛️ Deploying Template Method Agent Service to Cloud Run" -ForegroundColor Green
Write-Host "Project: $ProjectId"
Write-Host "Region: $Region"
Write-Host "Service: $SERVICE_NAME"
Write-Host "Architecture: Template Method Pattern"
Write-Host "Security: 4 Agent + 12 MCP Controls"
Write-Host "----------------------------------------"

# Ensure gcloud is configured
Write-Host "📋 Checking gcloud configuration..." -ForegroundColor Blue
gcloud config set project $ProjectId

# Enable required APIs
Write-Host "🔧 Enabling required APIs..." -ForegroundColor Blue
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Build and push container image
Write-Host "🔨 Building container image..." -ForegroundColor Blue
docker build -f $DOCKERFILE -t $IMAGE_NAME .

Write-Host "📤 Pushing image to Container Registry..." -ForegroundColor Blue
docker push $IMAGE_NAME

# Deploy to Cloud Run with Template Method configuration
Write-Host "🚀 Deploying Template Method Agent Service to Cloud Run..." -ForegroundColor Blue
gcloud run deploy $SERVICE_NAME `
    --image $IMAGE_NAME `
    --region $Region `
    --platform managed `
    --allow-unauthenticated `
    --memory 2Gi `
    --cpu 1 `
    --min-instances 1 `
    --max-instances 10 `
    --timeout 300 `
    --port 8080 `
    --set-env-vars "AGENT_MODEL=gemini-1.5-flash,AGENT_NAME=GreetingAgent,ENABLE_PROMPT_PROTECTION=true,ENABLE_CONTEXT_VALIDATION=true,ENABLE_MCP_VERIFICATION=true,ENABLE_RESPONSE_SANITIZATION=true,MAX_CONTEXT_SIZE=10000,PROMPT_INJECTION_THRESHOLD=0.7,VERIFY_MCP_SIGNATURES=true,TRUST_UNSIGNED_RESPONSES=false"

# Get service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME --region $Region --format 'value(status.url)'

Write-Host "✅ Template Method Agent Service deployment completed!" -ForegroundColor Green
Write-Host "🏛️ Architecture: Template Method Pattern" -ForegroundColor Cyan
Write-Host "🛡️ Security: 4 Agent Controls Active" -ForegroundColor Cyan
Write-Host "🌐 Service URL: $SERVICE_URL" -ForegroundColor Cyan
Write-Host "💚 Health Check: $SERVICE_URL/health" -ForegroundColor Cyan
Write-Host "💬 Greet Endpoint: $SERVICE_URL/greet" -ForegroundColor Cyan
Write-Host "📊 Security Status: $SERVICE_URL/security-status" -ForegroundColor Cyan
Write-Host "📚 API Docs: $SERVICE_URL/docs" -ForegroundColor Cyan

Write-Host ""
Write-Host "🏛️ Template Method Pattern Features:" -ForegroundColor Yellow
Write-Host "1. BaseAgentService - Abstract security framework"
Write-Host "2. EnhancedAgentService - Concrete Google ADK implementation"
Write-Host "3. Security-Business Logic Separation"
Write-Host "4. Consistent security pipeline across all agent types"

Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Test Template Method deployment: python test_template_method.py"
Write-Host "2. Verify security status: curl $SERVICE_URL/security-status"
Write-Host "3. Test security controls: python test_security_controls.py"
Write-Host "4. Monitor Template Method performance"
Write-Host "5. Consider adding new agent implementations (ChatGPT, Claude)"
```

### Enhanced deploy_agent.sh

The Bash deployment script now includes Template Method security configuration:

```bash
#!/bin/bash
# Deploy Template Method Agent Service to Cloud Run
# Usage: ./deploy_agent.sh [PROJECT_ID] [REGION]
set -e

# Configuration
PROJECT_ID=${1:-"your-project-id"}
REGION=${2:-"us-central1"}
SERVICE_NAME="agent-greeting-service"
IMAGE_NAME="gcr.io/$PROJECT_ID/$SERVICE_NAME"
DOCKERFILE="Dockerfile.agentservice"

echo "🏛️ Deploying Template Method Agent Service to Cloud Run"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Architecture: Template Method Pattern"
echo "Security: 4 Agent + 12 MCP Controls"
echo "----------------------------------------"

# Ensure gcloud is configured
echo "📋 Checking gcloud configuration..."
gcloud config set project $PROJECT_ID

# Build and push container image
echo "🔨 Building container image..."
docker build -f $DOCKERFILE -t $IMAGE_NAME .

echo "📤 Pushing image to Container Registry..."
docker push $IMAGE_NAME

# Deploy to Cloud Run with Template Method configuration
echo "🚀 Deploying Template Method Agent Service to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
    --image $IMAGE_NAME \
    --region $REGION \
    --platform managed \
    --allow-unauthenticated \
    --memory 2Gi \
    --cpu 1 \
    --min-instances 1 \
    --max-instances 10 \
    --timeout 300 \
    --port 8080 \
    --set-env-vars "AGENT_MODEL=gemini-1.5-flash,AGENT_NAME=GreetingAgent,ENABLE_PROMPT_PROTECTION=true,ENABLE_CONTEXT_VALIDATION=true,ENABLE_MCP_VERIFICATION=true,ENABLE_RESPONSE_SANITIZATION=true,MAX_CONTEXT_SIZE=10000,PROMPT_INJECTION_THRESHOLD=0.7,VERIFY_MCP_SIGNATURES=true,TRUST_UNSIGNED_RESPONSES=false"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')

echo "✅ Template Method Agent Service deployment completed!"
echo "🏛️ Architecture: Template Method Pattern"
echo "🛡️ Security: 4 Agent Controls Active"
echo "🌐 Service URL: $SERVICE_URL"
echo "💚 Health Check: $SERVICE_URL/health"
echo "📊 Security Status: $SERVICE_URL/security-status"
echo "📚 API Docs: $SERVICE_URL/docs"
echo "----------------------------------------"

# Test the Template Method service
echo "🧪 Testing Template Method deployment..."
curl -f "$SERVICE_URL/health" && echo "✅ Health check passed"

echo "🏛️ Testing Template Method security status..."
curl -f "$SERVICE_URL/security-status" && echo "✅ Security status check passed"

echo "🎉 Template Method Agent Service is ready!"
echo ""
echo "🏛️ Template Method Pattern Benefits:"
echo "• Security-Business Logic Separation"
echo "• Consistent security across all agent types"
echo "• Easy extension for new agent implementations"
echo "• Independent testing of security and business logic"
echo ""
echo "Example usage:"
echo "curl -X POST \"$SERVICE_URL/greet\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"message\": \"Hello, how are you?\"}'"
```

## Template Method Specific Health Checks

### Enhanced Health Endpoint

The Template Method implementation includes enhanced health checking:

```bash
# Basic health check
curl https://your-service-url/health

# Template Method security status
curl https://your-service-url/security-status

# Expected response for security status:
{
  "security_level": "template_method",
  "base_agent_service": {
    "status": "initialized",
    "security_framework": "active"
  },
  "enhanced_agent_service": {
    "status": "initialized", 
    "google_adk": "connected",
    "mcp_client": "connected"
  },
  "security_controls": {
    "prompt_protection": {"enabled": true, "status": "active"},
    "context_validation": {"enabled": true, "status": "active"},
    "mcp_verification": {"enabled": true, "status": "active"},
    "response_sanitization": {"enabled": true, "status": "active"}
  },
  "template_method": {
    "pattern": "implemented",
    "security_decoupling": "complete",
    "performance_overhead": "~4-6ms"
  }
}
```

## Performance Considerations for Template Method

### Resource Requirements

The Template Method pattern has specific resource requirements:

```yaml
resources:
  limits:
    memory: "2Gi"      # Sufficient for Template Method + Google ADK
    cpu: "1"           # Handles Template Method security overhead
  requests:
    memory: "1Gi"      # Baseline for Template Method initialization
    cpu: "0.5"         # Minimum for Template Method pattern
```

### Performance Metrics

Monitor these Template Method specific metrics:

- **Template Method Overhead**: ~4-6ms per request
- **Security Pipeline**: Pre/post processing latency
- **Agent Initialization**: BaseAgentService + EnhancedAgentService setup
- **Memory Usage**: Template Method pattern memory efficiency

## Testing Template Method Deployment

### Comprehensive Testing

```bash
# Test Template Method pattern functionality
python -c "
import requests
import json

# Test basic health
response = requests.get('https://your-service-url/health')
print(f'Health: {response.status_code}')

# Test Template Method security status
response = requests.get('https://your-service-url/security-status')
security_status = response.json()
print(f'Template Method: {security_status[\"template_method\"][\"pattern\"]}')
print(f'Security Decoupling: {security_status[\"template_method\"][\"security_decoupling\"]}')

# Test Template Method agent functionality
response = requests.post('https://your-service-url/greet', 
    json={'message': 'Test Template Method pattern'})
result = response.json()
print(f'Template Method Response: {result[\"success\"]}')
print(f'Security Validation: {\"security_validation\" in result}')
"
```

## Troubleshooting Template Method Deployment

### Common Issues

1. **Template Method Initialization Failure**
   ```bash
   # Check if BaseAgentService initializes properly
   kubectl logs deployment/agent-greeting-service | grep "BaseAgentService"
   ```

2. **Security Configuration Missing**
   ```bash
   # Verify Template Method security variables
   gcloud run services describe agent-greeting-service --format="export"
   ```

3. **Performance Issues**
   ```bash
   # Monitor Template Method overhead
   curl https://your-service-url/metrics
   ```

### Template Method Specific Logs

Look for these log patterns:

```
[INFO] BaseAgentService initialized with security framework
[INFO] EnhancedAgentService initialized with Google ADK integration
[INFO] Template Method pattern: Security-business logic separation complete
[INFO] Security controls active: 4/4 agent controls
[DEBUG] Template Method security pipeline: Pre-processing (2ms)
[DEBUG] Template Method security pipeline: Post-processing (2ms)
```

## Migration from Legacy Agent Service

### Zero-Downtime Migration

1. **Deploy Template Method service alongside legacy**
2. **Route traffic gradually to Template Method**
3. **Monitor Template Method performance**
4. **Complete migration when confident**

```bash
# Deploy with traffic splitting
gcloud run services update-traffic agent-greeting-service \
    --to-revisions=template-method-revision=50,legacy-revision=50
```

The Template Method pattern provides enterprise-grade security with architectural flexibility, enabling easy extension while maintaining consistent protection across all agent implementations.
