# MCP Consolidated Security Architecture - Complete Deployment Guide

## 🎯 Overview

This is the **single source of truth** for deploying the MCP (Model Context Protocol) implementation with consolidated security architecture to Google Cloud Run. This guide covers the complete end-to-end deployment process with 70% reduced code complexity through MCP framework integration.

### Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                     Google Cloud Run                            │
│            🔒 Consolidated Security Architecture 🔒             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐     ┌─────────────────────┐           │
│  │   Agent Service     │     │    MCP Server       │           │
│  │                     │     │                     │           │
│  │ • ConsolidatedSec   │◄────┤ • Tool Provider     │           │
│  │ • Port: 8080        │     │ • Port: 8000        │           │
│  │ • /greet endpoint   │     │ • /mcp-server/*     │           │
│  │ • MCP Integration   │     │ • 12 Security Ctrls │           │
│  └─────────────────────┘     └─────────────────────┘           │
│                                                                │
│  🔒 Security Controls: 4 Agent + 12 MCP Framework              │
│  ⚡ Performance: 8-10ms overhead (70% reduction)               │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Prerequisites

### 1. Required Tools
```bash
# Install Google Cloud SDK
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
docker --version  # Verify Docker is installed
```

### 2. Environment Setup
```bash
# Set core environment variables
export PROJECT_ID="your-project-id"
export REGION="us-central1"
export MCP_CLIENT_SERVICE="agent-greeting-service"
export MCP_SERVER_SERVICE="mcp-server-service"
```

### 3. Enable Required APIs
```bash
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
gcloud services enable iam.googleapis.com
```

## 🔐 Step 1: IAM Security Configuration (CRITICAL)

This step configures service-to-service authentication using ID tokens for zero-trust security.

### Create Service Accounts

```bash
# Create service account for Agent Service (MCP Client)
gcloud iam service-accounts create mcp-client-sa \
    --display-name="MCP Client Service Account" \
    --description="Service account for agent service to authenticate with MCP server"

# Create service account for MCP Server
gcloud iam service-accounts create mcp-server-sa \
    --display-name="MCP Server Service Account" \
    --description="Service account for MCP server to receive authenticated requests"

# Get service account emails
export CLIENT_SA_EMAIL="mcp-client-sa@${PROJECT_ID}.iam.gserviceaccount.com"
export SERVER_SA_EMAIL="mcp-server-sa@${PROJECT_ID}.iam.gserviceaccount.com"
```

### Grant IAM Permissions

```bash
# Allow client to create ID tokens
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator"

# Grant client Workload Identity permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountUser"

# Grant server access to secrets (if using Secret Manager)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVER_SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor"
```

## 🚀 Step 2: Deploy MCP Server

### Build and Deploy MCP Server

```bash
# Linux/macOS deployment
chmod +x deploy_mcpserver.sh
./deploy_mcpserver.sh $PROJECT_ID $REGION

# Windows PowerShell deployment
.\deploy_mcpserver.ps1 $PROJECT_ID $REGION
```

The deployment script automatically:
1. 📋 Configures gcloud project
2. 🔧 Enables required APIs
3. 👤 Creates MCP server service account (if not exists)
4. 🔨 Builds Docker image using `Dockerfile.mcpserver`
5. 📤 Pushes image to Google Container Registry
6. 📝 Templates `cloudrun-mcpserver.yaml` with PROJECT_ID
7. 🚀 Deploys using `gcloud run services replace`
8. ✅ Outputs service URL and endpoints

### Get MCP Server URL

```bash
export SERVER_URL=$(gcloud run services describe $MCP_SERVER_SERVICE \
    --region=$REGION \
    --format="value(status.url)")

echo "MCP Server URL: $SERVER_URL"
```

## 🤖 Step 3: Deploy Agent Service

### Build and Deploy Agent Service

```bash
# Linux/macOS deployment
chmod +x deploy_agent.sh
./deploy_agent.sh $PROJECT_ID $REGION

# Windows PowerShell deployment
.\deploy_agent.ps1 $PROJECT_ID $REGION
```

The deployment script configures:
- **ConsolidatedAgentSecurity** with MCP framework delegation
- **Environment Variables** for consolidated security controls
- **Performance Optimization** for 8-10ms overhead
- **MCP Server Integration** with proper authentication

### Environment Variables Configured

The deployment automatically sets these consolidated security variables:

```bash
ENABLE_PROMPT_PROTECTION=true         # AgentPromptGuard → InputSanitizer
ENABLE_CONTEXT_VALIDATION=true        # AgentContextValidator → ContextSanitizer
ENABLE_MCP_VERIFICATION=true          # MCP response verification
ENABLE_RESPONSE_SANITIZATION=true     # Response sanitization
MAX_CONTEXT_SIZE=10000                # Context size limit
PROMPT_INJECTION_THRESHOLD=0.7        # Injection detection threshold
VERIFY_MCP_SIGNATURES=true            # MCP signature verification
TRUST_UNSIGNED_RESPONSES=false        # Require signed responses
```

## 🔗 Step 4: Configure Service-to-Service Authentication

### Grant Agent Service Access to MCP Server

```bash
# Allow agent service to invoke MCP server
gcloud run services add-iam-policy-binding $MCP_SERVER_SERVICE \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --region=$REGION
```

### Configure Environment Variables

```bash
# Update agent service with MCP server URL
gcloud run services update $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --set-env-vars="MCP_SERVER_URL=${SERVER_URL}" \
    --set-env-vars="TARGET_AUDIENCE=${SERVER_URL}" \
    --set-env-vars="PROJECT_ID=${PROJECT_ID}"

# Update MCP server with expected audience
gcloud run services update $MCP_SERVER_SERVICE \
    --region=$REGION \
    --set-env-vars="EXPECTED_AUDIENCE=${SERVER_URL}" \
    --set-env-vars="PROJECT_ID=${PROJECT_ID}" \
    --set-env-vars="ALLOWED_CLIENT_SA=${CLIENT_SA_EMAIL}"
```

## ✅ Step 5: Verify Deployment

### Service URLs

After deployment, you'll have:

- **Agent Service**: `https://agent-greeting-service-[hash]-uc.a.run.app`
  - Health: `GET /health`
  - Greet: `POST /greet`
  - Security Status: `GET /security/status`
  - API Docs: `GET /docs`

- **MCP Server**: `https://mcp-server-service-[hash]-uc.a.run.app`
  - Health: `GET /health`
  - MCP Health: `GET /mcp-server/health`
  - Tool Invoke: `POST /invoke`
  - MCP Endpoint: `GET /mcp-server/*`

### Test Authentication

```bash
# Test ID token generation
gcloud auth print-identity-token --audiences="${SERVER_URL}"

# Test authenticated call to MCP server
curl -H "Authorization: Bearer $(gcloud auth print-identity-token --audiences=${SERVER_URL})" \
     "${SERVER_URL}/health"

# Test agent service
curl -X POST "${CLIENT_URL}/greet" \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello consolidated security!"}'
```

### Verify Security Status

```bash
# Check consolidated security status
curl "${CLIENT_URL}/security/status"

# Expected response shows:
# - ConsolidatedAgentSecurity active
# - 4 agent controls enabled
# - MCP framework integration working
# - 8-10ms overhead performance
```

## 📊 Security Architecture Details

### Consolidated Security Benefits

The deployed architecture provides:

1. **70% Code Reduction**: From 1,342 to 424 lines
2. **Performance Improvement**: 8-10ms overhead (vs 11-13ms previously)
3. **MCP Framework Integration**: Delegation patterns for consistency
4. **Backward Compatibility**: OptimizedAgentSecurity alias maintained

### Security Control Mapping

| Agent Control | MCP Framework Component | Purpose |
|---------------|------------------------|---------|
| `AgentPromptGuard` | `InputSanitizer` | Prompt injection protection |
| `AgentContextValidator` | `ContextSanitizer` | Context validation |
| `AgentMCPVerifier` | MCP Security Framework | Response verification |
| `AgentResponseSanitizer` | Response Processing | Output sanitization |

## 🔧 Configuration Files Reference

### Container Configuration

#### Dockerfile.agentservice
- **Base**: Python 3.11-slim
- **Architecture**: Consolidated Security
- **Environment**: Production-optimized defaults
- **Health Checks**: Automated monitoring

#### Dockerfile.mcpserver
- **Base**: Python 3.11-slim  
- **Security**: 12 MCP security controls
- **Ports**: 8000 for MCP endpoints
- **User**: Non-root security

### Cloud Run Configuration

#### cloudrun-agentservice.yaml
```yaml
# Resource allocation for consolidated security
resources:
  limits:
    memory: "2Gi"
    cpu: "1"
  requests:
    memory: "1Gi" 
    cpu: "0.5"

# Performance optimizations
annotations:
  run.googleapis.com/cpu-throttling: "false"
  run.googleapis.com/startup-cpu-boost: "true"
  run.googleapis.com/min-scale: "1"
  run.googleapis.com/max-scale: "10"
```

#### cloudrun-mcpserver.yaml
```yaml
# MCP server optimizations
resources:
  limits:
    memory: "2Gi"
    cpu: "1"

# Security configuration
annotations:
  run.googleapis.com/execution-environment: gen2
  run.googleapis.com/min-scale: "1"
  run.googleapis.com/max-scale: "20"
```

## 🌍 Environment-Specific Deployments

### Development Environment
```bash
# Local development without IAM complexity
docker build -f Dockerfile.agentservice -t agent-service .
docker build -f Dockerfile.mcpserver -t mcp-server .
docker run -p 8080:8080 agent-service
docker run -p 8000:8000 mcp-server
```

### Staging Environment
```bash
# Deploy with reduced resources
./deploy_mcpserver.sh staging-project us-central1
./deploy_agent.sh staging-project us-central1
# Modify YAML: min-scale: 0, max-scale: 5
```

### Production Environment
```bash
# Full security and scaling configuration
./deploy_mcpserver.sh production-project us-central1
./deploy_agent.sh production-project us-central1
# Use all security features and optimal scaling
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Authentication Failures
```bash
# Check service account permissions
gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:${CLIENT_SA_EMAIL}" \
    --format="table(bindings.role)"
```

#### 2. Service Communication Issues
```bash
# Check service logs
gcloud logs read "resource.type=cloud_run_revision AND resource.labels.service_name=${MCP_CLIENT_SERVICE}" \
    --limit=50 \
    --format="table(timestamp,severity,textPayload)"
```

#### 3. Environment Variable Issues
```bash
# Verify environment variables
gcloud run services describe $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --format="table(spec.template.spec.template.spec.containers[].env[].name,spec.template.spec.template.spec.containers[].env[].value)"
```

### Health Checks

```bash
# Check service status
gcloud run services describe $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --format="table(status.conditions[].type,status.conditions[].status)"

gcloud run services describe $MCP_SERVER_SERVICE \
    --region=$REGION \
    --format="table(status.conditions[].type,status.conditions[].status)"
```

## 📈 Performance Monitoring

### Key Metrics

Monitor these metrics for optimal performance:

1. **Response Time**: Should show 8-10ms security overhead
2. **Error Rate**: Monitor authentication and security control failures
3. **Resource Usage**: CPU and memory utilization
4. **Cold Start Time**: Minimized with min-scale: 1

### Alerting Setup

```bash
# Create log-based metrics for monitoring
gcloud logging metrics create auth_failures \
    --description="Authentication failures in MCP services" \
    --log-filter='resource.type="cloud_run_revision" AND severity="ERROR" AND textPayload:"authentication failed"'

gcloud logging metrics create security_violations \
    --description="Security control violations" \
    --log-filter='resource.type="cloud_run_revision" AND textPayload:"ConsolidatedAgentSecurity"'
```

## 🧹 Cleanup (For Testing)

### Remove Services
```bash
# Delete Cloud Run services
gcloud run services delete $MCP_CLIENT_SERVICE --region=$REGION --quiet
gcloud run services delete $MCP_SERVER_SERVICE --region=$REGION --quiet

# Delete service accounts
gcloud iam service-accounts delete $CLIENT_SA_EMAIL --quiet
gcloud iam service-accounts delete $SERVER_SA_EMAIL --quiet

# Remove IAM bindings
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator"
```

## 📚 File Reference

### Deployment Infrastructure

| File | Purpose | Key Features |
|------|---------|--------------|
| `deploy_agent.sh/.ps1` | Agent service deployment | Consolidated security configuration |
| `deploy_mcpserver.sh/.ps1` | MCP server deployment | Complete pipeline automation |
| `cloudrun-agentservice.yaml` | Agent service specification | Performance & security optimization |
| `cloudrun-mcpserver.yaml` | MCP server specification | 12 security controls configuration |
| `Dockerfile.agentservice` | Agent container build | Consolidated security architecture |
| `Dockerfile.mcpserver` | MCP server container build | MCP framework implementation |

### Documentation

| File | Purpose | Status |
|------|---------|--------|
| `DEPLOYMENT_GUIDE.md` | **This file** - Complete deployment guide | ✅ **Use This** |
| `DEPLOYMENT_ARCHITECTURE_UPDATE.md` | Architecture update summary | 📝 Reference |
| ~~`DEPLOYMENT.md`~~ | Legacy deployment guide | ❌ **Deprecated** |
| ~~`DEPLOYMENT_TEMPLATE_METHOD.md`~~ | Template method deployment | ❌ **Deprecated** |

## 🎉 Conclusion

This deployment guide provides everything needed to deploy the MCP consolidated security architecture to Google Cloud Run. The new architecture delivers:

- **70% Reduction** in security code complexity
- **Improved Performance** with 8-10ms overhead
- **MCP Framework Integration** for consistency
- **Production-Ready Security** with zero-trust authentication
- **Scalable Infrastructure** with automatic optimization

The consolidated approach simplifies deployment while maintaining enterprise-grade security through the MCP framework delegation pattern.

---

**Next Steps After Deployment:**
1. ✅ Verify all health checks pass
2. ✅ Test security status endpoints  
3. ✅ Monitor performance metrics
4. ✅ Set up alerting for production
5. ✅ Document any custom configuration changes

For support or issues, check the troubleshooting section above or examine service logs using the provided commands.
