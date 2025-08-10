# PowerShell script to deploy Agent Service to Cloud Run
# Usage: .\deploy_agent.ps1 [PROJECT_ID] [REGION]

param(
    [string]$ProjectId = "your-project-id",
    [string]$Region = "us-central1"
)

# Validate parameters
if ($ProjectId -eq "your-project-id") {
    Write-Error "Please provide a valid Google Cloud Project ID"
    Write-Host "Usage: .\deploy_agent.ps1 [PROJECT_ID] [REGION]"
    exit 1
}

if (-not $ProjectId -or $ProjectId.Trim() -eq "") {
    Write-Error "Project ID cannot be empty"
    exit 1
}

# Configuration
$SERVICE_NAME = "agent-greeting-service"
$IMAGE_NAME = "gcr.io/$ProjectId/$SERVICE_NAME"
$DOCKERFILE = "Dockerfile.agentservice"

Write-Host "Deploying Consolidated Agent Service to Cloud Run" -ForegroundColor Green
Write-Host "Project: $ProjectId"
Write-Host "Region: $Region"
Write-Host "Service: $SERVICE_NAME"
Write-Host "Architecture: Consolidated Security (70% code reduction)"
Write-Host "Security: 4 Agent Controls + MCP Framework Delegation"
Write-Host "Dockerfile: $DOCKERFILE"
Write-Host "----------------------------------------"

# Validate required files exist
if (-not (Test-Path $DOCKERFILE)) {
    Write-Error "Dockerfile not found: $DOCKERFILE"
    exit 1
}

# Ensure gcloud is configured
Write-Host "Checking gcloud configuration..." -ForegroundColor Blue

# Check if user is authenticated
$AUTH_CHECK = gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>$null
if (-not $AUTH_CHECK) {
    Write-Error "No active gcloud authentication found. Please run 'gcloud auth login' first."
    exit 1
}

gcloud config set project $ProjectId
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to set gcloud project"
    exit 1
}

# Enable required APIs
Write-Host "Enabling required APIs..." -ForegroundColor Blue
gcloud services enable run.googleapis.com
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to enable Cloud Run API"
    exit 1
}

gcloud services enable containerregistry.googleapis.com
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to enable Container Registry API"
    exit 1
}

# Build and push container image
Write-Host "Building container image..." -ForegroundColor Blue

# Configure Docker to use gcloud as credential helper
gcloud auth configure-docker --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to configure Docker for gcloud"
    exit 1
}

docker build -f $DOCKERFILE -t $IMAGE_NAME .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker build failed"
    exit 1
}

Write-Host "Pushing image to Container Registry..." -ForegroundColor Blue
docker push $IMAGE_NAME
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker push failed"
    exit 1
}

# Deploy to Cloud Run with Consolidated security configuration
Write-Host "Deploying Consolidated Agent Service to Cloud Run..." -ForegroundColor Blue
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

if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Run deployment failed"
    exit 1
}

# Get service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME --region $Region --format 'value(status.url)'

Write-Host "Consolidated Agent Service deployment completed!" -ForegroundColor Green
Write-Host "Architecture: ConsolidatedAgentSecurity" -ForegroundColor Cyan
Write-Host "Security: MCP Framework Integration" -ForegroundColor Cyan
Write-Host "Service URL: $SERVICE_URL" -ForegroundColor Cyan
Write-Host "Health Check: $SERVICE_URL/health" -ForegroundColor Cyan
Write-Host "API Documentation: $SERVICE_URL/docs" -ForegroundColor Cyan
Write-Host "Security Status: $SERVICE_URL/security/status" -ForegroundColor Cyan

Write-Host ""
Write-Host "Consolidated Security Features:" -ForegroundColor Yellow
Write-Host "1. Agent wrappers delegate to MCP framework components"
Write-Host "2. 70% code reduction through MCP integration"
Write-Host "3. Shared threat intelligence between agent and MCP layers"
Write-Host "4. Backward compatibility maintained"

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Test consolidated deployment: python test_agent_security_consolidated.py"
Write-Host "2. Verify security status: curl $SERVICE_URL/security/status"
Write-Host "3. Test security controls: python test_security_controls.py"
Write-Host "4. Monitor performance improvements"
Write-Host "5. Validate MCP framework integration"
