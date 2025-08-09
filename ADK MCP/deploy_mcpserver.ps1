# PowerShell script to deploy MCP Server to Cloud Run
# Usage: .\deploy_mcpserver.ps1 [PROJECT_ID] [REGION]

param(
    [string]$ProjectId = "your-project-id",
    [string]$Region = "us-central1"
)

# Validate parameters
if ($ProjectId -eq "your-project-id") {
    Write-Error "Please provide a valid Google Cloud Project ID"
    Write-Host "Usage: .\deploy_mcpserver.ps1 [PROJECT_ID] [REGION]"
    exit 1
}

if (-not $ProjectId -or $ProjectId.Trim() -eq "") {
    Write-Error "Project ID cannot be empty"
    exit 1
}

# Configuration
$SERVICE_NAME = "mcp-server-service"
$IMAGE_NAME = "gcr.io/$ProjectId/$SERVICE_NAME"
$DOCKERFILE = "Dockerfile.mcpserver"

Write-Host "Deploying MCP Server to Cloud Run" -ForegroundColor Green
Write-Host "Project: $ProjectId"
Write-Host "Region: $Region"
Write-Host "Service: $SERVICE_NAME"
Write-Host "Dockerfile: $DOCKERFILE"
Write-Host "----------------------------------------"

# Validate required files exist
if (-not (Test-Path $DOCKERFILE)) {
    Write-Error "Dockerfile not found: $DOCKERFILE"
    exit 1
}

if (-not (Test-Path "cloudrun-mcpserver.yaml")) {
    Write-Error "Cloud Run configuration not found: cloudrun-mcpserver.yaml"
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

# Create service account if it doesn't exist
Write-Host "Setting up service account..." -ForegroundColor Blue
$SERVICE_ACCOUNT_NAME = "mcp-server-service-account"
$SERVICE_ACCOUNT_EMAIL = "$SERVICE_ACCOUNT_NAME@$ProjectId.iam.gserviceaccount.com"

# Check if service account exists
gcloud iam service-accounts describe $SERVICE_ACCOUNT_EMAIL --quiet 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Creating service account: $SERVICE_ACCOUNT_EMAIL"
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME `
        --display-name="MCP Server Service Account" `
        --description="Service account for MCP Server Cloud Run service"
    
    # Grant necessary permissions
    gcloud projects add-iam-policy-binding $ProjectId `
        --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" `
        --role="roles/secretmanager.secretAccessor"
    
    gcloud projects add-iam-policy-binding $ProjectId `
        --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" `
        --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
} else {
    Write-Host "Service account already exists: $SERVICE_ACCOUNT_EMAIL"
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

# Update the YAML file with correct project ID
Write-Host "Updating Cloud Run configuration..." -ForegroundColor Blue
(Get-Content cloudrun-mcpserver.yaml) -replace 'PROJECT_ID', $ProjectId | Out-File -FilePath cloudrun-mcpserver-deploy.yaml -Encoding UTF8

# Deploy to Cloud Run using YAML configuration
Write-Host "Deploying to Cloud Run..." -ForegroundColor Blue
gcloud run services replace cloudrun-mcpserver-deploy.yaml --region $Region
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cloud Run deployment failed"
    Remove-Item -Path cloudrun-mcpserver-deploy.yaml -Force -ErrorAction SilentlyContinue
    exit 1
}

# Get service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME --region $Region --format 'value(status.url)'
if (-not $SERVICE_URL) {
    Write-Error "Failed to retrieve service URL"
    exit 1
}

Write-Host "MCP Server deployment completed!" -ForegroundColor Green
Write-Host "Service URL: $SERVICE_URL" -ForegroundColor Cyan
Write-Host "MCP Endpoint: $SERVICE_URL/mcp-server" -ForegroundColor Cyan
Write-Host "SSE Endpoint: $SERVICE_URL/mcp-server/sse" -ForegroundColor Cyan
Write-Host "Tool Invoke: $SERVICE_URL/invoke" -ForegroundColor Cyan

# Clean up temporary file
Remove-Item -Path cloudrun-mcpserver-deploy.yaml -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Update your MCP client configuration to use: $SERVICE_URL/mcp-server"
Write-Host "2. Configure Google Cloud Run service-to-service authentication with IAM roles and ID tokens"
Write-Host "3. Set up OPA (Open Policy Agent) for policy enforcement"
Write-Host "4. Configure Google Cloud KMS for encryption (if needed)"
Write-Host "5. Test the deployment with: python test_mcpserver.py"
