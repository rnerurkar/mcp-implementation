# MCP Server Deployment Script for HTTP Streaming Architecture
# Builds and deploys the MCP Server to Google Cloud Run

param(
    [string]$ProjectId = "flowing-radio-459513-g8",
    [string]$Region = "us-central1",
    [string]$ServiceName = "mcp-server-service",
    [string]$ImageTag = "latest"
)

Write-Host "Starting MCP Server deployment..." -ForegroundColor Green
Write-Host "Project: $ProjectId" -ForegroundColor Cyan
Write-Host "Region: $Region" -ForegroundColor Cyan
Write-Host "Service: $ServiceName" -ForegroundColor Cyan

# Step 1: Set up Google Cloud
Write-Host "`nConfiguring Google Cloud..." -ForegroundColor Yellow
gcloud config set project $ProjectId

# Step 2: Enable required APIs
Write-Host "Enabling required APIs..." -ForegroundColor Yellow
gcloud services enable run.googleapis.com containerregistry.googleapis.com

# Step 3: Build Docker image
Write-Host "`nBuilding Docker image..." -ForegroundColor Yellow
$mcpImage = "mcp-server-streaming"
$mcpFullImage = "gcr.io/$ProjectId/$mcpImage" + ":" + $ImageTag

docker build -f Dockerfile.mcpserver -t $mcpFullImage . --no-cache
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed!" -ForegroundColor Red
    exit 1
}

# Step 4: Push to Google Container Registry
Write-Host "`nPushing image to GCR..." -ForegroundColor Yellow
docker push $mcpFullImage
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker push failed!" -ForegroundColor Red
    exit 1
}

# Step 5: Deploy to Cloud Run
Write-Host "`nDeploying to Cloud Run..." -ForegroundColor Yellow
gcloud run deploy $ServiceName `
    --image $mcpFullImage `
    --region $Region `
    --allow-unauthenticated `
    --port 8080 `
    --memory 1Gi `
    --cpu 1 `
    --timeout 300 `
    --set-env-vars "ENVIRONMENT=production,HOST=0.0.0.0" `
    --format="value(status.url)"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Cloud Run deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 6: Get service URL
$mcpServiceUrl = gcloud run services describe $ServiceName --region=$Region --format="value(status.url)"

Write-Host "`nDeployment Summary:" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
Write-Host "Image: $mcpFullImage" -ForegroundColor Cyan
Write-Host "Service URL: $mcpServiceUrl" -ForegroundColor Cyan
Write-Host "`nImportant URLs:" -ForegroundColor Yellow
Write-Host "   API Docs: $mcpServiceUrl/docs" -ForegroundColor White
Write-Host "   Health Check: $mcpServiceUrl/mcp-server/health" -ForegroundColor White
Write-Host "   Streaming: $mcpServiceUrl/mcp/stream" -ForegroundColor White
Write-Host "   Tools: $mcpServiceUrl/mcp/tools" -ForegroundColor White

Write-Host "`nMCP Server deployment completed successfully!" -ForegroundColor Green
Write-Host "Use this URL for agent service: $mcpServiceUrl" -ForegroundColor Cyan
