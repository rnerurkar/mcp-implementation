# Agent Service Deployment Script for HTTP Streaming Architecture
# Builds and deploys the Agent Service to Google Cloud Run

param(
    [string]$ProjectId = "flowing-radio-459513-g8",
    [string]$Region = "us-central1",
    [string]$ServiceName = "agent-service-fixed",
    [string]$ImageTag = "v3",
    [string]$McpServerUrl = "https://mcp-server-service-kcpcuuzfea-uc.a.run.app",
    [string]$GoogleApiKey = "AIzaSyCwxH_FzCvXGj3yML7zMcpEb0br2V_C4oA"
)

Write-Host "Starting Agent Service deployment..." -ForegroundColor Green
Write-Host "Project: $ProjectId" -ForegroundColor Cyan
Write-Host "Region: $Region" -ForegroundColor Cyan
Write-Host "Service: $ServiceName" -ForegroundColor Cyan
Write-Host "MCP Server URL: $McpServerUrl" -ForegroundColor Cyan

# Step 1: Set up Google Cloud
Write-Host "`nConfiguring Google Cloud..." -ForegroundColor Yellow
gcloud config set project $ProjectId

# Step 2: Build Docker image
Write-Host "`nBuilding Docker image..." -ForegroundColor Yellow
$agentImage = "agent-service-fixed"
$agentFullImage = "gcr.io/$ProjectId/$agentImage" + ":" + $ImageTag

docker build -f Dockerfile.agentservice -t $agentFullImage . --no-cache
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker build failed!" -ForegroundColor Red
    exit 1
}

# Step 3: Push to Google Container Registry
Write-Host "`nPushing image to GCR..." -ForegroundColor Yellow
docker push $agentFullImage
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker push failed!" -ForegroundColor Red
    exit 1
}

# Step 4: Deploy to Cloud Run
Write-Host "`nDeploying to Cloud Run..." -ForegroundColor Yellow
gcloud run deploy $ServiceName `
    --image $agentFullImage `
    --region $Region `
    --allow-unauthenticated `
    --port 8080 `
    --memory 2Gi `
    --cpu 2 `
    --timeout 300 `
    --set-env-vars "ENVIRONMENT=production,HOST=0.0.0.0,MCP_SERVER_URL=$McpServerUrl,GOOGLE_API_KEY=$GoogleApiKey" `
    --format="value(status.url)"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Cloud Run deployment failed!" -ForegroundColor Red
    exit 1
}

# Step 5: Get service URL
$agentServiceUrl = gcloud run services describe $ServiceName --region=$Region --format="value(status.url)"

Write-Host "`nDeployment Summary:" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor Cyan
Write-Host "Image: $agentFullImage" -ForegroundColor Cyan
Write-Host "Service URL: $agentServiceUrl" -ForegroundColor Cyan
Write-Host "`nImportant URLs:" -ForegroundColor Yellow
Write-Host "   API Docs: $agentServiceUrl/docs" -ForegroundColor White
Write-Host "   Health Check: $agentServiceUrl/health" -ForegroundColor White
Write-Host "   Greet Endpoint: $agentServiceUrl/greet" -ForegroundColor White

Write-Host "`nAgent Service deployment completed successfully!" -ForegroundColor Green
Write-Host "Agent Service URL: $agentServiceUrl" -ForegroundColor Cyan
