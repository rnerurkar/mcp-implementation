# PowerShell script to deploy Agent Service to Cloud Run
# Usage: .\deploy_agent.ps1 [PROJECT_ID] [REGION]

param(
    [string]$ProjectId = "your-project-id",
    [string]$Region = "us-central1"
)

# Configuration
$SERVICE_NAME = "agent-greeting-service"
$IMAGE_NAME = "gcr.io/$ProjectId/$SERVICE_NAME"
$DOCKERFILE = "Dockerfile.agentservice"

Write-Host "🚀 Deploying Agent Service to Cloud Run" -ForegroundColor Green
Write-Host "Project: $ProjectId"
Write-Host "Region: $Region"
Write-Host "Service: $SERVICE_NAME"
Write-Host "Dockerfile: $DOCKERFILE"
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

# Deploy to Cloud Run
Write-Host "🚀 Deploying to Cloud Run..." -ForegroundColor Blue
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
    --set-env-vars "AGENT_MODEL=gemini-1.5-flash,AGENT_NAME=GreetingAgent" `
    --port 8080

# Get service URL
$SERVICE_URL = gcloud run services describe $SERVICE_NAME --region $Region --format 'value(status.url)'

Write-Host "✅ Agent Service deployment completed!" -ForegroundColor Green
Write-Host "🌐 Service URL: $SERVICE_URL" -ForegroundColor Cyan
Write-Host "🏥 Health Check: $SERVICE_URL/health" -ForegroundColor Cyan
Write-Host "💬 Greet Endpoint: $SERVICE_URL/greet" -ForegroundColor Cyan
Write-Host "📚 API Docs: $SERVICE_URL/docs" -ForegroundColor Cyan

Write-Host ""
Write-Host "📋 Next Steps:" -ForegroundColor Yellow
Write-Host "1. Test the deployment with: python test_agentservice.py"
Write-Host "2. Update MCP_URL in agent configuration to connect to MCP Server"
Write-Host "3. Configure Google Cloud Run service-to-service authentication with IAM roles (if required)"
Write-Host "4. Set up monitoring and alerting"
Write-Host "5. Try the interactive API documentation at: $SERVICE_URL/docs"
