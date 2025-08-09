# PowerShell script to deploy Agent Service to Cloud RunWrite-Host "✅ Template Method Agent Service deployment completed!" -ForegroundColor Green
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
Write-Host "5. Consider adding new agent implementations (ChatGPT, Claude)"deploy_agent.ps1 [PROJECT_ID] [REGION]

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

# Deploy to Cloud Run with Template Method security configuration
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
