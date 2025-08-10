#!/bin/bash

# Deploy Agent Service to Cloud Run
# Usage: ./deploy.sh [PROJECT_ID] [REGION]

set -e

# Configuration
PROJECT_ID=${1:-"your-project-id"}
REGION=${2:-"us-central1"}
SERVICE_NAME="agent-greeting-service"
IMAGE_NAME="gcr.io/$PROJECT_ID/$SERVICE_NAME"
DOCKERFILE="Dockerfile.agentservice"

echo "🔒 Deploying Consolidated Agent Service to Cloud Run"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Architecture: Consolidated Security (70% code reduction)"
echo "Security: 4 Agent Controls + MCP Framework Delegation"
echo "Dockerfile: $DOCKERFILE"
echo "----------------------------------------"

# Ensure gcloud is configured
echo "📋 Checking gcloud configuration..."
gcloud config set project $PROJECT_ID

# Build and push container image
echo "🔨 Building container image..."
docker build -f $DOCKERFILE -t $IMAGE_NAME .

echo "📤 Pushing image to Container Registry..."
docker push $IMAGE_NAME

# Deploy to Cloud Run
echo "🚀 Deploying to Cloud Run..."
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
    --set-env-vars "AGENT_MODEL=gemini-1.5-flash,AGENT_NAME=GreetingAgent,ENABLE_PROMPT_PROTECTION=true,ENABLE_CONTEXT_VALIDATION=true,ENABLE_MCP_VERIFICATION=true,ENABLE_RESPONSE_SANITIZATION=true,MAX_CONTEXT_SIZE=10000,PROMPT_INJECTION_THRESHOLD=0.7,VERIFY_MCP_SIGNATURES=true,TRUST_UNSIGNED_RESPONSES=false" \
    --port 8080

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')

echo "✅ Consolidated Agent Service deployment completed!"
echo "�️ Architecture: ConsolidatedAgentSecurity"
echo "🛡️ Security: MCP Framework Integration"
echo "�🌐 Service URL: $SERVICE_URL"
echo "� Health Check: $SERVICE_URL/health"
echo "📚 API Documentation: $SERVICE_URL/docs"
echo "🛡️ Security Status: $SERVICE_URL/security/status"
echo "📚 API Docs: $SERVICE_URL/docs"
echo "----------------------------------------"

# Test the service
echo "🧪 Testing the service..."
curl -f "$SERVICE_URL/health" && echo "✅ Health check passed"

echo "🎉 Agent Service is ready!"
echo ""
echo "Example usage:"
echo "curl -X POST \"$SERVICE_URL/greet\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"message\": \"Hello, how are you?\"}'"
