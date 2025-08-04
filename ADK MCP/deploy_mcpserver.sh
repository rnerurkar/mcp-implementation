#!/bin/bash

# Deploy MCP Server to Cloud Run
# Usage: ./deploy_mcpserver.sh [PROJECT_ID] [REGION]

set -e

# Configuration
PROJECT_ID=${1:-"your-project-id"}
REGION=${2:-"us-central1"}
SERVICE_NAME="mcp-server-service"
IMAGE_NAME="gcr.io/$PROJECT_ID/$SERVICE_NAME"
DOCKERFILE="Dockerfile.mcpserver"

echo "🚀 Deploying MCP Server to Cloud Run"
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Dockerfile: $DOCKERFILE"
echo "----------------------------------------"

# Ensure gcloud is configured
echo "📋 Checking gcloud configuration..."
gcloud config set project $PROJECT_ID

# Enable required APIs
echo "🔧 Enabling required APIs..."
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Create service account if it doesn't exist
echo "👤 Setting up service account..."
SERVICE_ACCOUNT_NAME="mcp-server-service-account"
SERVICE_ACCOUNT_EMAIL="$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe $SERVICE_ACCOUNT_EMAIL --quiet 2>/dev/null; then
    echo "Creating service account: $SERVICE_ACCOUNT_EMAIL"
    gcloud iam service-accounts create $SERVICE_ACCOUNT_NAME \
        --display-name="MCP Server Service Account" \
        --description="Service account for MCP Server Cloud Run service"
    
    # Grant necessary permissions
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
        --role="roles/secretmanager.secretAccessor"
    
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:$SERVICE_ACCOUNT_EMAIL" \
        --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
else
    echo "Service account already exists: $SERVICE_ACCOUNT_EMAIL"
fi

# Build and push container image
echo "🔨 Building container image..."
docker build -f $DOCKERFILE -t $IMAGE_NAME .

echo "📤 Pushing image to Container Registry..."
docker push $IMAGE_NAME

# Update the YAML file with correct project ID
echo "📝 Updating Cloud Run configuration..."
sed "s/PROJECT_ID/$PROJECT_ID/g" cloudrun-mcpserver.yaml > cloudrun-mcpserver-deploy.yaml

# Deploy to Cloud Run using YAML configuration
echo "🚀 Deploying to Cloud Run..."
gcloud run services replace cloudrun-mcpserver-deploy.yaml --region $REGION

# Alternative: Deploy using gcloud run deploy command
# Uncomment the following block if you prefer command-line deployment
# gcloud run deploy $SERVICE_NAME \
#     --image $IMAGE_NAME \
#     --region $REGION \
#     --platform managed \
#     --allow-unauthenticated \
#     --memory 2Gi \
#     --cpu 1 \
#     --min-instances 1 \
#     --max-instances 20 \
#     --timeout 300 \
#     --service-account $SERVICE_ACCOUNT_EMAIL \
#     --port 8000 \
#     --set-env-vars "AZURE_AUDIENCE=api://your-mcp-server-app-id,GCP_PROJECT=$PROJECT_ID,SECURITY_LEVEL=high"

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format 'value(status.url)')

echo "✅ MCP Server deployment completed!"
echo "🌐 Service URL: $SERVICE_URL"
echo "🔧 MCP Endpoint: $SERVICE_URL/mcp-server"
echo "⚡ SSE Endpoint: $SERVICE_URL/mcp-server/sse"
echo "🛠️ Tool Invoke: $SERVICE_URL/invoke"

# Clean up temporary file
rm -f cloudrun-mcpserver-deploy.yaml

echo ""
echo "📋 Next Steps:"
echo "1. Update your MCP client configuration to use: $SERVICE_URL/mcp-server"
echo "2. Configure Google Cloud Run service-to-service authentication with IAM roles and ID tokens"
echo "3. Set up OPA (Open Policy Agent) for policy enforcement"
echo "4. Configure Google Cloud KMS for encryption (if needed)"
echo "5. Test the deployment with: curl $SERVICE_URL/mcp-server/health"
