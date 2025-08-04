# Cloud Run IAM Configuration for Service-to-Service Authentication

This document provides the complete GCP CLI commands needed to set up IAM roles and permissions for Cloud Run service-to-service authentication using ID tokens generated via Google Auth library.

## Authentication Method

**ID Token Generation**: Uses Google Auth library exclusively (no metadata server calls)
- Works across all Google Cloud environments (Cloud Run, GCE, local development)
- Consistent behavior regardless of deployment environment
- Automatic credential discovery via Application Default Credentials (ADC)

## Prerequisites

1. **GCP CLI installed and authenticated**:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

2. **Environment Variables** (replace with your actual values):
   ```bash
   export PROJECT_ID="your-project-id"
   export MCP_CLIENT_SERVICE="mcp-client-service"
   export MCP_SERVER_SERVICE="mcp-server-service"
   export REGION="us-central1"
   ```

## 1. Service Account Creation

### Create Service Account for MCP Client
```bash
# Create service account for MCP client
gcloud iam service-accounts create mcp-client-sa \
    --display-name="MCP Client Service Account" \
    --description="Service account for MCP client to authenticate with MCP server"

# Create service account for MCP server
gcloud iam service-accounts create mcp-server-sa \
    --display-name="MCP Server Service Account" \
    --description="Service account for MCP server to receive authenticated requests"
```

### Get Service Account Emails
```bash
export CLIENT_SA_EMAIL="mcp-client-sa@${PROJECT_ID}.iam.gserviceaccount.com"
export SERVER_SA_EMAIL="mcp-server-sa@${PROJECT_ID}.iam.gserviceaccount.com"
```

## 2. IAM Role Assignments

### Grant ID Token Creation Permission to Client
```bash
# Allow MCP client service account to create ID tokens
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator"

# Grant client ability to act as itself (for Workload Identity)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountUser"
```

### Grant Server Basic Permissions
```bash
# Grant server service account basic Cloud Run permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVER_SA_EMAIL}" \
    --role="roles/run.invoker"

# Grant server ability to access secrets (if using Secret Manager)
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVER_SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor"
```

## 3. Cloud Run Service Deployment IAM

### Deploy MCP Client Service
```bash
# Deploy client with proper service account
gcloud run deploy $MCP_CLIENT_SERVICE \
    --image="gcr.io/${PROJECT_ID}/mcp-client:latest" \
    --service-account="${CLIENT_SA_EMAIL}" \
    --region=$REGION \
    --platform=managed \
    --allow-unauthenticated \
    --port=8080 \
    --memory=1Gi \
    --cpu=1 \
    --max-instances=10

# Get client service URL
export CLIENT_URL=$(gcloud run services describe $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --format="value(status.url)")
```

### Deploy MCP Server Service
```bash
# Deploy server with proper service account
gcloud run deploy $MCP_SERVER_SERVICE \
    --image="gcr.io/${PROJECT_ID}/mcp-server:latest" \
    --service-account="${SERVER_SA_EMAIL}" \
    --region=$REGION \
    --platform=managed \
    --no-allow-unauthenticated \
    --port=8080 \
    --memory=2Gi \
    --cpu=1 \
    --max-instances=10

# Get server service URL
export SERVER_URL=$(gcloud run services describe $MCP_SERVER_SERVICE \
    --region=$REGION \
    --format="value(status.url)")
```

## 4. Service-to-Service Access Configuration

### Allow Client to Invoke Server
```bash
# Grant MCP client permission to invoke MCP server
gcloud run services add-iam-policy-binding $MCP_SERVER_SERVICE \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --region=$REGION
```

### Alternative: Allow Specific Service Account to Invoke Server
```bash
# More restrictive: Only allow specific service account
gcloud run services set-iam-policy $MCP_SERVER_SERVICE \
    --region=$REGION \
    policy.yaml
```

**policy.yaml content:**
```yaml
bindings:
- members:
  - serviceAccount:mcp-client-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com
  role: roles/run.invoker
etag: BwXhBxxx
version: 1
```

## 5. Environment Variables for Services

### MCP Client Environment Variables
```bash
# Set environment variables for client service
gcloud run services update $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --set-env-vars="MCP_SERVER_URL=${SERVER_URL}" \
    --set-env-vars="TARGET_AUDIENCE=${SERVER_URL}" \
    --set-env-vars="PROJECT_ID=${PROJECT_ID}"
```

### MCP Server Environment Variables
```bash
# Set environment variables for server service
gcloud run services update $MCP_SERVER_SERVICE \
    --region=$REGION \
    --set-env-vars="EXPECTED_AUDIENCE=${SERVER_URL}" \
    --set-env-vars="PROJECT_ID=${PROJECT_ID}" \
    --set-env-vars="ALLOWED_CLIENT_SA=${CLIENT_SA_EMAIL}"
```

## 6. Security Verification Commands

### Test ID Token Generation
```bash
# Test if client can generate ID tokens (run from client service)
gcloud auth print-identity-token --audiences="${SERVER_URL}"
```

### Test Service Invocation
```bash
# Test authenticated call to server
curl -H "Authorization: Bearer $(gcloud auth print-identity-token --audiences=${SERVER_URL})" \
     "${SERVER_URL}/health"
```

### Verify IAM Bindings
```bash
# Check client service account permissions
gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:${CLIENT_SA_EMAIL}" \
    --format="table(bindings.role)"

# Check server service IAM
gcloud run services get-iam-policy $MCP_SERVER_SERVICE \
    --region=$REGION
```

## 7. Troubleshooting Commands

### Check Service Account Key Usage (Should be Empty)
```bash
# Verify no service account keys exist (good security practice)
gcloud iam service-accounts keys list \
    --iam-account="${CLIENT_SA_EMAIL}"

gcloud iam service-accounts keys list \
    --iam-account="${SERVER_SA_EMAIL}"
```

### Check Cloud Run Service Status
```bash
# Check client service status
gcloud run services describe $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --format="table(status.conditions[].type,status.conditions[].status)"

# Check server service status
gcloud run services describe $MCP_SERVER_SERVICE \
    --region=$REGION \
    --format="table(status.conditions[].type,status.conditions[].status)"
```

### View Service Logs
```bash
# View client logs
gcloud logs read "resource.type=cloud_run_revision AND resource.labels.service_name=${MCP_CLIENT_SERVICE}" \
    --limit=50 \
    --format="table(timestamp,severity,textPayload)"

# View server logs
gcloud logs read "resource.type=cloud_run_revision AND resource.labels.service_name=${MCP_SERVER_SERVICE}" \
    --limit=50 \
    --format="table(timestamp,severity,textPayload)"
```

## 8. Advanced Security Configuration

### Enable Cloud Run Security Features
```bash
# Enable VPC egress for client (if needed)
gcloud run services update $MCP_CLIENT_SERVICE \
    --region=$REGION \
    --vpc-egress=all-traffic

# Set execution environment to second generation
gcloud run services update $MCP_SERVER_SERVICE \
    --region=$REGION \
    --execution-environment=gen2 \
    --cpu-boost
```

### Configure Binary Authorization (Optional)
```bash
# Enable binary authorization for enhanced security
gcloud container binauthz policy import policy.yaml

# Update Cloud Run to use binary authorization
gcloud run services update $MCP_SERVER_SERVICE \
    --region=$REGION \
    --binary-authorization=default
```

## 9. Monitoring and Alerting Setup

### Create Log-Based Metrics
```bash
# Create metric for authentication failures
gcloud logging metrics create auth_failures \
    --description="Authentication failures in MCP services" \
    --log-filter='resource.type="cloud_run_revision" AND severity="ERROR" AND textPayload:"authentication failed"'

# Create metric for successful authentications
gcloud logging metrics create auth_success \
    --description="Successful authentications in MCP services" \
    --log-filter='resource.type="cloud_run_revision" AND textPayload:"Validated ID token"'
```

### Set Up Alerts
```bash
# Create notification channel (replace with your email)
gcloud alpha monitoring channels create \
    --display-name="MCP Security Alerts" \
    --type=email \
    --channel-labels=email_address=your-email@company.com
```

## 10. Cleanup Commands (For Testing)

### Remove IAM Bindings
```bash
# Remove client permissions
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/iam.serviceAccountTokenCreator"

# Remove server permissions
gcloud run services remove-iam-policy-binding $MCP_SERVER_SERVICE \
    --member="serviceAccount:${CLIENT_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --region=$REGION
```

### Delete Services and Service Accounts
```bash
# Delete Cloud Run services
gcloud run services delete $MCP_CLIENT_SERVICE --region=$REGION --quiet
gcloud run services delete $MCP_SERVER_SERVICE --region=$REGION --quiet

# Delete service accounts
gcloud iam service-accounts delete $CLIENT_SA_EMAIL --quiet
gcloud iam service-accounts delete $SERVER_SA_EMAIL --quiet
```

## Summary

The key IAM configurations for ID token-based authentication are:

1. **Client Service Account** needs:
   - `roles/iam.serviceAccountTokenCreator` - To create ID tokens
   - `roles/iam.serviceAccountUser` - For Workload Identity
   - `roles/run.invoker` on target server - To call the server

2. **Server Service Account** needs:
   - `roles/secretmanager.secretAccessor` - If using Secret Manager
   - Standard Cloud Run permissions

3. **Server Service** configured with:
   - `--no-allow-unauthenticated` - Requires authentication
   - Proper service account assignment
   - Environment variables for audience validation

This configuration ensures secure, keyless authentication using Google Cloud's managed identity system.
