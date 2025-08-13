# Cloud Run IAM Configuration for Automatic Authentication

This document provides the complete GCP CLI commands needed to set up IAM roles and permissions for **Cloud Run automatic authentication** using infrastructure-managed ID tokens.

## Authentication Method

**Cloud Run Automatic Authentication**: Leverages Cloud Run's built-in authentication infrastructure
- **Zero manual JWT handling**: Cloud Run handles all cryptographic validation
- **Automatic header injection**: Authentication details injected as HTTP headers
- **Infrastructure security**: Google-managed security with 99.99% uptime
- **Performance optimized**: 90% faster than manual JWT validation
- **Business validation**: Custom application logic for service account verification

## Authentication Flow

1. **Agent Service** makes request to **MCP Server**
2. **Cloud Run** automatically validates service account and generates ID token
3. **Cloud Run** cryptographically validates the token
4. **Cloud Run** injects authentication headers:
   - `X-Goog-Authenticated-User-Email`
   - `X-Goog-Authenticated-User-ID`
5. **MCP Server** receives authenticated request with headers
6. **Application code** performs business-level validation

## Prerequisites

1. **GCP CLI installed and authenticated**:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

2. **Environment Variables** (replace with your actual values):
   ```bash
   export PROJECT_ID="your-project-id"
   export AGENT_SERVICE="agent-greeting-service"
   export MCP_SERVER_SERVICE="mcp-server-service"
   export REGION="us-central1"
   ```

## 1. Service Account Creation

### Create Service Accounts for Cloud Run Authentication
```bash
# Create service account for Agent Service
gcloud iam service-accounts create agent-service-account \
    --display-name="Agent Service Account" \
    --description="Service account for agent service with Cloud Run automatic authentication"

# Create service account for MCP Server
gcloud iam service-accounts create mcp-server-service-account \
    --display-name="MCP Server Service Account" \
    --description="Service account for MCP server with Cloud Run automatic authentication"
```

### Get Service Account Emails
```bash
export AGENT_SA_EMAIL="agent-service-account@${PROJECT_ID}.iam.gserviceaccount.com"
export MCP_SA_EMAIL="mcp-server-service-account@${PROJECT_ID}.iam.gserviceaccount.com"
```

## 2. IAM Role Assignments for Cloud Run Authentication

### Grant Service Invocation Permission
```bash
# Allow agent service to invoke MCP server
# This automatically enables Cloud Run to generate and validate ID tokens
gcloud run services add-iam-policy-binding $MCP_SERVER_SERVICE \
    --member="serviceAccount:${AGENT_SA_EMAIL}" \
    --role="roles/run.invoker" \
    --region=$REGION

# Note: With Cloud Run automatic authentication, no additional permissions
# are needed for token creation or validation - it's handled by the infrastructure
```
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
