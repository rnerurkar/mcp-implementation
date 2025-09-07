## 🔑 Key Points

| Aspect | Description |
|--------|-------------|
| 🆔 **Session ID Management** | Generated once by Agent and used consistently to maintain state |
| 🔐 **OAuth 2.1 with PKCE** | MCP server implements full PKCE flow (code_verifier + code_challenge) for security |
| 🌐 **Manual Authentication** | **CRITICAL**: User must manually open browser and complete OAuth (Agent cannot render interactive links) |
| 💬 **User Confirmation Required** | User must return to Agent and confirm "authentication complete" before retry |
| 🔄 **Manual Retry Trigger** | Agent retries original request only after user confirmation (no automatic retry) |
| 🛡️ **PKCE Security** | Prevents authorization code interception; cryptographically binds auth request to token exchange |
| � **State Parameter** | CSRF protection that links OAuth callback to original Agent session |
