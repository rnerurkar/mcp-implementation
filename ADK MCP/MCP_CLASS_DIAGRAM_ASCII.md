# MCP Implementation Class Diagram (ASCII)

## Class Hierarchy and Relationships

```
                                    ┌─────────┐
                                    │   ABC   │
                                    │ (built) │
                                    └─────────┘
                                         △
                                         │ extends
                                         │
                        ┌─────────────────────────────────────┐
                        │         BaseMCPServer               │──────┐
                        │         <<abstract>>                │      │
                        │ ─────────────────────────────────── │      │ delegates to
                        │ +config: Dict[str, Any]             │      │
                        │ +input_sanitizer: InputSanitizer    │      │ ┌─────────────────────┐
                        │ +token_validator: GCTokenValidator  │      ├─│   InputSanitizer    │
                        │ +credential_manager: CredManager    │      │ │ ─────────────────── │
                        │ +context_sanitizer: ContextSanitizer│      │ │ +security_profile   │
                        │ +context_security: ContextSecurity  │      │ │ +patterns          │
                        │ +opa_client: OPAPolicyClient        │      │ │ +sanitize()        │
                        │ +installer_validator: InstValidator │      │ │ +sanitize_dict()   │
                        │ +server_registry: ServerNameRegistry│      │ └─────────────────────┘
                        │ +remote_authenticator: RemoteAuth   │      │
                        │ +tool_controller: ToolController    │      │ ┌─────────────────────┐
                        │ +semantic_validator: SemanticValid │      ├─│   SchemaValidator   │
                        │ ─────────────────────────────────── │      │ │ ─────────────────── │
                        │ +handle_request() : Dict[str, Any]  │      │ │ +schema            │
                        │ +validate_security_config()         │      │ │ +security_rules    │
                        │ +_get_tool_metadata()               │      │ │ +validate()        │
                        │ +_determine_error_phase()           │      │ │ +_apply_rules()    │
                        │ <<abstract>> +_load_tool_schema()   │      │ └─────────────────────┘
                        │ <<abstract>> +_load_security_rules()│      │
                        │ <<abstract>> +get_expected_audience │      │ ┌─────────────────────┐
                        │ <<abstract>> +validate_authorization│      ├─│GCloudTokenValidator │
                        │ <<abstract>> +fetch_data()          │      │ │ ─────────────────── │
                        │ <<abstract>> +build_context()       │      │ │ +expected_audience  │
                        └─────────────────────────────────────┘      │ │ +project_id        │
                                         △                            │ │ +validate()        │
                                         │ extends                    │ │ +_verify_token()   │
                                         │                            │ └─────────────────────┘
                        ┌─────────────────────────────────────┐      │
                        │           MCPServer                 │      │ ┌─────────────────────┐
                        │ ─────────────────────────────────── │      ├─│  OPAPolicyClient    │
                        │ +mcp: FastMCP                       │      │ │ ─────────────────── │
                        │ ─────────────────────────────────── │      │ │ +opa_url           │
                        │ +register_tools()                   │      │ │ +timeout           │
                        │ +get_fastapi_app(): FastAPI         │      │ │ +check_policy()    │
                        │ +_load_tool_schema(): Dict          │      │ │ +_make_request()   │
                        │ +_load_security_rules(): List       │      │ └─────────────────────┘
                        │ +get_expected_audience(): str       │      │
                        │ +validate_authorization()           │      │ ┌─────────────────────┐
                        │ +fetch_data(): dict                 │      ├─│InstallerSecValidator│
                        │ +build_context(): dict              │      │ │ ─────────────────── │
                        └─────────────────────────────────────┘      │ │ +trusted_registries │
                                         │                            │ │ +signature_keys     │
                                         │ contains                   │ │ +validate_integrity│
                                         ▼                            │ │ +_check_source()    │
                               ┌─────────────────┐                    │ └─────────────────────┘
                               │    FastMCP      │                    │
                               │   (external)    │                    │ ┌─────────────────────┐
                               └─────────────────┘                    ├─│ ServerNameRegistry  │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +registry_backend   │
                                                                      │ │ +namespace_sep      │
                                                                      │ │ +verify_identity()  │
                                                                      │ │ +register_server()  │
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      ├─│RemoteServerAuth     │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +trusted_ca_certs   │
                                                                      │ │ +handshake_timeout  │
                                                                      │ │ +authenticate()     │
                                                                      │ │ +_verify_cert()     │
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      ├─│ToolExposureControl  │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +policy_file        │
                                                                      │ │ +default_policy     │
                                                                      │ │ +validate_exposure()│
                                                                      │ │ +approve_exposure() │
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      ├─│SemanticMappingValid │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +semantic_models    │
                                                                      │ │ +validation_cache   │
                                                                      │ │ +validate_semantics│
                                                                      │ │ +_check_consistency│
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      ├─│  CredentialManager  │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +project_id         │
                                                                      │ │ +secret_client      │
                                                                      │ │ +get_credentials()  │
                                                                      │ │ +_get_secret()      │
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      ├─│  ContextSanitizer   │
                                                                      │ │ ─────────────────── │
                                                                      │ │ +security_level     │
                                                                      │ │ +sanitization_rules │
                                                                      │ │ +sanitize()         │
                                                                      │ │ +_remove_sensitive()│
                                                                      │ └─────────────────────┘
                                                                      │
                                                                      │ ┌─────────────────────┐
                                                                      └─│  ContextSecurity    │
                                                                        │ ─────────────────── │
                                                                        │ +kms_key_path       │
                                                                        │ +signing_strategy   │
                                                                        │ +sign()             │
                                                                        │ +verify()           │
                                                                        └─────────────────────┘

## Agent and Client Architecture

```
                        ┌─────────────────────────────────────┐
                        │         AgentService                │
                        │ ─────────────────────────────────── │
                        │ +mcp_client: BaseMCPClient          │
                        │ +model: str                         │
                        │ +name: str                          │
                        │ +instruction: str                   │
                        │ +agent: LlmAgent                    │
                        │ +toolset: MCPToolset                │
                        │ +session_service: SessionService    │
                        │ +is_initialized: bool               │
                        │ +app_name: str                      │
                        │ ─────────────────────────────────── │
                        │ +initialize(): None                 │
                        │ +greet_user(): Dict[str, Any]       │
                        │ +health_check(): Dict[str, Any]     │
                        │ +shutdown(): None                   │
                        └─────────────────────────────────────┘
                                         │
                                         │ delegates to
                                         ▼
                        ┌─────────────────────────────────────┐
                        │        BaseMCPClient                │
                        │ ─────────────────────────────────── │
                        │ +mcp_url: str                       │
                        │ +target_audience: str               │
                        │ +toolset: MCPToolset                │
                        │ +_id_token: str                     │
                        │ +_token_expires_at: float           │
                        │ ─────────────────────────────────── │
                        │ +authenticate(): None               │
                        │ +get_toolset(): Tuple[List, Toolset]│
                        │ +_is_token_expired(): bool          │
                        │ +close(): None                      │
                        └─────────────────────────────────────┘
                                         │
                                         │ invokes HTTP APIs
                                         ▼
                        ┌─────────────────────────────────────┐
                        │        MCPServer                    │
                        │        (from above)                 │
                        │ ─────────────────────────────────── │
                        │  HTTP Endpoints exposed:            │
                        │  POST /invoke                       │
                        │  GET /tools                         │
                        │  GET /health                        │
                        │  GET /prompt                        │
                        └─────────────────────────────────────┘
```
```

## Security Controls Composition (BaseMCPServer contains all of these)

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY CONTROLS                                     │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  PHASE 1: PRE-AUTHENTICATION (Fast Fail)                                       │
│  ┌─────────────────────┐  ┌─────────────────────┐                              │
│  │   InputSanitizer    │  │   SchemaValidator   │                              │
│  │ ─────────────────── │  │ ─────────────────── │                              │
│  │ +security_profile   │  │ +schema            │                              │
│  │ +patterns          │  │ +security_rules    │                              │
│  │ +sanitize()        │  │ +validate()        │                              │
│  │ +sanitize_dict()   │  │ +_apply_rules()    │                              │
│  └─────────────────────┘  └─────────────────────┘                              │
│                                                                                 │
│  PHASE 2: AUTHENTICATION & AUTHORIZATION                                        │
│  ┌─────────────────────┐  ┌─────────────────────┐                              │
│  │GCloudTokenValidator │  │  OPAPolicyClient    │                              │
│  │ ─────────────────── │  │ ─────────────────── │                              │
│  │ +expected_audience  │  │ +opa_url           │                              │
│  │ +project_id        │  │ +timeout           │                              │
│  │ +validate()        │  │ +check_policy()    │                              │
│  │ +_verify_token()   │  │ +_make_request()   │                              │
│  └─────────────────────┘  └─────────────────────┘                              │
│                                                                                 │
│  PHASE 3: INFRASTRUCTURE SECURITY                                               │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐     │
│  │InstallerSecValidator│  │ ServerNameRegistry  │  │RemoteServerAuth     │     │
│  │ ─────────────────── │  │ ─────────────────── │  │ ─────────────────── │     │
│  │ +trusted_registries │  │ +registry_backend   │  │ +trusted_ca_certs   │     │
│  │ +signature_keys     │  │ +namespace_sep      │  │ +handshake_timeout  │     │
│  │ +validate_integrity│  │ +verify_identity()  │  │ +authenticate()     │     │
│  │ +_check_source()    │  │ +register_server()  │  │ +_verify_cert()     │     │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘     │
│                                                                                 │
│  PHASE 4: TOOL-SPECIFIC SECURITY                                                │
│  ┌─────────────────────┐  ┌─────────────────────┐                              │
│  │ToolExposureControl  │  │SemanticMappingValid │                              │
│  │ ─────────────────── │  │ ─────────────────── │                              │
│  │ +policy_file        │  │ +semantic_models    │                              │
│  │ +default_policy     │  │ +validation_cache   │                              │
│  │ +validate_exposure()│  │ +validate_semantics│                              │
│  │ +approve_exposure() │  │ +_check_consistency│                              │
│  └─────────────────────┘  └─────────────────────┘                              │
│                                                                                 │
│  PHASE 5: EXECUTION & RESPONSE SECURITY                                         │
│  ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐     │
│  │  CredentialManager  │  │  ContextSanitizer   │  │  ContextSecurity    │     │
│  │ ─────────────────── │  │ ─────────────────── │  │ ─────────────────── │     │
│  │ +project_id         │  │ +security_level     │  │ +kms_key_path       │     │
│  │ +secret_client      │  │ +sanitization_rules │  │ +signing_strategy   │     │
│  │ +get_credentials()  │  │ +sanitize()         │  │ +sign()             │     │
│  │ +_get_secret()      │  │ +_remove_sensitive()│  │ +verify()           │     │
│  └─────────────────────┘  └─────────────────────┘  └─────────────────────┘     │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Exception Hierarchy

```
┌─────────────────┐
│   Exception     │
│   (built-in)    │
└─────────────────┘
         △
         │ extends
         │
┌─────────────────┐
│SecurityException│
│ ─────────────── │
│ +message        │
│ +error_code     │
│ +security_ctx   │
└─────────────────┘
         △
         │ thrown by
         │
┌─────────────────┐
│ All Security    │
│   Controls      │
└─────────────────┘
```

## Key Relationships Summary

### Inheritance (IS-A)
- `MCPServer` IS-A `BaseMCPServer`
- `BaseMCPServer` IS-A `ABC` (Abstract Base Class)
- `SecurityException` IS-A `Exception`

### Composition (HAS-A)
- `BaseMCPServer` HAS-A all 12 security controls
- `MCPServer` HAS-A `FastMCP` instance
- `AgentService` HAS-A `BaseMCPClient` instance
- `AgentService` HAS-A `LlmAgent` instance
- `AgentService` HAS-A `MCPToolset` instance

### Dependencies (USES)
- `SchemaValidator` USES `InputSanitizer`
- `ContextSecurity` USES `CredentialManager` (for KMS)
- `ToolExposureController` USES `OPAPolicyClient`
- All controls USE `SecurityException` (for errors)

### Delegation Patterns
- `AgentService` DELEGATES tool discovery to `BaseMCPClient`
- `BaseMCPClient` INVOKES HTTP APIs on `MCPServer` endpoints
- `MCPServer` DELEGATES security to `BaseMCPServer`
- `BaseMCPServer` DELEGATES protocol handling to `FastMCP`

### BaseMCPServer Security Control Delegation (Phase-based)
- `BaseMCPServer.handle_request()` DELEGATES to all 12 security controls:
  
  **Phase 1 - Pre-Authentication (Fast Fail):**
  - DELEGATES input validation to `InputSanitizer`
  - DELEGATES schema validation to `SchemaValidator`
  
  **Phase 2 - Authentication & Authorization:**
  - DELEGATES token validation to `GoogleCloudTokenValidator`
  - DELEGATES policy checking to `OPAPolicyClient`
  
  **Phase 3 - Infrastructure Security:**
  - DELEGATES integrity validation to `InstallerSecurityValidator`
  - DELEGATES identity verification to `ServerNameRegistry`
  - DELEGATES authentication to `RemoteServerAuthenticator`
  
  **Phase 4 - Tool-Specific Security:**
  - DELEGATES exposure control to `ToolExposureController`
  - DELEGATES semantic validation to `SemanticMappingValidator`
  
  **Phase 5 - Execution & Response Security:**
  - DELEGATES credential management to `CredentialManager`
  - DELEGATES context sanitization to `ContextSanitizer`
  - DELEGATES response security to `ContextSecurity`

### API Communication Flow
```
AgentService.initialize()
    ↓ delegates to
BaseMCPClient.get_toolset()
    ↓ HTTP requests to
MCPServer HTTP endpoints:
    - POST /invoke (via handle_request)
    - GET /tools
    - GET /health
    - GET /prompt
```

### Security Pipeline Flow
```
Request → [1.InputSanitizer] → [2.SchemaValidator] → [3.TokenValidator] → 
[4.OPAClient] → [5.InstallerValidator] → [6.ServerRegistry] → 
[7.RemoteAuth] → [8.ToolController] → [9.SemanticValidator] → 
[10.CredentialManager] → Tool Execution → [11.ContextSanitizer] → 
[12.ContextSecurity] → Secure Response
```

### Complete MCP Communication Flow
```
1. AgentService starts up
2. AgentService.initialize() calls BaseMCPClient.get_toolset()
3. BaseMCPClient.authenticate() gets Google Cloud ID token
4. BaseMCPClient makes HTTP requests to MCPServer endpoints
5. MCPServer.handle_request() processes through 12 security controls
6. MCPServer returns tools/responses to BaseMCPClient
7. AgentService receives toolset and initializes LlmAgent
8. User requests are processed by AgentService.greet_user()
9. LlmAgent uses tools via BaseMCPClient → MCPServer communication
```

This ASCII diagram shows the complete MCP implementation architecture with clear relationships between all classes including the Agent Service and MCP Client components, showing how agents delegate to MCP clients which invoke APIs on the secure MCP server.
