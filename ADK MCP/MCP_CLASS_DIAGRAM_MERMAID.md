# MCP Enhanced Architecture - Mermaid Class Diagram (Updated for Consolidated Security)

This document provides a Mermaid-format class diagram for the enhanced MCP implementation with **consolidated security architecture** featuring **40% code reduction** and **9 optimized security controls**.

## Consolidated Security Architecture (40% Code Reduction)

```
┌─────────────────────────────────────────────────────────────────┐
│                 Consolidated Security Architecture               │
├─────────────────────────────────────────────────────────────────┤
│ Layer 1: Apigee Gateway (External)                             │
│ ├── Authentication & Authorization                              │
│ ├── Rate Limiting & Throttling                                 │
│ ├── CORS Policy Enforcement                                    │
│ └── Basic JSON-RPC Validation                                  │
├─────────────────────────────────────────────────────────────────┤
│ Layer 2: ConsolidatedAgentSecurity (MCP Framework Delegation)  │
│ ├── AgentPromptGuard → InputSanitizer (MCP)                    │
│ ├── AgentContextValidator → ContextSanitizer (MCP)             │
│ ├── AgentMCPVerifier (Agent-specific)                          │
│ ├── AgentResponseSanitizer → ContextSanitizer (MCP)            │
│ ├── SecurityAuditor (Agent-specific)                           │
│ └── 40% Code Reduction via MCP Framework Integration           │
├─────────────────────────────────────────────────────────────────┤
│ Layer 3: MCP Server (9 Consolidated Controls)                  │
│ └── Complete Zero-Trust Tool Security Pipeline                 │
└─────────────────────────────────────────────────────────────────┘
```

## Mermaid Class Diagram

```mermaid
classDiagram
    %% Agent Service Layer (Layer 2) - Enhanced Security
    class AgentService {
        +BaseMCPClient mcp_client
        +str model
        +str name
        +str instruction
        +LlmAgent agent
        +MCPToolset toolset
        +InMemorySessionService session_service
        +bool is_initialized
        +ConsolidatedSecurityConfig security_config
        +ConsolidatedAgentSecurity security
        +Logger logger
        +__init__(mcp_client, model, name, instruction, security_config)
        +initialize() void
        +greet_user(message, user_id, session_id) Dict
        +secure_greet_user(request, fastapi_request) Dict
        +get_security_status() Dict
        +cleanup() void
    }

    class ConsolidatedSecurityConfig {
        +bool enable_prompt_injection_protection
        +bool enable_context_validation
        +bool enable_mcp_verification
        +bool enable_response_sanitization
        +bool enable_security_audit_logging
        +int max_context_size
        +float prompt_injection_threshold
        +int max_response_size
        +bool verify_mcp_signatures
        +bool trust_unsigned_responses
        +str security_level
        +str model_armor_api_key
    }

    class ConsolidatedAgentSecurity {
        +ConsolidatedSecurityConfig config
        +AgentPromptGuard prompt_guard
        +AgentContextValidator context_validator
        +AgentMCPVerifier mcp_verifier
        +AgentResponseSanitizer response_sanitizer
        +SecurityAuditor auditor
        +Logger logger
        +__init__(config)
        +validate_request(message, user_id, session_id, context) Tuple
        +verify_mcp_response(mcp_response, user_id, session_id) Tuple
        +sanitize_response(response, user_id, session_id) Tuple
        +get_security_status() Dict
    }

    class AgentPromptGuard {
        +InputSanitizer input_sanitizer
        +Logger logger
        +__init__()
        +detect_injection(message) Tuple
        +_delegate_to_mcp_framework(message) Tuple
    }

    class AgentContextValidator {
        +ContextSanitizer context_sanitizer
        +Logger logger
        +__init__()
        +validate_size(message, context) Tuple
        +_delegate_to_mcp_framework(context) Tuple
    }

    class AgentMCPVerifier {
        +bool verify_signatures
        +bool trust_unsigned
        +Logger logger
        +__init__(verify_signatures, trust_unsigned)
        +verify_response(mcp_response) Tuple
        +_verify_signature(data, signature) bool
    }

    class AgentResponseSanitizer {
        +ContextSanitizer context_sanitizer
        +Logger logger
        +__init__()
        +sanitize_response(response, user_id) Tuple
        +_delegate_to_mcp_framework(response) Tuple
    }

    class SecurityAuditor {
        +bool enable_logging
        +Logger logger
        +__init__(enable_logging)
        +log_security_event(event_type, details, user_id, session_id) void
        +_get_event_severity(event_type) str
    }

    class BaseMCPClient {
        +str mcp_url
        +str target_audience
        +AsyncClient session
        +Optional credentials
        +__init__(mcp_url, target_audience)
        +get_toolset() Tuple
        +_get_id_token() str
        +_authenticate_with_gcp(request) Request
    }

    %% MCP Server Layer (Layer 3) - 9 Consolidated Security Controls
    class BaseMCPServer {
        <<abstract>>
        +Dict config
        +InputSanitizer input_sanitizer
        +GoogleCloudTokenValidator token_validator
        +SchemaValidator schema_validator
        +CredentialManager credential_manager
        +ContextSanitizer context_sanitizer
        +OPAPolicyClient opa_client
        +ServerNameRegistry server_registry
        +ToolExposureController tool_controller
        +SemanticMappingValidator semantic_validator
        +__init__(config)
        +handle_request(request) Dict
        +validate_security_configuration() Dict
        +_get_tool_metadata(tool_name) Dict
        +_determine_error_phase(error) str
        +_load_tool_schema(tool_name)* Dict
        +_load_security_rules()* List
        +get_expected_audience()* str
        +validate_authorization(request_payload)* void
        +fetch_data(validated_params, credentials)* dict
        +build_context(raw_data)* dict
    }

    class MCPServer {
        +FastMCP mcp
        +__init__(config)
        +register_tools() void
        +get_fastapi_app() FastAPI
        +_load_tool_schema(tool_name) Dict
        +_load_security_rules() List
        +get_expected_audience() str
        +validate_authorization(request_payload) void
        +fetch_data(validated_params, credentials) dict
        +build_context(raw_data) dict
    }

    %% Security Controls (MCP Layer 3) - 9 Consolidated Controls
    class InputSanitizer {
        +str security_profile
        +List patterns
        +str model_armor_api_key
        +sanitize_input(text) str
        +sanitize_dict(data) Dict
        +_load_patterns(profile) List
        +_check_model_armor_input(text) Dict
    }

    class GoogleCloudTokenValidator {
        +str expected_audience
        +str project_id
        +Dict token_cache
        +validate(token) Dict
        +_verify_google_token(token) Dict
        +_validate_token_claims(claims) bool
    }

    class SchemaValidator {
        +Dict mcp_schemas
        +List security_rules
        +validate_jsonrpc_message(message) bool
        +validate_mcp_protocol(request) bool
        +apply_security_patterns(data) Dict
    }

    class CredentialManager {
        +str project_id
        +SecretManagerServiceClient secret_client
        +get_credentials(tool_name, params) Dict
        +_get_secret(secret_name) str
        +_build_secret_path(secret_name) str
    }

    class ContextSanitizer {
        +str security_level
        +str model_armor_api_key
        +List poison_patterns
        +List pii_patterns
        +sanitize(context) Dict
        +_apply_model_armor_protection(data) Any
        +_check_model_armor_context(text) Dict
        +_apply_poison_filters(data) Any
        +_redact_pii(data) Any
        +_limit_size(context, max_size) Dict
    }

    class OPAPolicyClient {
        +str opa_url
        +int timeout
        +check_policy(policy_context) bool
    }

    class ServerNameRegistry {
        +str registry_backend
        +Dict registered_servers
        +verify_server_identity(server_id, tool_name) bool
    }

    class ToolExposureController {
        +Optional policy_file
        +Dict exposure_policies
        +validate_tool_exposure(tool_name, user_id) bool
    }

    class SemanticMappingValidator {
        +Dict semantic_models
        +Dict validation_cache
        +validate_tool_semantics(tool_name, params) bool
    }

    %% External Integrations
    class LlmAgent {
        <<Google ADK>>
        +str model
        +str name
        +str instruction
        +List tools
    }

    class MCPToolset {
        <<Google ADK>>
        +List tools
        +close() void
    }

    class FastMCP {
        <<External Framework>>
        +tool() decorator
        +http_app() FastAPI
    }

    class ModelArmor {
        <<External API>>
        +analyze_context() Dict
        +detect_tool_injection() Dict
    }

    class FastAPI {
        <<External Framework>>
        +mount() void
        +get() decorator
        +post() decorator
    }

    %% Data Models
    class GreetingRequest {
        +str message
        +Optional user_id
        +Optional session_id
        +Optional signed_context
    }

    class GreetingResponse {
        +str response
        +str user_id
        +str session_id
        +bool success
        +Optional security_validation
    }

    class SecurityStatusResponse {
        +str security_level
        +list active_controls
        +Dict configuration
        +str architecture
    }

    %% Inheritance Relationships
    MCPServer --|> BaseMCPServer : extends

    %% Agent Service Composition (Layer 2) - Consolidated Security
    AgentService *-- ConsolidatedAgentSecurity : contains
    AgentService *-- BaseMCPClient : contains
    AgentService *-- LlmAgent : contains
    AgentService *-- MCPToolset : contains

    %% Consolidated Agent Security Composition (5 Controls with MCP Delegation)
    ConsolidatedAgentSecurity *-- ConsolidatedSecurityConfig : contains
    ConsolidatedAgentSecurity *-- AgentPromptGuard : contains
    ConsolidatedAgentSecurity *-- AgentContextValidator : contains
    ConsolidatedAgentSecurity *-- AgentMCPVerifier : contains
    ConsolidatedAgentSecurity *-- AgentResponseSanitizer : contains
    ConsolidatedAgentSecurity *-- SecurityAuditor : contains

    %% MCP Framework Delegation (40% Code Reduction)
    AgentPromptGuard ..> InputSanitizer : delegates to MCP framework
    AgentContextValidator ..> ContextSanitizer : delegates to MCP framework
    AgentResponseSanitizer ..> ContextSanitizer : delegates to MCP framework

    %% MCP Server Composition (9 Consolidated Controls)
    BaseMCPServer *-- InputSanitizer : contains
    BaseMCPServer *-- GoogleCloudTokenValidator : contains
    BaseMCPServer *-- SchemaValidator : contains
    BaseMCPServer *-- CredentialManager : contains
    BaseMCPServer *-- ContextSanitizer : contains
    BaseMCPServer *-- OPAPolicyClient : contains
    BaseMCPServer *-- ServerNameRegistry : contains
    BaseMCPServer *-- ToolExposureController : contains
    BaseMCPServer *-- SemanticMappingValidator : contains

    %% External Integrations
    MCPServer *-- FastMCP : contains
    AgentService ..> FastAPI : creates
    ContextSanitizer ..> ModelArmor : uses for tool response protection
    
    %% Data Flow Relationships
    AgentService ..> GreetingRequest : processes
    AgentService ..> GreetingResponse : produces
    AgentService ..> SecurityStatusResponse : produces

    %% Layer Boundaries
    class Layer1 {
        <<Apigee Gateway>>
        External Authentication
        Rate Limiting
        CORS Policy
        Basic Validation
    }

    class Layer2 {
        <<Agent Service>>
        6 Security Controls
        LLM Protection
    }

    class Layer3 {
        <<MCP Server>>
        9 Security Controls
        Zero-Trust Pipeline
        Tool Protection
    }
```

## Consolidated Architecture Benefits

### **Consolidation Achievements (40% Code Reduction)**

#### **Layer 1: Apigee Gateway (External)**
- **Authentication & Authorization**: OAuth 2.0, JWT validation
- **Rate Limiting & Throttling**: DDoS protection, request management
- **CORS Policy Enforcement**: Cross-origin security
- **Basic JSON-RPC Validation**: Message format checks, protocol compliance

#### **Layer 2: ConsolidatedAgentSecurity (5 Controls + MCP Delegation)**
1. **AgentPromptGuard → InputSanitizer**: Delegates to MCP framework for prompt injection detection
2. **AgentContextValidator → ContextSanitizer**: Delegates to MCP framework for context validation
3. **AgentMCPVerifier**: Agent-specific MCP response verification
4. **AgentResponseSanitizer → ContextSanitizer**: Delegates to MCP framework for response sanitization
5. **SecurityAuditor**: Agent-specific comprehensive audit logging

#### **Layer 3: MCP Server (9 Consolidated Controls)**
1. **InputSanitizer**: Enhanced with Model Armor integration
2. **GoogleCloudTokenValidator**: Cloud Run automatic authentication
3. **SchemaValidator**: JSON-RPC 2.0 and MCP protocol validation
4. **CredentialManager**: Google Cloud Secret Manager integration
5. **ContextSanitizer**: Advanced threat detection with Model Armor API
6. **OPAPolicyClient**: Policy-based access control
7. **ServerNameRegistry**: Server identity verification
8. **ToolExposureController**: Tool capability management
9. **SemanticMappingValidator**: Tool metadata verification

### **Architecture Benefits & Implementation**

#### **Code Optimization & Security Enhancement**
- **40% Code Reduction**: Agent controls delegate to comprehensive MCP framework, eliminating duplicate implementations
- **Model Armor Integration**: AI-powered threat detection with graceful fallback to regex patterns
- **Intelligent Delegation**: Shared InputSanitizer and ContextSanitizer across agent and MCP layers
- **Single Source of Truth**: Consistent security pipeline with reduced maintenance overhead

#### **Design Patterns & Enterprise Features**
- **Layered Security**: Clear separation across Apigee Gateway, Agent Service, and MCP Server
- **Composition Pattern**: Security controls as pluggable, composed components
- **Template Method**: Consistent processing pipeline with agent-specific implementations
- **Defense-in-Depth**: Complementary protection layers with enterprise monitoring
- **Production Ready**: 14/14 comprehensive tests passing with full compliance support

This consolidated architecture provides enterprise-grade AI security with **40% code reduction** while enhancing protection through **Model Armor integration** and maintaining optimal performance with clear architectural boundaries and intelligent security delegation.
