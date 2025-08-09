# MCP Enhanced Security Sequence Diagram with Template Method Pattern

This document provides sequence diagrams showing the complete end-to-end flow through the enhanced 3-layer MCP security architecture with **Template Method design pattern**, including Model Armor integration and comprehensive security controls.

## Enhanced 3-Layer Security Flow with Template Method

```
┌─────────────────────────────────────────────────────────────────┐
│              Template Method Security Flow Overview              │
├─────────────────────────────────────────────────────────────────┤
│ User → Apigee Gateway → BaseAgentService → EnhancedAgentService  │
│        (Layer 1)       (Template Method)   (Concrete Agent)     │
│                              ↓                    ↓             │
│                    OptimizedSecurity      Google ADK/LLM        │
│                        ↓                         ↓              │
│                   MCP Server → Tools      Agent Response        │
│                   (Layer 3)                                     │
├─────────────────────────────────────────────────────────────────┤
│ Security Controls Applied via Template Method:                  │
│ • Layer 1: 4 Gateway Controls (Authentication/Rate Limiting)    │
│ • Layer 2: 4 Agent Controls (Template Method Orchestrated)     │
│   - Pre-processing: Prompt injection + Context validation      │
│   - Post-processing: MCP verification + Response sanitization  │
│ • Layer 3: 12 MCP Server Controls (Tool-specific)              │
│ • Total: 20 Security Controls with Template Method Pattern     │
└─────────────────────────────────────────────────────────────────┘
```

## Template Method Security Sequence Diagram

```mermaid
sequenceDiagram
    participant User as 👤 User
    participant Apigee as 🛡️ Apigee Gateway<br/>(Layer 1 - 4 Controls)
    participant FastAPI as 🌐 FastAPI Endpoint
    participant BaseAgent as 🏛️ BaseAgentService<br/>(Template Method)
    participant Security as 🔒 OptimizedAgentSecurity<br/>(4 Agent Controls)
    participant EnhancedAgent as 🤖 EnhancedAgentService<br/>(Concrete Implementation)
    participant ADK as 🧠 Google ADK<br/>(LLM Agent + Runner)
    participant MCPClient as 🔗 BaseMCPClient<br/>(Tool Discovery)
    participant MCPServer as 🛠️ MCP Server<br/>(Layer 3 - 12 Controls)
    participant Tools as ⚙️ External Tools

    %% Initial Request Flow
    User->>Apigee: POST /greet {message, user_id, session_id}
    
    Note over Apigee: Layer 1 Security (4 Controls)
    Apigee->>Apigee: 1. Authentication & Authorization
    Apigee->>Apigee: 2. Rate Limiting & Throttling  
    Apigee->>Apigee: 3. CORS Policy Enforcement
    Apigee->>Apigee: 4. Basic Input Validation
    
    alt Layer 1 Security Fails
        Apigee-->>User: 401/429/403 Response
    else Layer 1 Security Passes
        Apigee->>FastAPI: Forward Request
        FastAPI->>BaseAgent: process_request(request, fastapi_request)
        
        %% Template Method Pattern Orchestration
        Note over BaseAgent: Template Method Pattern Begins
        
        %% Phase 1: Request Security Validation (Template Method Hook)
        BaseAgent->>BaseAgent: _validate_request_security()
        BaseAgent->>Security: validate_request(message, user_id, session_id, context)
        
        Note over Security: Agent Security Controls (4 Controls)
        Security->>Security: 1. Prompt Injection Detection
        Security->>Security: 2. Context Size Validation
        Security->>Security: 3. Input Sanitization
        Security->>Security: 4. User Session Verification
        
        Security-->>BaseAgent: (is_valid, validation_results, violations)
        
        alt Request Security Validation Fails
            BaseAgent->>BaseAgent: _handle_security_violation(violations)
            BaseAgent-->>FastAPI: HTTPException(400, "Security violation")
            FastAPI-->>User: Error Response with Details
        else Request Security Validation Passes
            
            %% Phase 2: Agent Processing (Abstract Method Implementation)
            BaseAgent->>EnhancedAgent: _process_agent_request(message, user_id, session_id, context, validation_context)
            
            Note over EnhancedAgent: Concrete Implementation Begins
            
            %% Google ADK Agent Execution
            EnhancedAgent->>ADK: runner.run_async(user_id, session_id, message)
            
            Note over ADK: Google ADK Processing
            ADK->>ADK: Initialize LLM Session
            ADK->>ADK: Process User Message
            ADK->>ADK: Determine Tool Requirements
            
            %% MCP Tool Discovery and Execution
            alt Tools Required
                ADK->>MCPClient: Request available tools
                MCPClient->>MCPServer: Tool discovery request
                
                Note over MCPServer: Layer 3 Security (12 Controls)
                MCPServer->>MCPServer: 1-4. Authentication & Authorization
                MCPServer->>MCPServer: 5-8. Input Validation & Sanitization  
                MCPServer->>MCPServer: 9-12. Tool Execution & Response Security
                
                MCPServer->>Tools: Execute requested tools
                Tools-->>MCPServer: Tool results
                MCPServer-->>MCPClient: Secured tool results
                MCPClient-->>ADK: Tool results
            end
            
            ADK->>ADK: Generate Agent Response
            ADK-->>EnhancedAgent: agent_response
            EnhancedAgent-->>BaseAgent: agent_result
            
            %% Phase 3: Response Security Validation (Template Method Hook)
            BaseAgent->>BaseAgent: _validate_response_security(agent_result, user_id, session_id)
            BaseAgent->>Security: verify_mcp_response(agent_result)
            
            Note over Security: Post-Processing Security
            Security->>Security: 5. MCP Response Verification
            Security->>Security: 6. Response Content Sanitization
            Security->>Security: 7. Output Content Filtering
            Security->>Security: 8. Metadata Validation
            
            Security-->>BaseAgent: verification_results
            
            alt Response Security Validation Fails
                BaseAgent->>BaseAgent: _handle_security_violation(violations)
                BaseAgent-->>FastAPI: HTTPException(500, "Response security violation")
                FastAPI-->>User: Error Response
            else Response Security Validation Passes
                
                %% Phase 4: Final Response Preparation (Template Method Hook)
                BaseAgent->>BaseAgent: _prepare_final_response(verified_result, user_id, session_id)
                BaseAgent-->>FastAPI: GreetingResponse{response, user_id, session_id, success, security_validation}
                FastAPI-->>User: Final Secure Response
            end
        end
    end
```

## Template Method Pattern Security Flow

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant Template as BaseAgentService<br/>(Template Method)
    participant Concrete as EnhancedAgentService<br/>(Concrete Implementation)
    participant Security as OptimizedAgentSecurity
    participant Agent as Google ADK LLM

    Note over Template: Template Method Pattern Controls Security Flow
    
    Client->>Template: process_request(request, fastapi_request)
    
    %% Template Method Orchestration
    Template->>Template: 1. _validate_request_security()
    Template->>Security: validate_request(message, user_id, session_id, context)
    Security-->>Template: (is_valid, validation_results)
    
    alt Security Check Fails
        Template->>Template: _handle_security_violation()
        Template-->>Client: Security Error Response
    else Security Check Passes
        Template->>Concrete: 2. _process_agent_request() [Abstract Method]
        
        Note over Concrete: Concrete Implementation Logic
        Concrete->>Agent: Execute agent pipeline
        Agent-->>Concrete: Agent response
        Concrete-->>Template: Processing results
        
        Template->>Template: 3. _validate_response_security()
        Template->>Security: verify_mcp_response() + sanitize_response()
        Security-->>Template: Validated response
        
        Template->>Template: 4. _prepare_final_response()
        Template-->>Client: Final secure response
    end
    
    Note over Template,Concrete: Template Method ensures consistent security<br/>across all agent implementations
```

## Security Control Distribution

### Layer 1: Apigee Gateway (4 Controls)
```mermaid
graph LR
    A[Client Request] --> B[Authentication]
    B --> C[Rate Limiting]
    C --> D[CORS Policy]
    D --> E[Input Validation]
    E --> F[Forward to Agent Service]
    
    style B fill:#ff9999
    style C fill:#ff9999  
    style D fill:#ff9999
    style E fill:#ff9999
```

### Layer 2: Template Method Security (4 Controls)
```mermaid
graph TB
    A[BaseAgentService.process_request] --> B[_validate_request_security]
    B --> C[Prompt Injection Detection]
    B --> D[Context Size Validation]
    E[_validate_response_security] --> F[MCP Response Verification]
    E --> G[Response Sanitization]
    
    H[_process_agent_request] --> I[EnhancedAgentService Implementation]
    
    A --> B
    B --> H
    H --> E
    E --> J[_prepare_final_response]
    
    style C fill:#99ccff
    style D fill:#99ccff
    style F fill:#99ccff
    style G fill:#99ccff
```

### Layer 3: MCP Server (12 Controls)
```mermaid
graph TB
    A[MCP Request] --> B[Authentication Group]
    A --> C[Validation Group]
    A --> D[Execution Group]
    
    B --> B1[Client Authentication]
    B --> B2[Token Validation]
    B --> B3[Permission Check]
    B --> B4[Session Verification]
    
    C --> C1[Request Schema Validation]
    C --> C2[Parameter Sanitization]
    C --> C3[Content Type Verification]
    C --> C4[Size Limit Enforcement]
    
    D --> D1[Tool Execution Isolation]
    D --> D2[Resource Limit Enforcement]
    D --> D3[Output Sanitization]
    D --> D4[Response Signing]
    
    style B1 fill:#99ff99
    style B2 fill:#99ff99
    style B3 fill:#99ff99
    style B4 fill:#99ff99
    style C1 fill:#ffcc99
    style C2 fill:#ffcc99
    style C3 fill:#ffcc99
    style C4 fill:#ffcc99
    style D1 fill:#cc99ff
    style D2 fill:#cc99ff
    style D3 fill:#cc99ff
    style D4 fill:#cc99ff
```

## Template Method Benefits

### 1. Consistent Security Enforcement
- **Single Point of Control**: All security logic consolidated in BaseAgentService
- **Template Method Orchestration**: process_request() ensures identical security pipeline for all implementations
- **Abstract Method Contracts**: Concrete implementations focus only on agent-specific logic

### 2. Easy Extension for New Agent Types
```mermaid
classDiagram
    class BaseAgentService {
        +process_request()
        +_validate_request_security()
        +_validate_response_security()
    }
    
    class EnhancedAgentService {
        +Google ADK Integration
    }
    
    class ChatGPTAgentService {
        +OpenAI Integration
    }
    
    class ClaudeAgentService {
        +Anthropic Integration
    }
    
    BaseAgentService <|-- EnhancedAgentService
    BaseAgentService <|-- ChatGPTAgentService
    BaseAgentService <|-- ClaudeAgentService
    
    note for BaseAgentService "Same security template\nfor all implementations"
```

### 3. Performance Characteristics
- **Security Overhead**: ~4-6ms per request via optimized template pipeline
- **Template Method Efficiency**: Single security validation cycle for all agent types
- **Parallel Processing**: Security validation can run concurrently with agent initialization

### 4. Development Benefits
- **Separation of Concerns**: Security logic completely isolated from business logic
- **Testing Strategy**: Security and agent logic can be unit tested independently
- **Maintenance**: Security updates automatically apply to all agent implementations
- **Code Reuse**: New agent implementations inherit complete security framework

## Error Handling Flow

```mermaid
sequenceDiagram
    participant BaseAgent as BaseAgentService
    participant Security as OptimizedAgentSecurity
    participant Client as Client

    BaseAgent->>Security: validate_request()
    
    alt Prompt Injection Detected
        Security-->>BaseAgent: (False, violations=["prompt_injection"])
        BaseAgent->>BaseAgent: _handle_security_violation()
        BaseAgent-->>Client: HTTPException(400, "Prompt injection detected")
    
    else Context Size Exceeded
        Security-->>BaseAgent: (False, violations=["context_size_exceeded"])
        BaseAgent->>BaseAgent: _handle_security_violation()
        BaseAgent-->>Client: HTTPException(413, "Context too large")
    
    else MCP Response Invalid
        Security-->>BaseAgent: (False, violations=["mcp_verification_failed"])
        BaseAgent->>BaseAgent: _handle_security_violation()
        BaseAgent-->>Client: HTTPException(500, "Tool response verification failed")
    
    else All Validations Pass
        Security-->>BaseAgent: (True, validation_results)
        BaseAgent->>BaseAgent: Continue processing
    end
```

This Template Method pattern provides enterprise-grade security consistency while maintaining the flexibility to support any LLM agent implementation. The pattern ensures that security controls are always applied in the correct order and with consistent behavior across all agent types.
