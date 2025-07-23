from abc import ABC, abstractmethod
from typing import Any, Dict, List
from fastapi import HTTPException
from mcp_security_controls import (
    InputSanitizer,
    AzureTokenValidator,
    CredentialManager,
    ContextSanitizer,
    ContextSecurity,
    OPAPolicyClient,
    SchemaValidator,
    SecurityException
)

class BaseMCPServer(ABC):
    """
    Base MCP Server with all security controls.
    Implements a secure request processing pipeline.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Security components
        self.input_sanitizer = InputSanitizer(security_profile=config.get("input_sanitizer_profile", "default"))
        self.token_validator = AzureTokenValidator(
            expected_audience=config["azure_audience"],
            required_scopes=config["azure_scopes"],
            issuer=config["azure_issuer"]
        )
        self.credential_manager = CredentialManager(project_id=config["gcp_project"])
        self.context_sanitizer = ContextSanitizer(security_level=config.get("security_level", "standard"))
        self.context_security = ContextSecurity(kms_key_path=config.get("kms_key_path"))
        self.opa_client = OPAPolicyClient(opa_url=config["opa_url"])

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming request with full security pipeline.
        Returns a signed, sanitized context or error.
        """
        try:
            # 1. Authentication & Authorization
            token_claims = self.token_validator.validate(request["token"])

            # 2. Input Sanitization
            sanitized_params = self.input_sanitizer.sanitize(request.get("parameters", {}))

            # 3. Input Validation
            input_validator = SchemaValidator(
                schema=self._load_tool_schema(request["tool_name"]),
                security_rules=self._load_security_rules()
            )
            validated_params = input_validator.validate(sanitized_params)

            # 4. Policy Enforcement
            policy_context = {
                "user": token_claims.get("sub"),
                "tool": request["tool_name"],
                "params": validated_params
            }
            if not self.opa_client.check_policy(policy_context):
                raise PermissionError("OPA policy violation.")

            # 5. Credential Injection & Secure Execution
            credentials = self.credential_manager.get_credentials(request["tool_name"], validated_params)
            result = self.fetch_data(request["tool_name"], validated_params, credentials)

            # 6. Build Agent Context
            context = self.build_context(result)

            # 7. Context Sanitization & Signing
            sanitized_context = self.context_sanitizer.sanitize(context)
            signed_context = self.context_security.sign(sanitized_context)

            return {"status": "success", "data": signed_context}

        except Exception as e:
            # Centralized error handling
            return {"status": "error", "message": str(e)}

    @abstractmethod
    def _load_tool_schema(self, tool_name: str) -> Dict[str, Any]:
        """
        Load JSON schema for tool (to be implemented in subclass).
        """
        pass

    @abstractmethod
    def _load_security_rules(self) -> List[Dict[str, Any]]:
        """
        Load security rules (to be implemented in subclass).
        """
        pass

    @abstractmethod
    def get_expected_audience(self) -> str:
        """
        Return the expected audience for token validation.
        """
        pass

    @abstractmethod
    def validate_authorization(self, request_payload: dict):
        """
        Perform additional claim validation.
        """
        pass

    @abstractmethod
    def fetch_data(self, toolname: str, validated_params: dict, credentials: dict):
        """
        Retrieve data from source system.
        """
        pass

    @abstractmethod
    def build_context(self, raw_data: Any) -> dict:
        """
        Convert to agent-consumable JSON-LD format.
        """
        pass