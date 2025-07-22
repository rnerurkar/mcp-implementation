from abc import ABC, abstractmethod
import os
import json
from typing import Any, Dict, List, Optional
from fastapi import HTTPException

# Import all security controls from your notebook implementation
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
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config

        # Initialize security components
        self.input_sanitizer = InputSanitizer()
        self.token_validator = AzureTokenValidator(
            expected_audience=config["azure_audience"],
            required_scopes=config["azure_scopes"],
            issuer=config["azure_issuer"]
        )
        self.credential_manager = CredentialManager(
            project_id=config["gcp_project"]
        )
        self.context_sanitizer = ContextSanitizer(
            security_level=config.get("security_level", "standard")
        )
        self.context_security = ContextSecurity(
            kms_key_path=config.get("kms_key_path")
        )
        self.opa_client = OPAPolicyClient(
            opa_url=config["opa_url"]
        )

    # TEMPLATE METHOD (invariant sequence)
    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming request with full security pipeline.
        """
        try:
            # 1. Authentication & Authorization
            token_claims = self.token_validator.validate(request["token"])
            # 2. Sanitize input
            sanitized_input = self.input_sanitizer.sanitize(request["parameters"])
            # 3. Input validation
            input_validator = SchemaValidator(
                schema=self._load_tool_schema(request["tool_name"]),
                security_rules=self._load_security_rules()
            )
            validated_params = input_validator.validate(request["parameters"])

            # 4. Policy enforcement
            policy_context = {
                "user": token_claims["sub"],
                "tool": request["tool_name"],
                "params": validated_params
            }
            if not self.opa_client.check_policy(policy_context):
                raise PermissionError("Policy violation")

            # 5. Secure execution
            result = self.credential_manager.execute_with_credentials(
                request["tool_name"],
                validated_params
            )

            # 6. Context security
            sanitized_result = self.context_sanitizer.sanitize(result)
            signed_result = self.context_security.sign(sanitized_result)

            return {"status": "success", "data": signed_result}

        except Exception as e:
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
    def fetch_data(self, request_payload: dict):
        """
        Retrieve data from source system.
        """
        pass

    @abstractmethod
    def build_context(self, raw_data) -> dict:
        """
        Convert to agent-consumable JSON-LD format.
        """
        pass