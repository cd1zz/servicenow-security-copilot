"""
Azure Key Vault configuration for secure credential management
"""

import os
import logging
from typing import Optional
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)


class KeyVaultConfig:
    """Manages Azure Key Vault integration for credentials."""
    
    def __init__(self, keyvault_url: Optional[str] = None):
        """
        Initialize Key Vault client.
        
        Args:
            keyvault_url: URL of the Key Vault (e.g., https://myvault.vault.azure.net/)
                         If not provided, will try to get from environment
        """
        self.keyvault_url = keyvault_url or os.environ.get('KEY_VAULT_URL')
        self.client = None
        
        if self.keyvault_url:
            try:
                # Try managed identity first (for Azure deployment)
                credential = ManagedIdentityCredential()
                self.client = SecretClient(
                    vault_url=self.keyvault_url,
                    credential=credential
                )
                logger.info("Initialized Key Vault client with Managed Identity")
            except Exception as e:
                logger.warning(f"Managed Identity failed, trying DefaultAzureCredential: {e}")
                try:
                    # Fall back to DefaultAzureCredential (works locally and in Azure)
                    credential = DefaultAzureCredential()
                    self.client = SecretClient(
                        vault_url=self.keyvault_url,
                        credential=credential
                    )
                    logger.info("Initialized Key Vault client with DefaultAzureCredential")
                except Exception as e:
                    logger.error(f"Failed to initialize Key Vault client: {e}")
                    self.client = None
    
    def get_secret(self, secret_name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get secret from Key Vault or environment variable.
        
        Args:
            secret_name: Name of the secret in Key Vault
            default: Default value if secret not found
        
        Returns:
            Secret value or default
        """
        # First try environment variable
        env_value = os.environ.get(secret_name)
        if env_value:
            return env_value
        
        # Then try Key Vault
        if self.client:
            try:
                secret = self.client.get_secret(secret_name)
                return secret.value
            except Exception as e:
                logger.warning(f"Failed to get secret {secret_name} from Key Vault: {e}")
        
        return default
    
    def get_servicenow_credentials(self) -> dict:
        """
        Get ServiceNow credentials from Key Vault or environment variables.
        
        Returns:
            Dictionary with ServiceNow credentials
        
        Raises:
            ValueError if required credentials are missing
        """
        credentials = {
            'instance_url': self.get_secret('SERVICENOW-INSTANCE-URL') or 
                          self.get_secret('SERVICENOW_INSTANCE_URL'),
            'client_id': self.get_secret('SERVICENOW-CLIENT-ID') or 
                        self.get_secret('SERVICENOW_CLIENT_ID'),
            'client_secret': self.get_secret('SERVICENOW-CLIENT-SECRET') or 
                            self.get_secret('SERVICENOW_CLIENT_SECRET'),
            'username': self.get_secret('SERVICENOW-USERNAME') or 
                       self.get_secret('SERVICENOW_USERNAME'),
            'password': self.get_secret('SERVICENOW-PASSWORD') or 
                       self.get_secret('SERVICENOW_PASSWORD')
        }
        
        # Check if all credentials are present
        missing = [k for k, v in credentials.items() if not v]
        if missing:
            raise ValueError(f"Missing ServiceNow credentials: {', '.join(missing)}")
        
        return credentials
    
    def get_api_key(self) -> Optional[str]:
        """
        Get API key for function authentication.
        
        Returns:
            API key or None if not configured
        """
        return self.get_secret('API-KEY') or self.get_secret('API_KEY')