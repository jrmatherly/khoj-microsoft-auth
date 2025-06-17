"""
Microsoft Entra ID / Azure AD authentication provider for Khoj.
"""
import os
from typing import Dict, Optional, Any

import msal

from khoj.auth.providers import AuthProvider
from khoj.database.models import KhojUser


class MicrosoftAuthProvider(AuthProvider):
    """Microsoft Entra ID / Azure AD authentication provider"""
    
    @property
    def name(self) -> str:
        return "microsoft"
        
    @property
    def is_enabled(self) -> bool:
        return bool(
            os.environ.get("MICROSOFT_CLIENT_ID") and
            os.environ.get("MICROSOFT_CLIENT_SECRET")
        )
        
    @property
    def tenant_id(self) -> Optional[str]:
        """Get the Microsoft tenant ID from environment variables"""
        return os.environ.get("MICROSOFT_TENANT_ID", "common")
    
    def get_template_context(self, request) -> Dict[str, Any]:
        """Get template context for this provider"""
        if not self.is_enabled:
            return {}
            
        return {
            "microsoft_client_id": os.environ.get("MICROSOFT_CLIENT_ID"),
            "microsoft_redirect_uri": str(request.app.url_path_for("microsoft_auth")),
        }
        
    async def authenticate(self, **kwargs) -> Optional[KhojUser]:
        """Authenticate a user with Microsoft Entra ID"""
        request = kwargs.get("request")
        token = kwargs.get("token")
        if not request or not token:
            return None
            
        try:
            # Create MSAL confidential client application
            authority = f"https://login.microsoftonline.com/{self.tenant_id}"
            app = msal.ConfidentialClientApplication(
                client_id=os.environ.get("MICROSOFT_CLIENT_ID"),
                client_credential=os.environ.get("MICROSOFT_CLIENT_SECRET"),
                authority=authority
            )
            
            # Verify the token
            claims = app.verify_token(token)
            if not claims:
                return None
                
            # This still ultimately needs to be handled in the auth router
            # where we have access to the database adapters
            return None
        except Exception:
            return None
            
    async def get_login_url(self, request, redirect_uri: str) -> str:
        """Get the Microsoft OAuth login URL"""
        # This will be implemented in the auth router where we have access to oauth
        return str(request.app.url_path_for("microsoft_login"))
