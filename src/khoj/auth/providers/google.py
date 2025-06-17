"""
Google OAuth authentication provider for Khoj.
"""
import os
from typing import Dict, Optional, Any

from authlib.integrations.starlette_client import OAuthError
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from khoj.auth.providers import AuthProvider
from khoj.database.models import KhojUser
from khoj.database.adapters import get_user_by_token, create_user_by_google_token


class GoogleAuthProvider(AuthProvider):
    """Google OAuth authentication provider"""
    
    @property
    def name(self) -> str:
        return "google"
        
    @property
    def is_enabled(self) -> bool:
        return bool(
            os.environ.get("GOOGLE_CLIENT_ID") and
            os.environ.get("GOOGLE_CLIENT_SECRET")
        )
    
    def get_template_context(self, request) -> Dict[str, Any]:
        """Get template context for this provider"""
        if not self.is_enabled:
            return {}
            
        return {
            "google_client_id": os.environ.get("GOOGLE_CLIENT_ID"),
            "google_redirect_uri": str(request.app.url_path_for("auth")),
        }
        
    async def authenticate(self, **kwargs) -> Optional[KhojUser]:
        """Authenticate a user with Google OAuth"""
        credential = kwargs.get("credential")
        if not credential:
            return None
            
        try:
            idinfo = id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                os.environ["GOOGLE_CLIENT_ID"]
            )
            
            # Get or create user from token
            user = await get_user_by_token(idinfo)
            if not user:
                user = await create_user_by_google_token(idinfo)
                
            return user
        except OAuthError:
            return None
            
    async def get_login_url(self, request, redirect_uri: str) -> str:
        """Get the Google OAuth login URL"""
        # This is handled by the Google Sign-In button on frontend for Google
        return ""
