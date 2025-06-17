"""
Magic Link authentication provider for Khoj.
"""
import os
from typing import Dict, Optional, Any

from fastapi import Request

from khoj.auth.providers import AuthProvider
from khoj.database.models import KhojUser
from khoj.database.adapters import aget_or_create_user_by_email
from khoj.routers.email import send_magic_link_email
from khoj.utils.helpers import in_debug_mode
from khoj.utils import state


class MagicLinkAuthProvider(AuthProvider):
    """Email Magic Link authentication provider"""
    
    @property
    def name(self) -> str:
        return "magic_link"
        
    @property
    def is_enabled(self) -> bool:
        # Magic links require RESEND_API_KEY to send emails
        return bool(os.environ.get("RESEND_API_KEY"))
    
    def get_template_context(self, request) -> Dict[str, Any]:
        """Get template context for this provider"""
        return {}  # No special context needed for magic links
        
    async def authenticate(self, **kwargs) -> Optional[KhojUser]:
        """Authenticate a user with Magic Link - validate verification code"""
        code = kwargs.get("code")
        email = kwargs.get("email")
        if not code or not email:
            return None
            
        from khoj.database.adapters import aget_user_validated_by_email_verification_code
        user, code_is_expired = await aget_user_validated_by_email_verification_code(code, email)
        
        if not user:
            return None
        
        if code_is_expired:
            return None
            
        return user
            
    async def get_login_url(self, request, redirect_uri: str) -> str:
        """Magic links don't have a login URL - they're sent via email"""
        return ""
    
    async def send_magic_link(self, email: str, request: Request) -> bool:
        """Send a magic link to the provided email"""
        # Get/create user if valid email address
        check_deliverability = state.billing_enabled and not in_debug_mode()
        user, _ = await aget_or_create_user_by_email(email, check_deliverability=check_deliverability)
        
        if not user:
            return False
            
        # Send email with magic link
        unique_id = user.email_verification_code
        await send_magic_link_email(user.email, unique_id, request.base_url)
        return True
