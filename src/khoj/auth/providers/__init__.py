"""
Authentication provider interface and classes for Khoj.
"""
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any

from khoj.database.models import KhojUser

class AuthProvider(ABC):
    """Base class for authentication providers"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the auth provider"""
        pass
        
    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if provider is enabled based on env vars"""
        pass
    
    @abstractmethod
    def get_template_context(self, request) -> Dict[str, Any]:
        """Get template context for this provider to be used in the login page"""
        pass
        
    @abstractmethod
    async def authenticate(self, **kwargs) -> Optional['KhojUser']:
        """Authenticate a user with this provider"""
        pass
        
    @abstractmethod
    async def get_login_url(self, request, redirect_uri: str) -> str:
        """Get the URL to redirect to for login"""
        pass
