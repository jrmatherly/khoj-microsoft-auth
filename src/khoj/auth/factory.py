"""
Factory class for managing authentication providers
"""
from typing import Dict

from khoj.auth.providers import AuthProvider
from khoj.auth.providers.google import GoogleAuthProvider
from khoj.auth.providers.magic_link import MagicLinkAuthProvider
from khoj.auth.providers.microsoft import MicrosoftAuthProvider


class AuthProviderFactory:
    """Factory for creating and managing authentication providers"""
    
    _instance = None
    _providers = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AuthProviderFactory, cls).__new__(cls)
            cls._instance._initialize_providers()
        return cls._instance
    
    def _initialize_providers(self):
        """Initialize all provider instances"""
        provider_classes = [
            GoogleAuthProvider,
            MicrosoftAuthProvider,
            MagicLinkAuthProvider
        ]
        
        for provider_class in provider_classes:
            provider = provider_class()
            if provider.is_enabled:
                self._providers[provider.name] = provider
    
    def get_enabled_providers(self) -> Dict[str, AuthProvider]:
        """Get all enabled authentication providers"""
        return self._providers
    
    def get_provider(self, name: str) -> AuthProvider:
        """Get a specific provider by name"""
        return self._providers.get(name)
    
    def has_provider(self, name: str) -> bool:
        """Check if a provider is enabled"""
        return name in self._providers
