"""
Microsoft Entra ID (Azure AD) user adapters
"""
import logging
from typing import Optional

from khoj.database.models import KhojUser, MicrosoftUser, Subscription

logger = logging.getLogger(__name__)


async def create_user_by_microsoft_token(token: dict) -> Optional[KhojUser]:
    """
    Creates or updates a user from a Microsoft Entra ID token

    Args:
        token: The Microsoft Entra ID token containing user info

    Returns:
        The created or updated user
    """
    # Get token fields
    try:
        sub = token.get("sub")
        email = token.get("email", "").lower()
        name = token.get("name")
        given_name = token.get("given_name")
        family_name = token.get("family_name")
        tenant_id = token.get("tid")  # Microsoft-specific Tenant ID
        picture = token.get("picture")  # May not be available in all tokens

        if not sub or not email:
            logger.error("Invalid Microsoft token: missing required fields")
            return None

        # Create KhojUser if it doesn't exist
        user, _ = await KhojUser.objects.filter(email=email).aupdate_or_create(
            defaults={"username": email, "email": email}
        )
        
        # Create/update Microsoft user data
        await MicrosoftUser.objects.filter(user=user).aupdate_or_create(
            user=user,
            defaults={
                "sub": sub,
                "email": email,
                "name": name,
                "given_name": given_name,
                "family_name": family_name,
                "tenant_id": tenant_id,
                "picture": picture,
            }
        )
        
        # Ensure user has a subscription
        subscription = await Subscription.objects.filter(user=user).afirst()
        if not subscription:
            await Subscription.objects.acreate(user=user, type=Subscription.Type.STANDARD)
            
        # Set email as verified since it's verified by Microsoft
        user.verified_email = True
        await user.asave()
        
        return user
    except Exception as e:
        logger.error(f"Error creating user from Microsoft token: {e}")
        return None


async def get_user_by_microsoft_token(token: dict) -> Optional[KhojUser]:
    """
    Get a user by Microsoft token

    Args:
        token: The Microsoft Entra ID token

    Returns:
        The user if found, None otherwise
    """
    try:
        sub = token.get("sub")
        email = token.get("email", "").lower()
        
        if not sub or not email:
            logger.error("Invalid Microsoft token: missing required fields")
            return None
        
        # Try to find user by sub (Microsoft ID)
        microsoft_user = await MicrosoftUser.objects.filter(sub=sub).afirst()
        if microsoft_user:
            return microsoft_user.user
            
        # Try to find by email as fallback
        user = await KhojUser.objects.filter(email=email).afirst()
        return user
    except Exception as e:
        logger.error(f"Error getting user from Microsoft token: {e}")
        return None
