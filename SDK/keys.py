"""
Key management and authentication for Event Horizon SDK
"""

import os
import aiohttp
from typing import Optional, Dict, Any
from exceptions import AuthenticationError, NetworkError, ValidationError
from models import KeyInfo, TokenInfo
from crypto import CryptoManager


class KeyManager:
    """Manages cryptographic keys and authentication"""
    
    def __init__(self, config, crypto_manager: CryptoManager):
        """
        Initialize key manager
        
        :param config: Client configuration
        :param crypto_manager: Crypto manager instance
        """
        self.config = config
        self.crypto_manager = crypto_manager
        self._ensure_keys_dir()
    
    def _ensure_keys_dir(self):
        """Ensure keys directory exists"""
        os.makedirs(self.config.keys_dir, exist_ok=True)
    
    def _get_key_path(self, key_type: str) -> str:
        """Get path for key file"""
        return os.path.join(self.config.keys_dir, f"{self.config.did}_{key_type}.pem")
    
    def load_or_generate_keys(self) -> None:
        """Load existing keys or generate new ones"""
        private_key_path = self._get_key_path('private')
        public_key_path = self._get_key_path('public')
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()
            with open(public_key_path, 'rb') as f:
                public_key_pem = f.read()
            
            self.crypto_manager.load_private_key(private_key_pem)
            self.crypto_manager.load_public_key(public_key_pem)
        else:
            # Generate new keys
            private_key_pem, public_key_pem = self.crypto_manager.generate_key_pair()
            self._save_keys(private_key_pem, public_key_pem)
    
    def _save_keys(self, private_key_pem: bytes, public_key_pem: bytes) -> None:
        """Save keys to filesystem"""
        try:
            with open(self._get_key_path('private'), 'wb') as f:
                f.write(private_key_pem)
            with open(self._get_key_path('public'), 'wb') as f:
                f.write(public_key_pem)
        except Exception as e:
            raise ValidationError(f"Failed to save keys: {str(e)}")
    
    async def exchange_public_key(self) -> bool:
        """
        Exchange public key with server
        
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for key exchange")
        
        public_key_pem = self.crypto_manager.get_public_key_pem()
        if not public_key_pem:
            raise ValidationError("Public key not available")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/exchange",
                    json={
                        "did": self.config.did,
                        "public_key": public_key_pem.decode()
                    },
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Key exchange failed: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error during key exchange: {str(e)}")
    
    async def get_public_key(self, target_did: str) -> Optional[KeyInfo]:
        """
        Get public key for another user
        
        :param target_did: Target user's DID
        :return: KeyInfo object or None if not found
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/keys/{target_did}",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return KeyInfo.from_dict(data)
                    elif response.status == 404:
                        return None
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to get public key: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting public key: {str(e)}")
    
    async def get_jwt_token(self) -> str:
        """
        Get JWT token for WebSocket authentication
        
        :return: JWT access token
        """
        if not self.config.did:
            raise ValidationError("DID is required for token generation")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/{self.config.did}/token",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["access_token"]
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to get JWT token: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting JWT token: {str(e)}")
    
    async def get_hmac_signature(self) -> Dict[str, str]:
        """
        Get HMAC signature for WebSocket authentication
        
        :return: Dictionary with signature and timestamp
        """
        if not self.config.did:
            raise ValidationError("DID is required for signature generation")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/{self.config.did}/signature",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to get HMAC signature: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting HMAC signature: {str(e)}")
    
    async def revoke_public_key(self) -> bool:
        """
        Revoke public key
        
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for key revocation")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.delete(
                    f"{self.config.api_base_url}/keys/{self.config.did}",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to revoke public key: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error revoking public key: {str(e)}")
    
    async def revoke_jwt_token(self, token: str) -> bool:
        """
        Revoke JWT token
        
        :param token: JWT token to revoke
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for token revocation")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/{self.config.did}/revoke-token",
                    json={"token": token},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to revoke JWT token: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error revoking JWT token: {str(e)}")
    
    async def blacklist_jwt_token(self, token: str) -> bool:
        """
        Blacklist JWT token
        
        :param token: JWT token to blacklist
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for token blacklisting")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/{self.config.did}/blacklist-token",
                    json={"token": token},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to blacklist JWT token: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error blacklisting JWT token: {str(e)}")
    
    async def get_token_info(self, token: str) -> TokenInfo:
        """
        Get information about JWT token
        
        :param token: JWT token to inspect
        :return: TokenInfo object
        """
        if not self.config.did:
            raise ValidationError("DID is required for token inspection")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/keys/{self.config.did}/token-info",
                    json={"token": token},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return TokenInfo.from_dict(data)
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to get token info: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting token info: {str(e)}")
    
    async def get_key_rotation_info(self) -> Dict[str, Any]:
        """
        Get information about key rotation
        
        :return: Key rotation information
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/keys/key-rotation/info",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_data = await response.json()
                        raise AuthenticationError(
                            f"Failed to get key rotation info: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting key rotation info: {str(e)}")
