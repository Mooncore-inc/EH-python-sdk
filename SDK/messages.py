"""
Message handling for Event Horizon SDK
"""

import aiohttp
from typing import List, Dict, Any, Optional
from exceptions import NetworkError, ValidationError, CryptoError
from models import Message
from crypto import CryptoManager


class MessageManager:
    """Manages message operations"""
    
    def __init__(self, config, crypto_manager: CryptoManager):
        """
        Initialize message manager
        
        :param config: Client configuration
        :param crypto_manager: Crypto manager instance
        """
        self.config = config
        self.crypto_manager = crypto_manager
    
    async def send_private_message(self, 
                                  recipient_did: str, 
                                  message: str) -> Optional[Message]:
        """
        Send encrypted private message
        
        :param recipient_did: Recipient's DID
        :param message: Plaintext message to send
        :return: Message object if successful, None otherwise
        """
        if not self.config.did:
            raise ValidationError("DID is required for sending messages")
        
        if not recipient_did:
            raise ValidationError("Recipient DID is required")
        
        if not message:
            raise ValidationError("Message content is required")
        
        # Get recipient's public key
        from keys import KeyManager
        key_manager = KeyManager(self.config, self.crypto_manager)
        recipient_key_info = await key_manager.get_public_key(recipient_did)
        
        if not recipient_key_info:
            raise ValidationError(f"Public key not found for recipient: {recipient_did}")
        
        try:
            # Encrypt message
            encrypted_data = self.crypto_manager.encrypt_message(
                message, 
                recipient_key_info.public_key.encode()
            )
            
            # Send encrypted message
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.api_base_url}/messages/send",
                    json={
                        "sender_did": self.config.did,
                        "recipient_did": recipient_did,
                        "encrypted_key": encrypted_data["encrypted_key"],
                        "iv": encrypted_data["iv"],
                        "ciphertext": encrypted_data["ciphertext"]
                    },
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return Message.from_dict(data)
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to send message: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
        except CryptoError as e:
            raise CryptoError(f"Encryption failed: {str(e)}")
        except aiohttp.ClientError as e:
            raise NetworkError(f"Network error sending message: {str(e)}")
    
    async def get_private_messages(self, 
                                   limit: int = 100, 
                                   offset: int = 0) -> List[Message]:
        """
        Get private messages for the current user
        
        :param limit: Maximum number of messages to retrieve
        :param offset: Number of messages to skip
        :return: List of Message objects
        """
        if not self.config.did:
            raise ValidationError("DID is required for retrieving messages")
        
        if limit < 1 or limit > 1000:
            raise ValidationError("Limit must be between 1 and 1000")
        
        if offset < 0:
            raise ValidationError("Offset must be non-negative")
        
        async with aiohttp.ClientSession() as session:
            try:
                params = {"limit": limit, "offset": offset}
                async with session.get(
                    f"{self.config.api_base_url}/messages/{self.config.did}",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        messages = data.get("messages", [])
                        return [Message.from_dict(msg) for msg in messages]
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get messages: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting messages: {str(e)}")
    
    def decrypt_message(self, 
                       encrypted_key_b64: str, 
                       iv_b64: str, 
                       ciphertext_b64: str) -> str:
        """
        Decrypt received message
        
        :param encrypted_key_b64: Base64 encoded encrypted session key
        :param iv_b64: Base64 encoded initialization vector
        :param ciphertext_b64: Base64 encoded encrypted message
        :return: Decrypted plaintext message
        """
        try:
            return self.crypto_manager.decrypt_message(
                encrypted_key_b64, 
                iv_b64, 
                ciphertext_b64
            )
        except CryptoError as e:
            raise CryptoError(f"Decryption failed: {str(e)}")
    
    async def get_message_history(self, 
                                 target_did: str, 
                                 limit: int = 100, 
                                 offset: int = 0) -> List[Message]:
        """
        Get message history with a specific user
        
        :param target_did: Target user's DID
        :param limit: Maximum number of messages to retrieve
        :param offset: Number of messages to skip
        :return: List of Message objects
        """
        if not self.config.did:
            raise ValidationError("DID is required for retrieving message history")
        
        if not target_did:
            raise ValidationError("Target DID is required")
        
        # Get all messages and filter by sender/recipient
        all_messages = await self.get_private_messages(limit=1000, offset=0)
        
        # Filter messages between the two users
        filtered_messages = []
        for msg in all_messages:
            if ((msg.sender_did == self.config.did and msg.recipient_did == target_did) or
                (msg.sender_did == target_did and msg.recipient_did == self.config.did)):
                filtered_messages.append(msg)
        
        # Sort by timestamp (newest first)
        filtered_messages.sort(key=lambda x: x.timestamp, reverse=True)
        
        # Apply pagination
        start = offset
        end = start + limit
        return filtered_messages[start:end]
    
    async def delete_message(self, message_id: str) -> bool:
        """
        Delete a specific message
        
        :param message_id: ID of the message to delete
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for deleting messages")
        
        if not message_id:
            raise ValidationError("Message ID is required")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.delete(
                    f"{self.config.api_base_url}/messages/{message_id}",
                    json={"did": self.config.did},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to delete message: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error deleting message: {str(e)}")
    
    async def mark_message_as_read(self, message_id: str) -> bool:
        """
        Mark a message as read
        
        :param message_id: ID of the message to mark as read
        :return: True if successful
        """
        if not self.config.did:
            raise ValidationError("DID is required for marking messages as read")
        
        if not message_id:
            raise ValidationError("Message ID is required")
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.config.api_base_url}/messages/{message_id}/read",
                    json={"did": self.config.did},
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to mark message as read: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error marking message as read: {str(e)}")
    
    def get_unread_count(self, messages: List[Message]) -> int:
        """
        Get count of unread messages
        
        :param messages: List of messages to check
        :return: Number of unread messages
        """
        if not self.config.did:
            return 0
        
        unread_count = 0
        for msg in messages:
            if (msg.recipient_did == self.config.did and 
                hasattr(msg, 'is_read') and not msg.is_read):
                unread_count += 1
        
        return unread_count
