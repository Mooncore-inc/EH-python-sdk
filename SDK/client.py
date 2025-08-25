"""
Main Event Horizon SDK client
"""

import logging
import asyncio
from typing import Optional, Callable, Dict, Any
from config import ClientConfig
from crypto import CryptoManager
from keys import KeyManager
from messages import MessageManager
from websocket import WebSocketClient
from system import SystemManager
from exceptions import (
    EventHorizonError,
    ConfigurationError,
    AuthenticationError,
    NetworkError
)


class EventHorizonClient:
    """
    Main Event Horizon SDK client
    
    This client provides a unified interface for all Event Horizon operations:
    - Key management and authentication
    - Message sending and receiving
    - Real-time WebSocket communication
    - System monitoring and statistics
    
    Usage:
        # Basic usage
        client = EventHorizonClient(did="user123")
        await client.initialize()
        
        # Send message
        await client.send_message("recipient456", "Hello secure world!")
        
        # Get messages
        messages = await client.get_messages()
        
        # Real-time messaging
        await client.start_realtime()
        client.on_message = lambda sender, msg, timestamp: print(f"{sender}: {msg}")
    """
    
    def __init__(self, 
                 did: Optional[str] = None,
                 config: Optional[ClientConfig] = None,
                 logger: Optional[logging.Logger] = None):
        """
        Initialize Event Horizon client
        
        :param did: User's decentralized identifier
        :param config: Client configuration (optional)
        :param logger: Custom logger (optional)
        """
        # Setup configuration
        if config:
            self.config = config
            if did:
                self.config.did = did
        else:
            self.config = ClientConfig(did=did)
        
        # Validate configuration
        try:
            self.config.validate()
        except ValueError as e:
            raise ConfigurationError(str(e))
        
        # Setup logging
        self.logger = logger or self._setup_logging()
        
        # Initialize managers
        self.crypto_manager = CryptoManager(self.config.key_size)
        self.key_manager = KeyManager(self.config, self.crypto_manager)
        self.message_manager = MessageManager(self.config, self.crypto_manager)
        self.websocket_client = WebSocketClient(self.config, self.crypto_manager)
        self.system_manager = SystemManager(self.config)
        
        # State
        self.initialized = False
        self.realtime_running = False
        
        # Callbacks
        self.on_message: Optional[Callable[[str, str, str], None]] = None
        self.on_connect: Optional[Callable[[], None]] = None
        self.on_disconnect: Optional[Callable[[], None]] = None
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for the client"""
        logger = logging.getLogger("EventHorizonClient")
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(self.config.log_format)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(getattr(logging, self.config.log_level.upper()))
        
        return logger
    
    async def initialize(self) -> None:
        """
        Initialize the client
        
        This method:
        - Loads or generates cryptographic keys
        - Exchanges public keys with the server
        - Sets up authentication
        """
        if self.initialized:
            self.logger.warning("Client is already initialized")
            return
        
        try:
            self.logger.info("Initializing Event Horizon client...")
            
            # Load or generate keys
            self.key_manager.load_or_generate_keys()
            self.logger.info("Cryptographic keys loaded")
            
            # Exchange public keys with server
            await self.key_manager.exchange_public_key()
            self.logger.info("Public key exchange completed")
            
            self.initialized = True
            self.logger.info("Event Horizon client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize client: {str(e)}")
            raise EventHorizonError(f"Initialization failed: {str(e)}")
    
    # Key Management Methods
    
    async def get_public_key(self, target_did: str):
        """Get public key for another user"""
        return await self.key_manager.get_public_key(target_did)
    
    async def revoke_public_key(self) -> bool:
        """Revoke current public key"""
        return await self.key_manager.revoke_public_key()
    
    async def get_jwt_token(self) -> str:
        """Get JWT token for authentication"""
        return await self.key_manager.get_jwt_token()
    
    async def get_hmac_signature(self):
        """Get HMAC signature for authentication"""
        return await self.key_manager.get_hmac_signature()
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke JWT token"""
        return await self.key_manager.revoke_jwt_token(token)
    
    async def blacklist_token(self, token: str) -> bool:
        """Blacklist JWT token"""
        return await self.key_manager.blacklist_jwt_token(token)
    
    async def get_token_info(self, token: str):
        """Get information about JWT token"""
        return await self.key_manager.get_token_info(token)
    
    async def get_key_rotation_info(self):
        """Get information about key rotation"""
        return await self.key_manager.get_key_rotation_info()
    
    # Message Methods
    
    async def send_message(self, recipient_did: str, message: str):
        """Send encrypted message to another user"""
        return await self.message_manager.send_private_message(recipient_did, message)
    
    async def get_messages(self, limit: int = 100, offset: int = 0):
        """Get messages for current user"""
        return await self.message_manager.get_private_messages(limit, offset)
    
    async def get_message_history(self, target_did: str, limit: int = 100, offset: int = 0):
        """Get message history with specific user"""
        return await self.message_manager.get_message_history(target_did, limit, offset)
    
    def decrypt_message(self, encrypted_key: str, iv: str, ciphertext: str) -> str:
        """Decrypt received message"""
        return self.message_manager.decrypt_message(encrypted_key, iv, ciphertext)
    
    async def delete_message(self, message_id: str) -> bool:
        """Delete specific message"""
        return await self.message_manager.delete_message(message_id)
    
    async def mark_message_as_read(self, message_id: str) -> bool:
        """Mark message as read"""
        return await self.message_manager.mark_message_as_read(message_id)
    
    # Real-time Methods
    
    async def start_realtime(self, auth_method: str = "jwt") -> None:
        """
        Start real-time messaging
        
        :param auth_method: Authentication method ("jwt", "hmac", or "debug")
        """
        if not self.initialized:
            raise ConfigurationError("Client must be initialized before starting real-time")
        
        if self.realtime_running:
            self.logger.warning("Real-time messaging is already running")
            return
        
        try:
            # Setup callbacks
            if self.on_message:
                self.websocket_client.set_message_callback(self.on_message)
            
            if self.on_connect:
                self.websocket_client.set_connection_callback(self.on_connect)
            
            if self.on_disconnect:
                self.websocket_client.set_disconnection_callback(self.on_disconnect)
            
            # Connect to WebSocket
            await self.websocket_client.connect(auth_method)
            self.realtime_running = True
            
            self.logger.info("Real-time messaging started")
            
        except Exception as e:
            self.logger.error(f"Failed to start real-time messaging: {str(e)}")
            raise EventHorizonError(f"Real-time startup failed: {str(e)}")
    
    async def stop_realtime(self) -> None:
        """Stop real-time messaging"""
        if not self.realtime_running:
            return
        
        try:
            await self.websocket_client.disconnect()
            self.realtime_running = False
            self.logger.info("Real-time messaging stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping real-time messaging: {str(e)}")
    
    # System Methods
    
    async def get_system_health(self):
        """Get system health status"""
        return await self.system_manager.get_system_health()
    
    async def get_system_info(self):
        """Get system information"""
        return await self.system_manager.get_system_info()
    
    async def get_stats_overview(self):
        """Get system statistics overview"""
        return await self.system_manager.get_stats_overview()
    
    async def get_user_activity_stats(self):
        """Get user activity statistics"""
        return await self.system_manager.get_user_activity_stats()
    
    async def get_message_trends(self):
        """Get message trends statistics"""
        return await self.system_manager.get_message_trends()
    
    async def ping_server(self) -> float:
        """Ping server to measure latency"""
        return await self.system_manager.ping_server()
    
    async def check_server_status(self):
        """Comprehensive server status check"""
        return await self.system_manager.check_server_status()
    
    # Utility Methods
    
    def is_initialized(self) -> bool:
        """Check if client is initialized"""
        return self.initialized
    
    def is_realtime_running(self) -> bool:
        """Check if real-time messaging is running"""
        return self.realtime_running
    
    def get_config(self) -> ClientConfig:
        """Get current configuration"""
        return self.config
    
    def get_crypto_manager(self) -> CryptoManager:
        """Get crypto manager instance"""
        return self.crypto_manager
    
    # Context Manager Support
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        """Async context manager exit"""
        if self.realtime_running:
            await self.stop_realtime()
    
    # Cleanup
    
    async def cleanup(self) -> None:
        """Clean up resources"""
        try:
            if self.realtime_running:
                await self.stop_realtime()
            
            self.initialized = False
            self.logger.info("Event Horizon client cleaned up")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {str(e)}")
    
    def __del__(self):
        """Destructor to ensure cleanup"""
        if hasattr(self, 'realtime_running') and self.realtime_running:
            try:
                # Try to stop real-time if still running
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.stop_realtime())
            except:
                pass
