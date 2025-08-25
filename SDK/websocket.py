"""
WebSocket client for Event Horizon SDK
"""

import asyncio
import json
import logging
from typing import Optional, Callable, Dict, Any, List
import websockets
from exceptions import WebSocketError, AuthenticationError
from models import Message, MessageType


class WebSocketClient:
    """WebSocket client for real-time messaging"""
    
    def __init__(self, config, crypto_manager):
        """
        Initialize WebSocket client
        
        :param config: Client configuration
        :param crypto_manager: Crypto manager instance
        """
        self.config = config
        self.crypto_manager = crypto_manager
        self.websocket = None
        self.running = False
        self.reconnect_attempts = 0
        self.message_callback = None
        self.connection_callback = None
        self.disconnection_callback = None
        self.realtime_queue = asyncio.Queue()
        self.background_tasks = set()
        self.logger = logging.getLogger("WebSocketClient")
    
    def set_message_callback(self, callback: Callable[[str, str, str], None]):
        """
        Set callback for incoming real-time messages
        
        :param callback: Function with signature (sender_did: str, message: str, timestamp: str)
        """
        self.message_callback = callback
    
    def set_connection_callback(self, callback: Callable[[], None]):
        """
        Set callback for connection events
        
        :param callback: Function called when connection is established
        """
        self.connection_callback = callback
    
    def set_disconnection_callback(self, callback: Callable[[], None]):
        """
        Set callback for disconnection events
        
        :param callback: Function called when connection is lost
        """
        self.disconnection_callback = callback
    
    async def connect(self, auth_method: str = "jwt") -> bool:
        """
        Connect to WebSocket server
        
        :param auth_method: Authentication method ("jwt", "hmac", or "debug")
        :return: True if connection successful
        """
        if self.running:
            self.logger.warning("WebSocket client is already running")
            return True
        
        # Get authentication credentials
        auth_params = await self._get_auth_params(auth_method)
        if not auth_params:
            raise AuthenticationError(f"Failed to get authentication for method: {auth_method}")
        
        # Build WebSocket URL
        ws_url = f"{self.config.websocket_url}/ws/{self.config.did}"
        if auth_params:
            query_string = "&".join([f"{k}={v}" for k, v in auth_params.items()])
            ws_url += f"?{query_string}"
        
        self.logger.info(f"Connecting to WebSocket: {ws_url}")
        
        try:
            self.websocket = await websockets.connect(ws_url)
            self.running = True
            self.reconnect_attempts = 0
            
            # Start background tasks
            await self._start_background_tasks()
            
            if self.connection_callback:
                self.connection_callback()
            
            self.logger.info("WebSocket connected successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to WebSocket: {str(e)}")
            raise WebSocketError(f"Connection failed: {str(e)}")
    
    async def _get_auth_params(self, auth_method: str) -> Optional[Dict[str, str]]:
        """
        Get authentication parameters for WebSocket connection
        
        :param auth_method: Authentication method
        :return: Dictionary with authentication parameters
        """
        try:
            from keys import KeyManager
            key_manager = KeyManager(self.config, self.crypto_manager)
            
            if auth_method == "jwt":
                token = await key_manager.get_jwt_token()
                return {"token": token}
            
            elif auth_method == "hmac":
                signature_data = await key_manager.get_hmac_signature()
                return {
                    "signature": signature_data["signature"],
                    "timestamp": signature_data["timestamp"]
                }
            
            elif auth_method == "debug":
                # Only allow in debug mode
                if self.config.base_url == "http://localhost:8000":
                    return {}
                else:
                    raise AuthenticationError("Debug mode only allowed for localhost")
            
            else:
                raise AuthenticationError(f"Unsupported authentication method: {auth_method}")
                
        except Exception as e:
            self.logger.error(f"Failed to get authentication parameters: {str(e)}")
            return None
    
    async def _start_background_tasks(self):
        """Start background tasks for WebSocket handling"""
        task_listener = asyncio.create_task(self._message_listener())
        task_handler = asyncio.create_task(self._message_handler())
        task_heartbeat = asyncio.create_task(self._heartbeat())
        
        self.background_tasks = {task_listener, task_handler, task_heartbeat}
        for task in self.background_tasks:
            task.add_done_callback(self._remove_task)
    
    async def disconnect(self):
        """Disconnect from WebSocket server"""
        if not self.running:
            return
        
        self.logger.info("Disconnecting from WebSocket...")
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Close WebSocket connection
        if self.websocket:
            await self.websocket.close()
            self.websocket = None
        
        if self.disconnection_callback:
            self.disconnection_callback()
        
        self.logger.info("WebSocket disconnected")
    
    async def _message_listener(self):
        """Listen for incoming WebSocket messages"""
        self.logger.info("Starting WebSocket message listener")
        
        while self.running and self.websocket:
            try:
                message = await self.websocket.recv()
                await self.realtime_queue.put(message)
            except websockets.exceptions.ConnectionClosed:
                self.logger.warning("WebSocket connection closed")
                break
            except Exception as e:
                self.logger.error(f"Error receiving message: {str(e)}")
                break
        
        # Handle disconnection
        if self.running:
            await self._handle_disconnection()
    
    async def _message_handler(self):
        """Process messages from the real-time queue"""
        self.logger.info("Starting WebSocket message handler")
        
        while self.running:
            try:
                # Wait for message with timeout
                message = await asyncio.wait_for(
                    self.realtime_queue.get(), 
                    timeout=0.5
                )
                
                await self._process_message(message)
                self.realtime_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error handling message: {str(e)}")
        
        self.logger.info("WebSocket message handler stopped")
    
    async def _process_message(self, message_data: str):
        """Process a single WebSocket message"""
        try:
            data = json.loads(message_data)
            message_type = data.get("type")
            
            if message_type == MessageType.PRIVATE:
                await self._handle_private_message(data)
            elif message_type == MessageType.SYSTEM:
                await self._handle_system_message(data)
            elif message_type == MessageType.HEARTBEAT:
                await self._handle_heartbeat(data)
            elif message_type == MessageType.WELCOME:
                await self._handle_welcome_message(data)
            else:
                self.logger.warning(f"Unknown message type: {message_type}")
                
        except json.JSONDecodeError:
            self.logger.error("Invalid JSON received via WebSocket")
        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")
    
    async def _handle_private_message(self, data: Dict[str, Any]):
        """Handle private message"""
        if not self.message_callback:
            return
        
        try:
            # Decrypt message
            decrypted_message = self.crypto_manager.decrypt_message(
                data["encrypted_key"],
                data["iv"],
                data["ciphertext"]
            )
            
            # Call message callback
            self.message_callback(
                data["sender_did"],
                decrypted_message,
                data["timestamp"]
            )
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt private message: {str(e)}")
    
    async def _handle_system_message(self, data: Dict[str, Any]):
        """Handle system message"""
        self.logger.info(f"System message: {data.get('data', {}).get('message', 'Unknown')}")
    
    async def _handle_heartbeat(self, data: Dict[str, Any]):
        """Handle heartbeat message"""
        self.logger.debug(f"Heartbeat received: {data.get('data', {}).get('timestamp')}")
    
    async def _handle_welcome_message(self, data: Dict[str, Any]):
        """Handle welcome message"""
        welcome_msg = data.get('data', {}).get('message', 'Welcome!')
        self.logger.info(f"Welcome message: {welcome_msg}")
    
    async def _heartbeat(self):
        """Send periodic heartbeat messages"""
        self.logger.info("Starting heartbeat task")
        
        while self.running and self.websocket:
            try:
                await asyncio.sleep(self.config.websocket_heartbeat_interval)
                
                if self.running and self.websocket:
                    heartbeat_msg = {
                        "type": "heartbeat",
                        "data": {
                            "timestamp": asyncio.get_event_loop().time()
                        }
                    }
                    await self.websocket.send(json.dumps(heartbeat_msg))
                    
            except Exception as e:
                self.logger.error(f"Heartbeat error: {str(e)}")
                break
        
        self.logger.info("Heartbeat task stopped")
    
    async def _handle_disconnection(self):
        """Handle WebSocket disconnection"""
        self.logger.warning("WebSocket disconnected, attempting to reconnect...")
        
        if self.disconnection_callback:
            self.disconnection_callback()
        
        # Attempt to reconnect
        while (self.running and 
               self.reconnect_attempts < self.config.websocket_max_reconnect_attempts):
            
            self.reconnect_attempts += 1
            self.logger.info(f"Reconnection attempt {self.reconnect_attempts}")
            
            try:
                await asyncio.sleep(self.config.websocket_reconnect_delay)
                if await self.connect():
                    self.logger.info("WebSocket reconnected successfully")
                    return
            except Exception as e:
                self.logger.error(f"Reconnection attempt failed: {str(e)}")
        
        if self.reconnect_attempts >= self.config.websocket_max_reconnect_attempts:
            self.logger.error("Max reconnection attempts reached")
            self.running = False
    
    def _remove_task(self, task):
        """Remove completed task from tracking"""
        self.background_tasks.discard(task)
        self.logger.debug("Background task completed")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        """Async context manager exit"""
        await self.disconnect()
