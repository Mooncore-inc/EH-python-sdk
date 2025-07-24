import aiohttp
import asyncio
import json
import logging
import os
import websockets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from typing import Optional, Callable, Dict, Any, List

class SecureMessagingClient:
    """
    Secure end-to-end encrypted messaging client with WebSocket real-time support
    
    Features:
    - RSA key generation and management
    - Hybrid encryption (RSA + AES)
    - Secure key exchange
    - Message history retrieval
    - Real-time notifications
    - Error handling and logging
    
    Usage:
    async with SecureMessagingClient(did="user123") as client:
        await client.exchange_keys()
        await client.send_private_message("recipient456", "Hello secure world!")
        client.set_message_callback(my_message_handler)
    """
    
    def __init__(self, 
                 did: str, 
                 base_url: str = "http://localhost:8000", 
                 keys_dir: str = "keys",
                 logger: Optional[logging.Logger] = None):
        """
        Initialize messaging client
        
        :param did: Unique decentralized identifier for the user
        :param base_url: Base URL for the messaging server
        :param keys_dir: Directory to store cryptographic keys
        :param logger: Custom logger instance (optional)
        """
        self.did = did
        self.base_url = base_url
        self.keys_dir = keys_dir
        self.websocket = None
        self.realtime_queue = asyncio.Queue()
        self.background_tasks = set()
        self.message_callback = None
        self.running = False
        
        self.logger = logger or logging.getLogger("SecureMessagingClient")
        if not self.logger.handlers:
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        self._ensure_keys_dir()
        self._load_or_generate_keys()

    def _ensure_keys_dir(self):
        """Ensure keys directory exists"""
        os.makedirs(self.keys_dir, exist_ok=True)
        self.logger.debug(f"Keys directory: {os.path.abspath(self.keys_dir)}")

    def _load_or_generate_keys(self):
        """Load existing keys or generate new key pair"""
        private_key = self._load_key('private')
        public_key = self._load_key('public')
        
        if private_key and public_key:
            self.private_key_pem = private_key
            self.public_key_pem = public_key
            self.logger.info("Existing cryptographic keys loaded")
        else:
            self.logger.info("Generating new cryptographic keys...")
            self.private_key_pem, self.public_key_pem = self._generate_keys()
            self._save_keys()
            self.logger.info("New keys generated and saved")

    def _load_key(self, key_type: str) -> Optional[bytes]:
        """Load key from file system"""
        try:
            with open(f"{self.keys_dir}/{self.did}_{key_type}.pem", "rb") as f:
                return f.read()
        except FileNotFoundError:
            self.logger.warning(f"{key_type.capitalize()} key not found")
            return None
        except Exception as e:
            self.logger.error(f"Error loading {key_type} key: {str(e)}")
            return None

    def _generate_keys(self) -> tuple[bytes, bytes]:
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

    def _save_keys(self):
        """Save keys to filesystem"""
        try:
            with open(f"{self.keys_dir}/{self.did}_private.pem", "wb") as f:
                f.write(self.private_key_pem)
            with open(f"{self.keys_dir}/{self.did}_public.pem", "wb") as f:
                f.write(self.public_key_pem)
            self.logger.debug("Keys saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving keys: {str(e)}")
            raise CryptoStorageError("Failed to save keys") from e

    async def start(self):
        """Start background tasks for real-time messaging"""
        if self.running:
            self.logger.warning("Client is already running")
            return
            
        self.running = True
        self.logger.info("Starting messaging client...")
        
        task_listener = asyncio.create_task(self._websocket_listener())
        task_handler = asyncio.create_task(self._handle_realtime_messages())
        
        self.background_tasks = {task_listener, task_handler}
        for task in self.background_tasks:
            task.add_done_callback(self._remove_task)
            
        self.logger.info("Background tasks started")

    async def stop(self):
        """Stop client and clean up resources"""
        if not self.running:
            return
            
        self.logger.info("Stopping messaging client...")
        self.running = False

        if self.websocket:
            await self.websocket.close()
            self.websocket = None

        for task in self.background_tasks:
            if not task.done():
                task.cancel()

        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.logger.info("Client stopped successfully")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stop()

    def set_message_callback(self, callback: Callable[[str, str, str], None]):
        """
        Set callback for incoming real-time messages
        
        :param callback: Function with signature (sender_did: str, message: str, timestamp: str)
        """
        self.message_callback = callback
        self.logger.info("Message callback set")

    async def exchange_keys(self):
        """Exchange public keys with server"""
        self.logger.info("Initiating key exchange...")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.base_url}/exchange_keys",
                    json={"did": self.did, "public_key": self.public_key_pem.decode()}
                ) as response:
                    if response.status == 200:
                        self.logger.info("Key exchange successful")
                        return True
                    else:
                        error = await response.text()
                        self.logger.error(f"Key exchange failed: {response.status} - {error}")
                        return False
            except aiohttp.ClientError as e:
                self.logger.error(f"Network error during key exchange: {str(e)}")
                raise NetworkError("Key exchange failed") from e

    async def get_public_key(self, target_did: str) -> Optional[bytes]:
        """Retrieve public key for another user"""
        self.logger.info(f"Retrieving public key for: {target_did}")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{self.base_url}/public_key/{target_did}") as response:
                    if response.status == 200:
                        data = await response.json()
                        return data["public_key"].encode()
                    else:
                        error = await response.text()
                        self.logger.error(f"Failed to get key: {response.status} - {error}")
                        return None
            except aiohttp.ClientError as e:
                self.logger.error(f"Network error getting key: {str(e)}")
                raise NetworkError("Key retrieval failed") from e

    async def send_private_message(self, 
                                  recipient_did: str, 
                                  message: str) -> bool:
        """
        Send encrypted private message
        
        :param recipient_did: Recipient's decentralized ID
        :param message: Plaintext message to send
        :return: True if message sent successfully
        """
        self.logger.info(f"Sending message to: {recipient_did}")
        public_key_pem = await self.get_public_key(recipient_did)
        if not public_key_pem:
            self.logger.error("Aborting send - no public key available")
            return False
        
        try:
            encrypted = self._encrypt_message(message, public_key_pem)
        except CryptoOperationError as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            return False
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{self.base_url}/send_private",
                    json={
                        "sender_did": self.did,
                        "recipient_did": recipient_did,
                        "encrypted_key": encrypted["encrypted_key"],
                        "iv": encrypted["iv"],
                        "ciphertext": encrypted["ciphertext"]
                    }
                ) as response:
                    if response.status == 200:
                        self.logger.info("Message sent successfully")
                        return True
                    else:
                        error = await response.text()
                        self.logger.error(f"Send failed: {response.status} - {error}")
                        return False
            except aiohttp.ClientError as e:
                self.logger.error(f"Network error sending message: {str(e)}")
                raise NetworkError("Message send failed") from e

    def _encrypt_message(self, 
                        message: str, 
                        public_key_pem: bytes) -> Dict[str, str]:
        """Encrypt message using hybrid encryption"""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            session_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)           # AES block size
            
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(message.encode()) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), 
                           backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            encrypted_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return {
                "encrypted_key": encrypted_key.hex(),
                "ciphertext": ciphertext.hex(),
                "iv": iv.hex()
            }
        except Exception as e:
            self.logger.error(f"Encryption error: {str(e)}")
            raise CryptoOperationError("Encryption failed") from e

    async def get_private_messages(self, 
                                  limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve private message history
        
        :param limit: Maximum number of messages to retrieve
        :return: List of message objects
        """
        self.logger.info(f"Retrieving messages (limit: {limit})")
        params = {"limit": limit}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.base_url}/private_messages/{self.did}",
                    params=params
                ) as response:
                    if response.status == 200:
                        messages = await response.json()
                        self.logger.info(f"Retrieved {len(messages)} messages")
                        return messages
                    else:
                        error = await response.text()
                        self.logger.error(f"Get messages failed: {response.status} - {error}")
                        return []
            except aiohttp.ClientError as e:
                self.logger.error(f"Network error getting messages: {str(e)}")
                raise NetworkError("Message retrieval failed") from e

    def decrypt_message(self, 
                       encrypted_key_hex: str, 
                       iv_hex: str, 
                       ciphertext_hex: str) -> str:
        """
        Decrypt received message
        
        :param encrypted_key_hex: Encrypted session key (hex)
        :param iv_hex: Initialization vector (hex)
        :param ciphertext_hex: Encrypted message (hex)
        :return: Decrypted plaintext message
        """
        try:
            private_key = serialization.load_pem_private_key(
                self.private_key_pem,
                password=None,
                backend=default_backend()
            )
            
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            
            session_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), 
                           backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
        except Exception as e:
            self.logger.error(f"Decryption error: {str(e)}")
            raise CryptoOperationError("Decryption failed") from e

    async def _websocket_listener(self):
        """WebSocket listener for real-time messages"""
        if self.base_url.startswith("https://"):
            ws_url = f"wss://{self.base_url[8:]}/ws/{self.did}"
        elif self.base_url.startswith("http://"):
            ws_url = f"ws://{self.base_url[7:]}/ws/{self.did}"
        else:
            ws_url = f"ws://{self.base_url}/ws/{self.did}"
            
        self.logger.info(f"Connecting to WebSocket: {ws_url}")
        
        while self.running:
            try:
                async with websockets.connect(ws_url) as websocket:
                    self.websocket = websocket
                    self.logger.info("WebSocket connected")
                    
                    async for message in websocket:
                        try:
                            data = json.loads(message)
                            await self.realtime_queue.put(data)
                        except json.JSONDecodeError:
                            self.logger.error("Invalid JSON received via WebSocket")
            except Exception as e:
                self.logger.error(f"WebSocket error: {str(e)}")
                self.logger.info("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

    async def _handle_realtime_messages(self):
        """Process real-time messages from queue"""
        self.logger.info("Starting real-time message handler")
        while self.running:
            try:
                msg = await asyncio.wait_for(self.realtime_queue.get(), timeout=0.5)
                
                if (msg.get("type") == "private_message" and 
                    msg.get("recipient_did") == self.did and 
                    self.message_callback):
                    
                    try:
                        decrypted = self.decrypt_message(
                            msg["encrypted_key"],
                            msg["iv"],
                            msg["ciphertext"]
                        )
                        self.message_callback(
                            msg['sender_did'],
                            decrypted,
                            msg['timestamp']
                        )
                    except CryptoOperationError:
                        self.logger.error("Failed to decrypt real-time message")
                        
                self.realtime_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error handling message: {str(e)}")
                
        self.logger.info("Real-time message handler stopped")

    def _remove_task(self, task):
        """Remove completed task from tracking"""
        self.background_tasks.discard(task)
        self.logger.debug("Background task completed")

class CryptoStorageError(Exception):
    """Error related to cryptographic key storage"""

class CryptoOperationError(Exception):
    """Error during cryptographic operations"""

class NetworkError(Exception):
    """Network communication error"""

class ConfigurationError(Exception):
    """Client configuration error"""