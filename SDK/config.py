"""
Configuration management for Event Horizon SDK
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class ClientConfig:
    """Configuration for Event Horizon client"""
    
    # Server configuration
    base_url: str = "http://localhost:8000"
    api_version: str = "v1"
    
    # Authentication
    did: Optional[str] = None
    access_token: Optional[str] = None
    
    # Security
    keys_dir: str = "keys"
    key_size: int = 2048
    encryption_algorithm: str = "RSA"
    
    # WebSocket
    websocket_reconnect_delay: int = 5
    websocket_heartbeat_interval: int = 30
    websocket_max_reconnect_attempts: int = 10
    
    # HTTP client
    timeout: int = 30
    max_retries: int = 3
    retry_delay: int = 1
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Rate limiting
    rate_limit_per_minute: int = 100
    
    def __post_init__(self):
        """Post-initialization setup"""
        # Ensure keys directory is absolute path
        if not os.path.isabs(self.keys_dir):
            self.keys_dir = str(Path.cwd() / self.keys_dir)
        
        # Set default DID from environment if available
        if not self.did:
            self.did = os.getenv("EH_DID")
        
        # Set base URL from environment if available
        if self.base_url == "http://localhost:8000":
            env_url = os.getenv("EH_BASE_URL")
            if env_url:
                self.base_url = env_url
        
        # Set access token from environment if available
        if not self.access_token:
            self.access_token = os.getenv("EH_ACCESS_TOKEN")
    
    @property
    def api_base_url(self) -> str:
        """Get full API base URL"""
        return f"{self.base_url}/api/{self.api_version}"
    
    @property
    def websocket_url(self) -> str:
        """Get WebSocket URL"""
        if self.base_url.startswith("https://"):
            return f"wss://{self.base_url[8:]}"
        elif self.base_url.startswith("http://"):
            return f"ws://{self.base_url[7:]}"
        else:
            return f"ws://{self.base_url}"
    
    def validate(self) -> bool:
        """Validate configuration"""
        if not self.did:
            raise ValueError("DID is required")
        
        if not self.base_url:
            raise ValueError("Base URL is required")
        
        if self.key_size not in [1024, 2048, 4096]:
            raise ValueError("Key size must be 1024, 2048, or 4096")
        
        return True
    
    def to_dict(self) -> dict:
        """Convert config to dictionary"""
        return {
            "base_url": self.base_url,
            "api_version": self.api_version,
            "did": self.did,
            "keys_dir": self.keys_dir,
            "key_size": self.key_size,
            "encryption_algorithm": self.encryption_algorithm,
            "websocket_reconnect_delay": self.websocket_reconnect_delay,
            "websocket_heartbeat_interval": self.websocket_heartbeat_interval,
            "websocket_max_reconnect_attempts": self.websocket_max_reconnect_attempts,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "log_level": self.log_level,
            "rate_limit_per_minute": self.rate_limit_per_minute
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ClientConfig':
        """Create config from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> 'ClientConfig':
        """Create config from environment variables"""
        return cls(
            base_url=os.getenv("EH_BASE_URL", "http://localhost:8000"),
            api_version=os.getenv("EH_API_VERSION", "v1"),
            did=os.getenv("EH_DID"),
            access_token=os.getenv("EH_ACCESS_TOKEN"),
            keys_dir=os.getenv("EH_KEYS_DIR", "keys"),
            key_size=int(os.getenv("EH_KEY_SIZE", "2048")),
            encryption_algorithm=os.getenv("EH_ENCRYPTION_ALGORITHM", "RSA"),
            websocket_reconnect_delay=int(os.getenv("EH_WS_RECONNECT_DELAY", "5")),
            websocket_heartbeat_interval=int(os.getenv("EH_WS_HEARTBEAT_INTERVAL", "30")),
            websocket_max_reconnect_attempts=int(os.getenv("EH_WS_MAX_RECONNECT", "10")),
            timeout=int(os.getenv("EH_TIMEOUT", "30")),
            max_retries=int(os.getenv("EH_MAX_RETRIES", "3")),
            retry_delay=int(os.getenv("EH_RETRY_DELAY", "1")),
            log_level=os.getenv("EH_LOG_LEVEL", "INFO"),
            rate_limit_per_minute=int(os.getenv("EH_RATE_LIMIT", "100"))
        )
