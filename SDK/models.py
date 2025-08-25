"""
Data models for Event Horizon SDK
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum


class MessageType(str, Enum):
    """Types of messages"""
    PRIVATE = "private_message"
    SYSTEM = "system_message"
    HEARTBEAT = "heartbeat"
    WELCOME = "welcome"


class TokenType(str, Enum):
    """Types of authentication tokens"""
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass
class KeyInfo:
    """Public key information"""
    did: str
    public_key: str
    last_updated: datetime
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyInfo':
        """Create KeyInfo from dictionary"""
        if isinstance(data.get('last_updated'), str):
            data['last_updated'] = datetime.fromisoformat(data['last_updated'].replace('Z', '+00:00'))
        return cls(**data)


@dataclass
class TokenInfo:
    """JWT token information"""
    did: str
    issued_at: datetime
    expires_at: datetime
    time_until_exp: int
    is_expired: bool
    is_revoked: bool
    is_blacklisted: bool
    token_type: TokenType
    jti: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenInfo':
        """Create TokenInfo from dictionary"""
        # Parse datetime strings
        for field in ['issued_at', 'expires_at']:
            if isinstance(data.get(field), str):
                data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
        
        # Parse token type
        if isinstance(data.get('token_type'), str):
            data['token_type'] = TokenType(data['token_type'])
            
        return cls(**data)


@dataclass
class Message:
    """Message model"""
    id: str
    sender_did: str
    recipient_did: str
    encrypted_key: str
    iv: str
    ciphertext: str
    timestamp: datetime
    message_type: MessageType = MessageType.PRIVATE
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create Message from dictionary"""
        # Parse timestamp
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        
        # Parse message type
        if isinstance(data.get('message_type'), str):
            data['message_type'] = MessageType(data['message_type'])
            
        return cls(**data)


@dataclass
class SystemInfo:
    """System information"""
    status: str
    timestamp: datetime
    version: str
    database: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SystemInfo':
        """Create SystemInfo from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)


@dataclass
class StatsOverview:
    """System statistics overview"""
    timestamp: datetime
    users: Dict[str, Any]
    messages: Dict[str, Any]
    system: Dict[str, Any]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StatsOverview':
        """Create StatsOverview from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)


@dataclass
class KeyRotationInfo:
    """Key rotation information"""
    current_key_hash: str
    last_rotation: datetime
    next_rotation: datetime
    rotation_interval_hours: int
    previous_keys_count: int
    total_keys_managed: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'KeyRotationInfo':
        """Create KeyRotationInfo from dictionary"""
        # Parse datetime strings
        for field in ['last_rotation', 'next_rotation']:
            if isinstance(data.get(field), str):
                data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
        return cls(**data)
