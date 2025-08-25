"""
Utility functions for Event Horizon SDK
"""

import os
import hashlib
import base64
from typing import Optional, Dict, Any
from datetime import datetime, timezone


def generate_did(prefix: str = "did:example", identifier: Optional[str] = None) -> str:
    """
    Generate a decentralized identifier
    
    :param prefix: DID method prefix
    :param identifier: Custom identifier (optional)
    :return: Generated DID
    """
    if identifier:
        return f"{prefix}:{identifier}"
    
    # Generate random identifier
    import secrets
    random_bytes = secrets.token_bytes(16)
    random_hex = random_bytes.hex()
    return f"{prefix}:{random_hex}"


def hash_data(data: str) -> str:
    """
    Generate SHA-256 hash of data
    
    :param data: Data to hash
    :return: Hexadecimal hash string
    """
    return hashlib.sha256(data.encode()).hexdigest()


def encode_base64(data: bytes) -> str:
    """
    Encode data to base64
    
    :param data: Data to encode
    :return: Base64 encoded string
    """
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data: str) -> bytes:
    """
    Decode base64 data
    
    :param data: Base64 encoded string
    :return: Decoded bytes
    """
    return base64.b64decode(data)


def format_timestamp(timestamp: Optional[datetime] = None) -> str:
    """
    Format timestamp to ISO format
    
    :param timestamp: Timestamp to format (defaults to current time)
    :return: ISO formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    
    return timestamp.isoformat()


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO timestamp string
    
    :param timestamp_str: ISO formatted timestamp string
    :return: Datetime object
    """
    # Remove timezone info if present and convert to UTC
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1] + '+00:00'
    
    return datetime.fromisoformat(timestamp_str)


def validate_did(did: str) -> bool:
    """
    Validate DID format
    
    :param did: DID to validate
    :return: True if valid
    """
    if not did or not isinstance(did, str):
        return False
    
    # Basic DID format validation
    parts = did.split(':')
    if len(parts) < 3:
        return False
    
    if not parts[0] == 'did':
        return False
    
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations
    
    :param filename: Original filename
    :return: Sanitized filename
    """
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    for char in unsafe_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip(' .')
    
    # Ensure filename is not empty
    if not filename:
        filename = 'unnamed'
    
    return filename


def ensure_directory(path: str) -> str:
    """
    Ensure directory exists, create if necessary
    
    :param path: Directory path
    :return: Absolute path to directory
    """
    abs_path = os.path.abspath(path)
    os.makedirs(abs_path, exist_ok=True)
    return abs_path


def get_file_size(file_path: str) -> Optional[int]:
    """
    Get file size in bytes
    
    :param file_path: Path to file
    :return: File size in bytes or None if error
    """
    try:
        return os.path.getsize(file_path)
    except (OSError, FileNotFoundError):
        return None


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format
    
    :param size_bytes: Size in bytes
    :return: Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def merge_configs(default_config: Dict[str, Any], user_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge configuration dictionaries
    
    :param default_config: Default configuration
    :param user_config: User configuration
    :return: Merged configuration
    """
    merged = default_config.copy()
    
    for key, value in user_config.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_configs(merged[key], value)
        else:
            merged[key] = value
    
    return merged


def retry_with_backoff(func, max_retries: int = 3, base_delay: float = 1.0):
    """
    Retry function with exponential backoff
    
    :param func: Function to retry
    :param max_retries: Maximum number of retries
    :param base_delay: Base delay between retries
    :return: Function result
    """
    import asyncio
    
    async def async_retry(*args, **kwargs):
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
                    
            except Exception as e:
                last_exception = e
                
                if attempt < max_retries:
                    delay = base_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                else:
                    break
        
        raise last_exception
    
    return async_retry


def create_rate_limiter(max_requests: int, time_window: float):
    """
    Create a simple rate limiter
    
    :param max_requests: Maximum requests per time window
    :param time_window: Time window in seconds
    :return: Rate limiter function
    """
    import time
    from collections import deque
    
    requests = deque()
    
    def rate_limiter():
        now = time.time()
        
        # Remove old requests outside the time window
        while requests and requests[0] <= now - time_window:
            requests.popleft()
        
        # Check if we can make a request
        if len(requests) >= max_requests:
            return False
        
        # Add current request
        requests.append(now)
        return True
    
    return rate_limiter
