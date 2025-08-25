"""
Custom exceptions for Event Horizon SDK
"""


class EventHorizonError(Exception):
    """Base exception for all Event Horizon SDK errors"""
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(EventHorizonError):
    """Authentication and authorization related errors"""
    
    def __init__(self, message: str = "Authentication failed", error_code: str = None):
        super().__init__(message, error_code or "AUTH_ERROR")


class NetworkError(EventHorizonError):
    """Network communication errors"""
    
    def __init__(self, message: str = "Network error occurred", error_code: str = None):
        super().__init__(message, error_code or "NETWORK_ERROR")


class CryptoError(EventHorizonError):
    """Cryptographic operation errors"""
    
    def __init__(self, message: str = "Cryptographic operation failed", error_code: str = None):
        super().__init__(message, error_code or "CRYPTO_ERROR")


class ConfigurationError(EventHorizonError):
    """Configuration and setup errors"""
    
    def __init__(self, message: str = "Configuration error", error_code: str = None):
        super().__init__(message, error_code or "CONFIG_ERROR")


class ValidationError(EventHorizonError):
    """Data validation errors"""
    
    def __init__(self, message: str = "Validation failed", error_code: str = None):
        super().__init__(message, error_code or "VALIDATION_ERROR")


class RateLimitError(EventHorizonError):
    """Rate limiting errors"""
    
    def __init__(self, message: str = "Rate limit exceeded", error_code: str = None):
        super().__init__(message, error_code or "RATE_LIMIT_ERROR")


class WebSocketError(EventHorizonError):
    """WebSocket connection errors"""
    
    def __init__(self, message: str = "WebSocket error occurred", error_code: str = None):
        super().__init__(message, error_code or "WEBSOCKET_ERROR")
