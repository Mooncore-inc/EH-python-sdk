"""
Simple test script to verify SDK functionality
"""

import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def test_sdk_imports():
    """Test that all SDK modules can be imported"""
    print("Testing SDK imports...")
    
    try:
        # Import from local modules
        from client import EventHorizonClient
        from config import ClientConfig
        from exceptions import (
            EventHorizonError,
            AuthenticationError,
            NetworkError,
            CryptoError,
            ConfigurationError
        )
        print("✅ All main classes imported successfully")
        
        # Test configuration
        config = ClientConfig(did="test:user123")
        print(f"✅ Configuration created: {config.did}")
        
        # Test client creation
        client = EventHorizonClient(config=config)
        print(f"✅ Client created: {client.is_initialized()}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

async def test_crypto_manager():
    """Test crypto manager functionality"""
    print("\nTesting crypto manager...")
    
    try:
        from crypto import CryptoManager
        
        crypto = CryptoManager(key_size=2048)
        print("✅ Crypto manager created")
        
        # Test key generation
        private_key, public_key = crypto.generate_key_pair()
        print(f"✅ Key pair generated: {len(private_key)} bytes private, {len(public_key)} bytes public")
        
        return True
        
    except Exception as e:
        print(f"❌ Crypto manager error: {e}")
        return False

async def test_models():
    """Test data models"""
    print("\nTesting data models...")
    
    try:
        from models import Message, KeyInfo, MessageType
        
        # Test message creation
        from datetime import datetime
        message = Message(
            id="test-123",
            sender_did="did:test:sender",
            recipient_did="did:test:recipient",
            encrypted_key="test_key",
            iv="test_iv",
            ciphertext="test_ciphertext",
            timestamp=datetime.now()
        )
        print(f"✅ Message model created: {message.id}")
        
        # Test enum
        print(f"✅ Message type enum: {MessageType.PRIVATE}")
        
        return True
        
    except Exception as e:
        print(f"❌ Models error: {e}")
        return False

async def test_config():
    """Test configuration management"""
    print("\nTesting configuration...")
    
    try:
        from config import ClientConfig
        
        # Test basic config
        config = ClientConfig(
            did="did:test:user123",
            base_url="http://localhost:8000",
            key_size=4096
        )
        print(f"✅ Basic config: {config.did}, {config.key_size} bits")
        
        # Test environment config
        os.environ["EH_DID"] = "did:env:user456"
        env_config = ClientConfig.from_env()
        print(f"✅ Environment config: {env_config.did}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

async def main():
    """Run all tests"""
    print("🚀 Event Horizon SDK Test Suite\n")
    
    tests = [
        test_sdk_imports,
        test_crypto_manager,
        test_models,
        test_config
    ]
    
    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "="*50)
    print("📊 Test Results:")
    
    passed = sum(results)
    total = len(results)
    
    for i, result in enumerate(results):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"Test {i+1}: {status}")
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! SDK is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
