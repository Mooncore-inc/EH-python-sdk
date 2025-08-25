"""
Basic usage example for Event Horizon SDK
"""

import asyncio
import logging
from SDK import EventHorizonClient, ClientConfig

# Setup logging
logging.basicConfig(level=logging.INFO)


async def basic_example():
    """Basic example of using the Event Horizon SDK"""
    
    # Create client with custom configuration
    config = ClientConfig(
        did="did:example:user123",
        base_url="http://localhost:8000",
        log_level="INFO"
    )
    
    # Initialize client
    async with EventHorizonClient(config=config) as client:
        print(f"Client initialized: {client.is_initialized()}")
        
        # Send a message
        try:
            message = await client.send_message(
                recipient_did="did:example:recipient456",
                message="Hello from Event Horizon SDK!"
            )
            print(f"Message sent successfully: {message.id}")
        except Exception as e:
            print(f"Failed to send message: {e}")
        
        # Get messages
        try:
            messages = await client.get_messages(limit=10)
            print(f"Retrieved {len(messages)} messages")
            
            for msg in messages:
                print(f"Message from {msg.sender_did}: {msg.timestamp}")
        except Exception as e:
            print(f"Failed to get messages: {e}")
        
        # Get system health
        try:
            health = await client.get_system_health()
            print(f"System status: {health.status}")
        except Exception as e:
            print(f"Failed to get system health: {e}")


async def realtime_example():
    """Example of real-time messaging"""
    
    config = ClientConfig(
        did="did:example:user123",
        base_url="http://localhost:8000"
    )
    
    async with EventHorizonClient(config=config) as client:
        # Set up message callback
        def on_message(sender_did: str, message: str, timestamp: str):
            print(f"Real-time message from {sender_did}: {message}")
        
        client.on_message = on_message
        
        # Start real-time messaging
        await client.start_realtime(auth_method="jwt")
        print("Real-time messaging started")
        
        # Keep running for a while to receive messages
        await asyncio.sleep(30)
        
        # Stop real-time messaging
        await client.stop_realtime()
        print("Real-time messaging stopped")


async def advanced_example():
    """Advanced example with key management and system monitoring"""
    
    config = ClientConfig(
        did="did:example:user123",
        base_url="http://localhost:8000",
        key_size=4096  # Use stronger encryption
    )
    
    async with EventHorizonClient(config=config) as client:
        # Get JWT token
        try:
            token = await client.get_jwt_token()
            print(f"JWT token obtained: {token[:20]}...")
        except Exception as e:
            print(f"Failed to get JWT token: {e}")
        
        # Get key rotation info
        try:
            rotation_info = await client.get_key_rotation_info()
            print(f"Key rotation info: {rotation_info}")
        except Exception as e:
            print(f"Failed to get key rotation info: {e}")
        
        # Check server status
        try:
            status = await client.check_server_status()
            print(f"Server status: {status['overall_status']}")
            if status['ping'] > 0:
                print(f"Server ping: {status['ping']:.2f}ms")
        except Exception as e:
            print(f"Failed to check server status: {e}")
        
        # Get statistics
        try:
            stats = await client.get_stats_overview()
            print(f"Total users: {stats.users['total']}")
            print(f"Total messages: {stats.messages['total']}")
        except Exception as e:
            print(f"Failed to get statistics: {e}")


if __name__ == "__main__":
    print("=== Event Horizon SDK Examples ===\n")
    
    # Run basic example
    print("1. Basic Usage Example:")
    asyncio.run(basic_example())
    print()
    
    # Run real-time example
    print("2. Real-time Messaging Example:")
    asyncio.run(realtime_example())
    print()
    
    # Run advanced example
    print("3. Advanced Features Example:")
    asyncio.run(advanced_example())
    print()
    
    print("Examples completed!")
