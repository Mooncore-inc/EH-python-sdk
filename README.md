# Event Horizon SDK

Python SDK for Event Horizon.

## Installation

1. Clone the repository:
```bash
git clone 
cd EH-sdk
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Quick Start:
```python
import asyncio
from SDK.EH_sdk import SecureMessagingClient

async def message_handler(sender, message, timestamp):
    print(f"\nNew message from {sender} ({timestamp}): {message}")

async def main():
    async with SecureMessagingClient(did="your_did_here") as client:
        # Setup real-time message handler
        client.set_message_callback(message_handler)
        
        # Exchange encryption keys with server
        await client.exchange_keys()
        
        # Send encrypted message
        await client.send_private_message("recipient_did", "Hello!")
        
        # Retrieve message history
        messages = await client.get_private_messages(limit=10)
        for msg in messages:
            print(f"\nFrom {msg['sender_did']}: {msg['decrypted_content']}")
        
if __name__ == "__main__":
    asyncio.run(main())
```
