# Event Horizon Python SDK 🚀

**Professional Python SDK for Event Horizon Chat** - высокопроизводительный, модульный SDK для работы с Event Horizon backend, обеспечивающий end-to-end шифрование и real-time messaging.

## 🌟 Особенности

- **🔐 End-to-End Шифрование** - гибридное RSA + AES шифрование
- **📦 Модульная архитектура** - разделение на логические компоненты
- **⚡ Async/await поддержка** - современный асинхронный подход
- **🔄 Real-time WebSocket** - мгновенная доставка сообщений
- **🆔 DID-based Identity** - децентрализованная идентификация
- **🔑 Управление ключами** - автоматическая генерация и ротация
- **📊 Мониторинг** - встроенная система наблюдения
- **🧪 Полное тестирование** - покрытие тестами всех компонентов

## 📚 Структура SDK

```
SDK/
├── __init__.py          # Основной модуль с импортами
├── client.py            # Главный клиент SDK
├── config.py            # Управление конфигурацией
├── crypto.py            # Криптографические операции
├── exceptions.py        # Кастомные исключения
├── keys.py              # Управление ключами и аутентификация
├── messages.py          # Работа с сообщениями
├── models.py            # Модели данных
├── system.py            # Системные операции
├── utils.py             # Вспомогательные функции
├── websocket.py         # WebSocket клиент
└── examples/            # Примеры использования
    └── basic_usage.py   # Базовые примеры
```

## 🚀 Быстрый старт

### Установка

```bash
pip install -r requirements.txt
```

### Базовое использование

```python
import asyncio
from SDK import EventHorizonClient, ClientConfig

async def main():
    # Создание клиента
    config = ClientConfig(
        did="did:example:user123",
        base_url="http://localhost:8000"
    )
    
    # Использование контекстного менеджера
    async with EventHorizonClient(config=config) as client:
        # Отправка сообщения
        message = await client.send_message(
            recipient_did="did:example:recipient456",
            message="Hello secure world!"
        )
        print(f"Message sent: {message.id}")
        
        # Получение сообщений
        messages = await client.get_messages(limit=10)
        print(f"Retrieved {len(messages)} messages")

# Запуск
asyncio.run(main())
```

## 🔧 Конфигурация

### Создание конфигурации

```python
from SDK import ClientConfig

# Базовая конфигурация
config = ClientConfig(
    did="did:example:user123",
    base_url="http://localhost:8000",
    key_size=2048,
    timeout=30
)

# Из переменных окружения
config = ClientConfig.from_env()

# Из словаря
config = ClientConfig.from_dict({
    "did": "did:example:user123",
    "base_url": "http://localhost:8000"
})
```

### Переменные окружения

```bash
# Основные настройки
export EH_DID="did:example:user123"
export EH_BASE_URL="http://localhost:8000"
export EH_API_VERSION="v1"

# Безопасность
export EH_KEY_SIZE="2048"
export EH_ENCRYPTION_ALGORITHM="RSA"

# WebSocket
export EH_WS_RECONNECT_DELAY="5"
export EH_WS_HEARTBEAT_INTERVAL="30"
export EH_WS_MAX_RECONNECT="10"

# HTTP клиент
export EH_TIMEOUT="30"
export EH_MAX_RETRIES="3"
export EH_RETRY_DELAY="1"

# Логирование
export EH_LOG_LEVEL="INFO"
export EH_RATE_LIMIT="100"
```

## 🔐 Управление ключами

### Обмен публичными ключами

```python
async with EventHorizonClient(did="user123") as client:
    # Автоматический обмен ключей при инициализации
    await client.initialize()
    
    # Получение публичного ключа другого пользователя
    key_info = await client.get_public_key("did:example:recipient456")
    print(f"Public key: {key_info.public_key[:50]}...")
    
    # Отзыв публичного ключа
    await client.revoke_public_key()
```

### JWT токены

```python
# Получение JWT токена
token = await client.get_jwt_token()
print(f"JWT token: {token[:20]}...")

# Получение HMAC подписи
signature_data = await client.get_hmac_signature()
print(f"Signature: {signature_data['signature']}")

# Информация о токене
token_info = await client.get_token_info(token)
print(f"Token expires: {token_info.expires_at}")

# Отзыв токена
await client.revoke_token(token)

# Блокировка токена
await client.blacklist_token(token)
```

## 💬 Сообщения

### Отправка и получение

```python
# Отправка зашифрованного сообщения
message = await client.send_message(
    recipient_did="did:example:recipient456",
    message="Secret message content"
)
print(f"Message sent with ID: {message.id}")

# Получение сообщений
messages = await client.get_messages(limit=50, offset=0)
for msg in messages:
    print(f"From {msg.sender_did}: {msg.timestamp}")

# История сообщений с конкретным пользователем
chat_history = await client.get_message_history(
    target_did="did:example:recipient456",
    limit=100
)

# Расшифровка сообщения
decrypted = client.decrypt_message(
    msg.encrypted_key,
    msg.iv,
    msg.ciphertext
)
print(f"Decrypted: {decrypted}")
```

### Управление сообщениями

```python
# Удаление сообщения
await client.delete_message("message-uuid-123")

# Отметка как прочитанное
await client.mark_message_as_read("message-uuid-123")

# Подсчет непрочитанных
messages = await client.get_messages()
unread_count = client.message_manager.get_unread_count(messages)
print(f"Unread messages: {unread_count}")
```

## 🌐 Real-time WebSocket

### Базовое использование

```python
async with EventHorizonClient(did="user123") as client:
    # Настройка callback'ов
    def on_message(sender_did: str, message: str, timestamp: str):
        print(f"Real-time message from {sender_did}: {message}")
    
    def on_connect():
        print("WebSocket connected!")
    
    def on_disconnect():
        print("WebSocket disconnected!")
    
    client.on_message = on_message
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    
    # Запуск real-time messaging
    await client.start_realtime(auth_method="jwt")
    
    # Работа с real-time сообщениями
    await asyncio.sleep(60)  # Слушаем сообщения 1 минуту
    
    # Остановка
    await client.stop_realtime()
```

### Методы аутентификации

```python
# JWT токен (рекомендуется)
await client.start_realtime(auth_method="jwt")

# HMAC подпись
await client.start_realtime(auth_method="hmac")

# Debug режим (только для localhost)
await client.start_realtime(auth_method="debug")
```

## 📊 Системный мониторинг

### Проверка здоровья

```python
# Базовая проверка здоровья
health = await client.get_system_health()
print(f"System status: {health.status}")
print(f"Database: {health.database}")

# Полная проверка статуса
status = await client.check_server_status()
print(f"Overall status: {status['overall_status']}")
print(f"Ping: {status['ping']:.2f}ms")

# Системная информация
info = await client.get_system_info()
print(f"Version: {info.get('version')}")
```

### Статистика

```python
# Обзор статистики
stats = await client.get_stats_overview()
print(f"Total users: {stats.users['total']}")
print(f"Online users: {stats.users['connected']}")
print(f"Online percentage: {stats.users['online_percentage']:.1f}%")
print(f"Total messages: {stats.messages['total']}")
print(f"Messages last 24h: {stats.messages['last_24h']}")

# Активность пользователей
user_activity = await client.get_user_activity_stats()
print(f"User activity: {user_activity}")

# Тренды сообщений
message_trends = await client.get_message_trends()
print(f"Message trends: {message_trends}")
```

## 🧪 Тестирование

### Запуск тестов

```bash
# Все тесты
pytest

# С покрытием
pytest --cov=SDK

# Асинхронные тесты
pytest --asyncio-mode=auto

# Конкретный модуль
pytest SDK/tests/test_crypto.py
```

### Примеры тестирования

```python
import pytest
from SDK import EventHorizonClient, ClientConfig

@pytest.mark.asyncio
async def test_client_initialization():
    config = ClientConfig(did="test:user123")
    async with EventHorizonClient(config=config) as client:
        assert client.is_initialized() == True
        assert client.config.did == "test:user123"

@pytest.mark.asyncio
async def test_message_sending():
    config = ClientConfig(did="test:sender")
    async with EventHorizonClient(config=config) as client:
        # Тест отправки сообщения
        pass
```

## 🔧 Разработка

### Структура проекта

```bash
# Клонирование
git clone <repository>
cd Event-Horizon-chat/SDK

# Установка зависимостей разработки
pip install -r requirements.txt

# Форматирование кода
black .
isort .

# Проверка качества
flake8
mypy .

# Запуск тестов
pytest
```

### Добавление новых функций

1. **Создайте модуль** в соответствующей директории
2. **Добавьте тесты** в `tests/`
3. **Обновите документацию** в README
4. **Добавьте примеры** в `examples/`

## 📖 API Reference

### Основные классы

- **`EventHorizonClient`** - главный клиент SDK
- **`ClientConfig`** - конфигурация клиента
- **`CryptoManager`** - управление криптографией
- **`KeyManager`** - управление ключами
- **`MessageManager`** - работа с сообщениями
- **`WebSocketClient`** - WebSocket соединения
- **`SystemManager`** - системные операции

### Исключения

- **`EventHorizonError`** - базовое исключение SDK
- **`AuthenticationError`** - ошибки аутентификации
- **`NetworkError`** - сетевые ошибки
- **`CryptoError`** - криптографические ошибки
- **`ConfigurationError`** - ошибки конфигурации
- **`ValidationError`** - ошибки валидации

## 🚀 Производительность

### Оптимизации

- **Асинхронные операции** - неблокирующие вызовы
- **Connection pooling** - переиспользование соединений
- **Rate limiting** - защита от перегрузки
- **Retry logic** - автоматические повторы при ошибках
- **Background tasks** - фоновые задачи для WebSocket

### Мониторинг

```python
# Проверка производительности
ping_time = await client.ping_server()
print(f"Server response time: {ping_time:.2f}ms")

# Статус real-time соединения
if client.is_realtime_running():
    print("Real-time messaging is active")
```

## 🔒 Безопасность

### Рекомендации

1. **Используйте HTTPS** в продакшене
2. **Настройте CORS** для ваших доменов
3. **Регулярно обновляйте** зависимости
4. **Мониторьте логи** на подозрительную активность
5. **Используйте сильные ключи** (2048+ бит)

### Криптография

- **RSA-2048/4096** для асимметричного шифрования
- **AES-256** для симметричного шифрования
- **OAEP padding** для RSA
- **PKCS7 padding** для AES
- **SHA-256** для хеширования

## 📄 Лицензия

Этот SDK лицензирован под GNU GPLv3 — см. файл [LICENSE](../LICENSE) для подробностей.

---

**Event Horizon Python SDK** - где безопасность встречается с простотой! 🚀🔐

## 🤝 Поддержка

- **Документация**: [Event Horizon Chat README](../README.md)
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Wiki**: GitHub Wiki
