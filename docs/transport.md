# Transport Module

## 概述

傳輸層抽象，支援多種協議（STOMP, MQTT, WebSocket）。

## 架構設計

```
TransportProtocol (ABC)
├── STOMPTransport (已實現)
├── MQTTTransport (接口保留)
└── WebSocketTransport (未來)
```

## 主要類

### `TransportProtocol` (抽象基類)
定義所有傳輸協議必須實現的接口：
- `connect()`: 建立連接
- `disconnect()`: 斷開連接
- `subscribe()`: 訂閱目的地
- `send()`: 發送訊息
- `set_message_callback()`: 設置訊息回調

### `TransportState` (狀態枚舉)
- `DISCONNECTED`: 未連接
- `CONNECTING`: 連接中
- `CONNECTED`: 已連接
- `DISCONNECTING`: 斷開中
- `ERROR`: 錯誤狀態

### `TransportFactory` (工廠類)
動態創建傳輸協議實例。

## 使用方式

```python
from usp_controller.transport import TransportFactory

# 創建 STOMP 傳輸
transport = TransportFactory.create('stomp', {
    'broker_host': '127.0.0.1',
    'broker_port': 61613,
    'username': 'admin',
    'password': 'admin'
})

# 設置回調
transport.set_message_callback(on_message_received)
transport.set_state_callback(on_state_changed)

# 連接和訂閱
transport.connect()
transport.subscribe('/queue/usp.controller')

# 發送訊息
transport.send('/queue/usp.agent', message_bytes)
```

## 已實現協議

### STOMP 1.2
- 完整實現
- 支援心跳機制
- 自動重連（可選）

### MQTT
- 接口保留，未來實現

## 相關文件

- `usp_controller/transport/base.py` - 抽象基類
- `usp_controller/transport/stomp.py` - STOMP 實現
- `usp_controller/transport/mqtt.py` - MQTT 接口
