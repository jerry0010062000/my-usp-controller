# Configuration Module

## 概述

提供類型安全的配置管理，使用 Python dataclass 實現。

## 主要類

### `ControllerConfig`
主配置類，包含：
- `controller_endpoint_id`: Controller 端點 ID
- `transport`: 傳輸層配置
- `ipc`: IPC 服務配置
- `scripting`: 腳本引擎配置
- `debug_level`: 調試級別 (0-2)

### `TransportConfig`
傳輸層配置：
- `protocol`: 協議類型 (stomp, mqtt)
- `broker_host`: Broker 主機
- `broker_port`: Broker 端口
- `username/password`: 認證資訊
- `queue_name`: 訂閱佇列
- `reply_to_queue`: 回覆佇列

## 使用方式

```python
from usp_controller.config import load_config

# 載入配置文件
config = load_config("config.json")

# 訪問配置
print(config.controller_endpoint_id)
print(config.transport.broker_host)
```

## 配置文件範例

參見專案根目錄的 `config.example.json`

## 相關文件

- `usp_controller/config.py` - 實現代碼
- `config.example.json` - 配置範例
