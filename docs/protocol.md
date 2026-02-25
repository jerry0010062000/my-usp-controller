# Protocol Module

## 概述

USP 協議層，負責 USP 訊息的構建和解析（基於 TR-369 規範）。

## 主要類

### `USPMessage`
USP 訊息構建器，支援所有 USP 操作類型。

## 支援的操作

### GET
獲取參數值：
```python
record_bytes = USPMessage.create_get(
    endpoint_id="agent-001",
    paths=["Device.DeviceInfo.", "Device.Ethernet."]
)
```

### SET
設置參數值：
```python
record_bytes = USPMessage.create_set(
    endpoint_id="agent-001",
    params={
        "Device.X.Parameter": "value"
    }
)
```

### ADD
添加對象實例：
```python
record_bytes = USPMessage.create_add(
    endpoint_id="agent-001",
    obj_path="Device.DHCPv4.Server.Pool.",
    params={"Enable": "true"}
)
```

### DELETE
刪除對象實例：
```python
record_bytes = USPMessage.create_delete(
    endpoint_id="agent-001",
    obj_paths=["Device.DHCPv4.Server.Pool.1."]
)
```

### GET_INSTANCES
獲取對象實例：
```python
record_bytes = USPMessage.create_get_instances(
    endpoint_id="agent-001",
    obj_paths=["Device.Ethernet.Interface."]
)
```

### GET_SUPPORTED_DM
獲取支援的數據模型：
```python
record_bytes = USPMessage.create_get_supported_dm(
    endpoint_id="agent-001",
    obj_paths=["Device."],
    return_commands=True,
    return_events=True,
    return_params=True
)
```

### OPERATE
執行命令：
```python
record_bytes = USPMessage.create_operate(
    endpoint_id="agent-001",
    command_path="Device.Reboot()",
    args={"Cause": "Upgrade"}
)
```

## 訊息解析

```python
from_id, to_id, usp_msg = USPMessage.parse_record(record_bytes)

# 檢查訊息類型
if usp_msg.body.HasField('response'):
    # 處理響應
    pass
elif usp_msg.body.HasField('request'):
    # 處理請求
    pass
```

## USP Record 封裝

所有 USP 訊息都封裝在 Record 中：
- `version`: "1.4"
- `to_id`: 目標端點 ID
- `from_id`: 來源端點 ID
- `payload_security`: PLAINTEXT
- `payload`: 序列化的 USP 訊息

## 相關文件

- `usp_controller/protocol/__init__.py` - 實現代碼
- `usp_msg_1_4_pb2.py` - USP Message Protobuf
- `usp_record_1_4_pb2.py` - USP Record Protobuf
