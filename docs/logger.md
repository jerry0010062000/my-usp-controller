# Logger Module

## 概述

執行緒安全的日誌系統，支援多級別日誌和歷史記錄。

## 主要功能

### 日誌級別
- `CRITICAL` (0): 嚴重錯誤
- `ERROR` (1): 錯誤訊息
- `SUCCESS` (2): 成功訊息
- `INFO` (3): 一般訊息
- `DEBUG` (4): 調試訊息

### 日誌類型
- `critical()`: 嚴重錯誤
- `error()`: 錯誤
- `success()`: 成功
- `info()`: 資訊
- `data()`: 數據輸出
- `usp_message()`: USP 協議訊息

## 使用方式

```python
from usp_controller.logger import get_logger, set_debug_level

# 獲取 Logger 實例（單例模式）
logger = get_logger()

# 設置調試級別
set_debug_level(1)  # 0: Agent Only, 1: Both Payloads, 2: Full Details

# 記錄日誌
logger.info("Connection established", level=0)
logger.error("Failed to connect")
logger.success("Operation completed")

# USP 訊息日誌
logger.usp_message("send", endpoint_id, "GET", {"path": "Device."})

# 獲取歷史記錄
history = logger.get_history(last_n=100)
```

## 特性

- **執行緒安全**: 使用 threading.Lock
- **歷史緩衝**: 保存最近 5000 條日誌
- **回調支援**: 可註冊自定義回調處理
- **單例模式**: 全局唯一實例

## 相關文件

- `usp_controller/logger.py` - 實現代碼
