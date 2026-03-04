# Logger 模組

## 目的

提供統一的輸出格式與除錯分級，讓 GUI、Daemon、IPC 訊息可追蹤。

## 核心職責

- 分級輸出（一般資訊、警告、錯誤、詳細協議內容）
- 維護歷史緩衝，支援 GUI 輪詢顯示
- 在大量訊息場景下保持可讀性

## 使用情境

- Daemon 啟動與關閉流程
- Broker 連線狀態變更
- USP request/response 調試追蹤