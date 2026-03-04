# Config 模組

## 目的

集中管理 `config.json` 的載入、儲存與基本驗證，確保 GUI 與 Daemon 使用一致設定。

## 核心職責

- 載入設定：讀取 JSON 並提供預設值回退
- 儲存設定：將使用者操作寫回 `config.json`
- 驗證設定：檢查 `usp_controller` 區塊與必要欄位

## 重點欄位

- `usp_controller.controller_endpoint_id`
- `usp_controller.receive_topic`
- `usp_controller.broker_host` / `broker_port`
- `mini_broker.enable` / `host` / `port`
- `ipc.host` / `ipc.port`