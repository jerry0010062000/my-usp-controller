# Scripting 模組

## 目的

支援以腳本檔批次執行 USP 操作，適合回歸測試與驗證流程。

## scripts 目錄定位

`scripts/` 僅放 USP 測試腳本資料（例如 `.txt` 測試流程檔），不放專案維運工具。

## 核心職責

- 腳本命令解析（含 endpoint/path/value）
- 批次執行與結果彙整
- 與 IPC/Daemon 協作完成實際送包