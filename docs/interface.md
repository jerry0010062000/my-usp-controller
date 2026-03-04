# Interface 模組

## 目的

定義使用者操作面（GUI）與執行面（Daemon）之間的互動邊界。

## 分層責任

- **GUI 層**：輸入操作、顯示狀態、維持操作流程
- **IPC 層**：將 GUI 命令送到 Daemon，並回收 JSON 結果
- **Daemon 層**：執行 USP 與 broker 實際邏輯

## 設計重點

- GUI 不直接操作 USP 協議細節
- Daemon 不承擔 GUI 排版邏輯
- IPC 命令介面保持可擴展（status/get/set/reload 等）