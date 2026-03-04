# Protocol 模組

## 目的

處理 USP 訊息（TR-369）組包與解析，讓上層以命令語意操作而非手動處理 protobuf。

## 核心職責

- 建立 GET / SET / ADD / DELETE / OPERATE 等請求
- 封裝 USP Message 到 USP Record
- 解析 agent 回應並轉成可讀資料

## 主要資料流

1. GUI/IPC 指令觸發 Daemon 行為
2. Protocol 模組組出 USP 封包
3. 由 Transport 送到 broker/agent
4. 回應由 Protocol 解析後回傳 GUI