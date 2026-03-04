# Transport 模組

## 目的

封裝與 STOMP broker 的連線、訂閱、發送流程，對上層提供穩定傳輸介面。

## 核心職責

- 建立 broker 連線與重連
- 訂閱控制器接收佇列
- 傳送 USP Record 封包
- 維護已連線狀態與基本健康檢查

## 與 Mini-Broker 關係

- 開發模式下，transport 直接連到內建 Mini-Broker
- 若切換外部 broker，transport 層保持相同操作介面