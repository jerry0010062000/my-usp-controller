# USP STOMP Controller

一個雙模式的 USP (User Services Platform) 控制器，支援人工互動操作與 AI 工具自動化控制。

## 🎯 設計架構

```
┌─────────────────────────────────────────────────────────┐
│                    使用場景                              │
├──────────────────────┬──────────────────────────────────┤
│   人工操作           │         AI 自動化                │
│                      │                                  │
│  互動式 Shell        │      IPC 客戶端                  │
│  ./usp_controller.py │   ./usp_client.py <cmd>          │
│         │            │            │                     │
│         └────────────┼────────────┘                     │
│                      │                                  │
│              ┌───────▼────────┐                         │
│              │  Daemon 模式    │                         │
│              │ (IPC Server)    │                         │
│              │ Port: 6001      │                         │
│              └───────┬────────┘                         │
│                      │                                  │
│              ┌───────▼────────┐                         │
│              │  STOMP Manager  │                         │
│              │  (USP Protocol) │                         │
│              └───────┬────────┘                         │
│                      │                                  │
│              ┌───────▼────────┐                         │
│              │  ActiveMQ       │                         │
│              │  STOMP Broker   │                         │
│              │  Port: 61613    │                         │
│              └─────────────────┘                         │
└─────────────────────────────────────────────────────────┘
```

## 📦 核心組件

### 1. STOMPManager
- 管理 STOMP 連接與 USP 協定通訊
- 自動訂閱主題並維護設備清單
- 處理 USP Protobuf 訊息的收發

### 2. IPCServer (Daemon 模式)
- 提供 TCP socket 介面 (預設: `127.0.0.1:6001`)
- 接收 JSON 格式命令
- 供 AI 工具或外部腳本呼叫

### 3. Interactive Shell (互動模式)
- 人工操作介面
- 支援 readline 歷史記錄
- 即時查看設備狀態與回應

## 🚀 快速開始

### 安裝依賴

```bash
pip install -r requirements.txt
```

### 基本使用

**方式 1：互動式操作（適合人工測試）**

```bash
./usp_controller.py
```

進入互動 shell 後：
```
usp-cli> help
usp-cli> list
usp-cli> status
usp-cli> get <endpoint_id> Device.DeviceInfo.
```

**方式 2：背景 Daemon（適合 AI 工具呼叫）**

```bash
# 啟動 daemon
./usp_controller.py --daemon &

# 使用 IPC 客戶端呼叫
./usp_client.py status
./usp_client.py devices
./usp_client.py get <endpoint_id> Device.DeviceInfo.
```

## 💻 命令參考

### 互動模式命令

| 命令 | 說明 | 範例 |
|------|------|------|
| `help` | 顯示命令說明 | `help` |
| `list` | 列出已知設備 | `list` |
| `status` | 顯示連線狀態 | `status` |
| `get` | 讀取參數 | `get proto::agent-001 Device.DeviceInfo.` |
| `send` | 傳送原始訊息 | `send /topic/test "hello"` |
| `exit` | 離開程式 | `exit` 或 `quit` |

### IPC 命令（Daemon 模式）

透過 `usp_client.py` 或直接 TCP socket 呼叫：

```bash
# 查詢狀態
./usp_client.py status

# 列出設備
./usp_client.py devices

# 讀取參數
./usp_client.py get <endpoint_id> <path>
```

**回應格式（JSON）：**

```json
{
  "status": "ok",
  "connected": true,
  "devices_count": 2,
  "last_active": "proto::agent-001"
}
```

## 🔧 設定檔

### devices.json

自動生成的設備清單，記錄已發現的 USP Agent：

```json
{
  "proto::agent-001": {
    "reply_to": "/queue/proto::agent-001",
    "last_seen": "2026-01-13 10:30:45"
  }
}
```

### 主要配置（usp_controller.py）

```python
BROKER_HOST = '127.0.0.1'       # ActiveMQ 地址
BROKER_PORT = 61613             # STOMP 端口
USERNAME = 'admin'              # STOMP 認證帳號
PASSWORD = 'password'           # STOMP 認證密碼

CONTROLLER_ENDPOINT_ID = 'proto::controller-1'  # Controller ID
RECEIVE_TOPIC = '/topic/my_send_q'              # 接收主題
SEND_DESTINATION = '/topic/agent'               # 預設傳送目標

IPC_HOST = '127.0.0.1'          # IPC 綁定地址
IPC_PORT = 6001                 # IPC 端口
```

## 🤖 AI 工具整合

### Gemini / Claude 使用範例

1. **啟動 Daemon 模式：**
```bash
./usp_controller.py --daemon &
```

2. **AI 工具透過 IPC 呼叫：**
```python
import socket
import json

def call_usp(command):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 6001))
    sock.sendall(command.encode('utf-8'))
    response = sock.recv(4096).decode('utf-8')
    sock.close()
    return json.loads(response)

# 查詢設備
devices = call_usp("devices")
print(devices)

# 讀取參數
result = call_usp("get proto::agent-001 Device.DeviceInfo.")
print(result)
```

## 📁 檔案結構

```
.
├── usp_controller.py         # 主程式（雙模式）
├── usp_client.py             # IPC 客戶端工具
├── config.json               # 配置文件（不納入版本控制）
├── config.example.json       # 配置範本
├── devices.json              # 設備清單（自動生成）
├── usp_msg_1_4_pb2.py        # USP Message Protobuf
├── usp_record_1_4_pb2.py     # USP Record Protobuf
├── usp-msg-1-4.proto         # Protobuf 定義
├── usp-record-1-4.proto      # Protobuf 定義
├── requirements.txt          # Python 依賴
├── tools/                    # 測試與開發工具
│   ├── mock_agent.py         # USP Agent 模擬器
│   ├── collect_dm.py         # 數據模型收集工具
│   ├── debug_proto.py        # 協定除錯工具
│   └── ...                   # 其他測試腳本
└── README.md                 # 本文件
```

## 🔍 除錯模式

### Debug Level 系統

控制器提供 3 個 debug level，可在 runtime 動態調整：

| Level | 名稱 | 顯示內容 |
|-------|------|----------|
| **0** | Agent Only | 只顯示 agent 回應數據 (DM 值) **預設** |
| **1** | Both Payloads | 顯示 controller 請求 + agent 回應 (USP 訊息) |
| **2** | Full Details | 完整 STOMP headers + payloads |

### 使用方式

**互動模式：**
```bash
usp-cli> debug        # 查看目前 level
usp-cli> debug 1      # 設定為 Both Payloads
usp-cli> debug 0      # 設定為 Agent Only（只看結果）
```

**啟動時設定：**
```bash
./usp_controller.py --debug          # 啟用舊的 DEBUG_MODE
# 建議在程式啟動後用 debug 命令調整 level
```

### Debug Level 輸出範例

**Level 0 (Agent Only):**
```
  Path: Device.DeviceInfo. (✓)
    Device.DeviceInfo.
      Manufacturer = OpenSync
      ModelName = HomeGateway
```

**Level 1 (Both Payloads):**
```
→ USP GET → proto::agent-id
← USP GET_RESP ← proto::agent-id
  Path: Device.DeviceInfo. (✓)
    Device.DeviceInfo.
      Manufacturer = OpenSync
```

**Level 2 (Full Details):**
```
>>>> STOMP Frame >>>>
  destination: /topic/agent
  content-type: application/vnd.bbf.usp.msg
  content-length: 114

→ USP GET → proto::agent-id
    msg_id: c8bd0df6-3857-449f-9c02-6bd85118fa76

<<<< STOMP Frame <<<<
  destination: /queue/controller
  content-type: application/vnd.bbf.usp.msg
  content-length: 234

← USP GET_RESP ← proto::agent-id
    msg_id: c8bd0df6-3857-449f-9c02-6bd85118fa76
  Path: Device.DeviceInfo. (✓)
```

## 🐛 常見問題

**Q: 為何出現 "Address already in use" 錯誤？**

A: Daemon 已在背景運行。使用 `--force` 自動終止舊 daemon：
```bash
./usp_controller.py --daemon --force
```

**Q: 如何查看目前是否有 daemon 運行？**

A: 使用以下命令：
```bash
ps aux | grep "usp_controller.py --daemon"
# 或查看 PID 文件
cat /tmp/usp_controller.pid
```

**Q: 互動模式能與 daemon 同時使用嗎？**

A: 可以！互動模式不啟動 IPC Server，不會衝突。

**Q: 如何調整顯示的詳細程度？**

A: 使用 `debug` 命令動態調整 level (0-2)：
```bash
usp-cli> debug 0    # 只看結果數據
usp-cli> debug 1    # 看雙向 USP 訊息
usp-cli> debug 2    # 看完整 STOMP 訊息
```

**Q: 測試腳本在哪裡？**

A: 已移至 `tools/` 目錄，保持根目錄整潔。

## 📝 開發資訊

- **版本**：2.0.0
- **作者**：Jerry Bai
- **協定**：USP 1.4 (User Services Platform)
- **傳輸**：STOMP 1.2
- **序列化**：Protocol Buffers

## 📄 授權

內部開發工具
