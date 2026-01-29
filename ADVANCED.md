# USP Controller 進階文檔

## 核心組件

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

## 設定檔

### config.json

```json
{
  "usp_controller": {
    "broker_host": "127.0.0.1",
    "broker_port": 61613,
    "username": "guest",
    "password": "guest",
    "controller_endpoint_id": "proto::controller-jerry-laptop",
    "receive_topic": "/queue/usp/controller/jerry-laptop",
    "devices_file": "devices.json"
  },
  "ipc": {
    "host": "127.0.0.1",
    "port": 6001
  }
}
```

### devices.json

自動生成的設備清單，記錄已發現的 USP Agent：

```json
{
  "proto::agent-001": {
    "endpoint_id": "proto::agent-001",
    "reply_to": "/queue/proto::agent-001",
    "last_seen": "2026-01-13 10:30:45"
  }
}
```

Agent 會主動告知 controller 其 `reply_to` destination，controller 會記錄在此檔案中。

## 完整命令參考

### 互動模式

| 命令 | 別名 | 說明 | 範例 |
|------|------|------|------|
| `help` | `h` | 顯示命令說明 | `help` |
| `list` | `ls` | 列出已知設備 | `list` |
| `status` | - | 顯示連線狀態 | `status` |
| `get` | - | 讀取參數 | `get proto::agent-001 Device.DeviceInfo.` |
| `set` | - | 設定參數 | `set proto::agent-001 Device.X_CUSTOM.Enable true` |
| `add` | - | 新增物件 | `add proto::agent-001 Device.WiFi.SSID.` |
| `delete` | - | 刪除物件 | `delete proto::agent-001 Device.WiFi.SSID.1.` |
| `operate` | - | 執行命令 | `operate proto::agent-001 Device.Reboot()` |
| `get_instances` | - | 取得物件實例 | `get_instances proto::agent-001 Device.WiFi.SSID.` |
| `get_supported` | `gsdm` | 取得支援的數據模型 | `get_supported proto::agent-001 Device.` |
| `discover` | `disc` | 觸發設備發現 | `discover` |
| `send` | - | 傳送原始訊息 | `send /topic/test "hello"` |
| `debug` | - | 調整顯示層級 (0-2) | `debug 1` |
| `clear` | - | 清除螢幕 | `clear` |
| `quit` | `exit`, `q` | 離開程式 | `quit` |

### IPC 命令（Daemon 模式）

透過 `usp_client.py` 呼叫：

```bash
# 查詢狀態
./usp_client.py status

# 列出設備
./usp_client.py devices

# USP 操作
./usp_client.py get <endpoint_id> <path>
./usp_client.py set <endpoint_id> <path> <value>
./usp_client.py add <endpoint_id> <path>
./usp_client.py delete <endpoint_id> <path>
./usp_client.py operate <endpoint_id> <command>
./usp_client.py get_instances <endpoint_id> <path>
./usp_client.py get_supported <endpoint_id> <path>
```

## Debug Level 系統

控制器提供 3 個 debug level：

| Level | 名稱 | 顯示內容 |
|-------|------|----------|
| **0** | Agent Only | 只顯示 agent 回應數據 (DM 值) **預設** |
| **1** | Both Payloads | 顯示 controller 請求 + agent 回應 (USP 訊息) |
| **2** | Full Details | 完整 STOMP headers + payloads |

### 使用方式

```bash
usp-cli> debug        # 查看目前 level
usp-cli> debug 0      # 只看結果
usp-cli> debug 1      # 看雙向 USP 訊息
usp-cli> debug 2      # 看完整 STOMP 訊息
```

### 輸出範例

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
  Path: Device.DeviceInfo. (✓)
```

## AI 工具整合

### Python 範例

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

### 回應格式

```json
{
  "status": "ok",
  "connected": true,
  "devices_count": 2,
  "last_active": "proto::agent-001"
}
```

## 檔案結構

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
├── README.md                 # 快速入門
├── ADVANCED.md               # 本文件（進階說明）
├── WINDOWS_INSTALL.md        # Windows 安裝指南
├── tools/                    # 測試與開發工具
│   ├── mock_agent.py         # USP Agent 模擬器
│   ├── collect_dm.py         # 數據模型收集工具
│   ├── debug_proto.py        # 協定除錯工具
│   └── ...                   # 其他測試腳本
```

## 常見問題

### Q: "Address already in use" 錯誤？

Daemon 已在背景運行。使用 `--force` 終止舊 daemon：
```bash
./usp_controller.py --daemon --force
```

### Q: 如何查看是否有 daemon 運行？

**Windows:**
```powershell
Get-Process | Where-Object {$_.CommandLine -like "*usp_controller*"}
```

**Linux:**
```bash
ps aux | grep "usp_controller.py --daemon"
cat /tmp/usp_controller.pid
```

### Q: 互動模式能與 daemon 同時使用嗎？

可以！互動模式不啟動 IPC Server，不會衝突。

### Q: 測試工具在哪裡？

在 `tools/` 目錄中：
- `mock_agent.py` - Agent 模擬器
- `collect_dm.py` - 數據模型收集
- `trigger_discovery.py` - 設備發現（已廢棄）
- 更多工具請查看 `tools/README.md`

### Q: Agent 如何註冊到 Controller？

Agent 發送 USP 訊息時會在 STOMP header 中帶 `reply-to` destination，controller 會自動記錄到 `devices.json`。不需要手動配置。

## 開發資訊

- **版本**：2.0.1
- **作者**：Jerry Bai
- **協定**：USP 1.4 (User Services Platform)
- **傳輸**：STOMP 1.2
- **序列化**：Protocol Buffers
