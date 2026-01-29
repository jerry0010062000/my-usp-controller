# USP STOMP Controller

雙模式 USP 控制器：人工互動 + AI 自動化

支援：Linux / Raspberry Pi / Windows / macOS

## 系統架構

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

## 安裝

### Windows 用戶

**使用啟動腳本（推薦）：**
```powershell
# PowerShell (功能豐富)
.\start_controller.ps1

# 或使用 CMD
start_controller.bat
```

**或手動執行：**
```powershell
# 安裝依賴
pip install -r requirements.txt

# 運行測試
**Windows:**
```powershell
pip install -r requirements.txt
python usp_controller.py
```

**Linux / Raspberry Pi:**
```bash
pip install -r requirements.txt
./usp_controller.py
```

詳細安裝：[WINDOWS_INSTALL.md](WINDOWS_INSTALL.md)

## 
```bash
# 啟動 daemon
./usp_controller.py --daemon &
### 互動模式

```bash
./usp_controller.py
```

```
usp-cli> list                              # 列出設備
usp-cli> status                            # 連線狀態
usp-cli> get <endpoint_id> <path>          # 讀取參數
usp-cli> set <endpoint_id> <path> <value>  # 設定參數
usp-cli> debug 0                           # 調整顯示層級 (0-2)
```

### Daemon 模式

```bash
./usp_controller.py --daemon
./usp_client.py status
./usp_client.py get <endpoint_id> <path>
```

## 配置

編輯 `config.json`：

```json
{
  "usp_controller": {
    "broker_host": "127.0.0.1",
    "broker_port": 61613,
    "username": "guest",
    "password": "guest",
    "controller_endpoint_id": "proto::controller-1",
    "receive_topic": "/queue/usp/controller/controller-1",
    "devices_file": "devices.json"
  },
  "ipc": {
    "host": "127.0.0.1",
    "port": 6001
  }
}
```

Agent 會主動註冊到 controller，無需手動配置 destination。

---

**詳細文檔：** [ADVANCED.md](ADVANCED.md)  
**版本：** 2.0.1 | **協定：** USP 1.4 / STOMP 1.2