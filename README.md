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
│  Windows GUI         │      Python Script               │
│  python usp_gui.py   │   (自動化任務)                   │
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

### Windows

```powershell
pip install -r requirements.txt
```

**快速啟動（推薦）：**
```cmd
run_ui.bat
```
自動啟動 daemon + GUI

### Linux / Raspberry Pi

```bash
pip install -r requirements.txt
chmod +x usp_controller.py usp_client.py
```

## 使用方式

### Windows GUI（推薦）

```powershell
# 方法 1: 使用啟動腳本
run_ui.bat

# 方法 2: 手動啟動
python usp_controller.py --daemon
python usp_gui.py
```

**GUI 功能：**
- 📊 即時監控：設備狀態、連線狀態、即時日誌
- 🎮 互動操作：GET/SET/ADD/DELETE/GetSupportedDM/GetInstances
- 🧪 測試腳本：自動化測試執行、變數替換、斷言驗證
- ⚙️ 設定管理：Broker 配置、Debug 級別、mDNS 控制
- 🔍 mDNS 發現：自動掃描網路上的 USP Agent
- 🎯 命令歷史：儲存/載入/重新執行命令

### 互動模式

```bash
python usp_controller.py  # Windows
./usp_controller.py       # Linux
```

命令：
- `list` - 列出設備
- `status` - 連線狀態
- `get <endpoint> <path>` - 讀取參數
- `set <endpoint> <path> <value>` - 設定參數
- `get_instances <endpoint> <path>` - 列出實例
- `debug <0-2>` - 調整顯示層級

### Daemon + IPC

```bash
# 啟動 daemon
python usp_controller.py --daemon       # Windows 前景
python usp_controller.py --daemon &     # Linux 背景

# IPC 客戶端
python usp_client.py status
python usp_client.py get <endpoint> <path>
python usp_client.py set <endpoint> <path> <value>

# 測試腳本
python scripts/run_test.py --script test.txt --endpoint proto::agent-id
```

## 配置

`config.json`（參考 `config.example.json`）：

```json
{
  "usp_controller": {
    "broker_host": "127.0.0.1",
    "broker_port": 61613,
    "username": "admin",
    "password": "password",
    "controller_endpoint_id": "proto::controller-1",
    "receive_topic": "/topic/my_send_q",
    "devices_file": "devices.json",
    "enable_mdns_discovery": true,
    "heartbeat_check_enabled": true,
    "heartbeat_check_interval": 60
  },
  "ipc": {
    "host": "127.0.0.1",
    "port": 6001
  }
}
```

Agent 自動註冊，無需手動配置 destination。

## 功能特色

### 🧪 測試腳本自動化（v2.0.4）
- 變數替換：`{ENDPOINT}` `{INSTANCE}`
- 斷言驗證：`# expect: value`
- 同步等待：GET/GetInstances 等待實際回應（15秒）
- 重複保護：防止等待期間重複發送

### 🔍 mDNS 自動發現
- 自動掃描區網 USP Agent（`_usp-agent._tcp.local.`）
- 被動監聽 + 主動掃描
- 自動註冊到 devices.json

### 🖥️ Windows GUI
- Tkinter 原生介面
- 四大分頁：Operations / Settings / mDNS Debug / Test Scripts
- 命令歷史、右鍵複製、即時日誌

### 🔧 多模式運行
- 互動 Shell：人工測試
- Daemon + IPC：自動化腳本
- GUI：視覺化管理

---

**版本：** 2.0.4 | **協定：** USP 1.4 / STOMP 1.2

## v2.0.4 更新

### 測試腳本
```bash
# CLI
python scripts/run_test.py --script test_dhcpv4_pool.txt --endpoint proto::agent-id

# GUI Test Scripts 標籤頁
選擇腳本 → 選擇設備 → Run Script
```

**語法：**
```
# 註解
get {ENDPOINT} Device.Path.Param
get_instances {ENDPOINT} Device.Path.{INSTANCE}.
set {ENDPOINT} Device.Path.Param value # expect: OK
```

### 改進
- GET/GetInstances 同步等待實際回應（15秒 timeout）
- 重複請求保護
- IPC timeout 延長至 20秒
- 回應格式：`{"status": "ok", "msg": "...", "data": {...}, "instances": [...]}`