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

## 使用方式

### Windows GUI 圖形介面（推薦）

**前提：** 先啟動 daemon 模式

```powershell
# 1. 啟動 daemon（背景執行）
python usp_controller.py --daemon

# 2. 啟動 GUI
python usp_gui.py
```

**GUI 功能：**
- 📊 **即時監控**：設備狀態、連線狀態、即時日誌
- 🎮 **互動操作**：Get/Set 參數、命令執行、歷史記錄
- ⚙️ **設定管理**：Broker 配置、Debug 級別、mDNS 控制
- 🔍 **mDNS 發現**：自動掃描網路上的 USP Agent、服務監控
- 📝 **日誌查看**：支援右鍵複製、自動捲動、多層級顯示
- 🎯 **命令歷史**：儲存執行過的命令、快速重新執行

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

### Daemon 模式 + IPC 客戶端

```bash
# 啟動 daemon
./usp_controller.py --daemon &

# 使用 IPC 客戶端
./usp_client.py status
./usp_client.py get <endpoint_id> <path>
./usp_client.py set <endpoint_id> <path> <value>
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
    "devices_file": "devices.json",
    "enable_mdns_discovery": true
  },
  "ipc": {
    "host": "127.0.0.1",
    "port": 6001
  }
}
```

Agent 會主動註冊到 controller，無需手動配置 destination。

## 功能特色

### 🔍 mDNS 自動發現
- 自動掃描區網 USP Agent（`_usp-agent._tcp.local.`）
- 被動監聽 + 主動掃描雙模式
- 發現後自動註冊到 devices.json
- 詳細文檔：[MDNS_DISCOVERY.md](MDNS_DISCOVERY.md)

### 🖥️ Windows GUI
- Tkinter 原生介面，無需額外安裝
- 三大功能分頁：監控、設定、mDNS Debug
- 即時日誌、命令歷史、右鍵複製
- 完整 IPC 整合

### 🔧 多模式運行
- **互動 Shell**：人工操作測試
- **Daemon + IPC**：自動化腳本
- **GUI 介面**：視覺化管理

---

**詳細文檔：** [ADVANCED.md](ADVANCED.md)  
**版本：** 2.0.4 | **協定：** USP 1.4 / STOMP 1.2

## v2.0.4 新功能

### 測試腳本自動化
```bash
# CLI 執行
python scripts/run_test.py --script test_dhcpv4_pool.txt --endpoint proto::agent-id

# GUI 執行
Test Scripts 標籤頁 → 選擇腳本 → 選擇設備 → Run Script
```

**腳本語法：**
```
# 註解說明
get {ENDPOINT} Device.Path.Param                     # 變數替換
get_instances {ENDPOINT} Device.Path.{INSTANCE}.     # 動態 instance
set {ENDPOINT} Device.Path.Param value # expect: OK  # 斷言驗證
```

**特性：**
- 變數：`{ENDPOINT}` 目標設備、`{INSTANCE}` 自動提取
- 斷言：`# expect: value` 驗證回應內容
- 同步等待：GET/GetInstances 等待實際回應（15秒 timeout）
- 重複保護：等待期間防止重複發送相同請求

### IPC 穩定性提升
- 客戶端 timeout 20秒（適配長時間等待）
- 伺服器錯誤處理增強（timeout/BrokenPipe/socket 錯誤）
- 連線重試機制

### 回應追蹤系統
- GET 返回實際參數值（非 "GET sent"）
- GetInstances 返回 instance 清單
- 回應格式：`{"status": "ok", "msg": "...", "data": {...}, "instances": [...]}`