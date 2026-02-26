# USP Controller

Python 實現的 TR-369 USP (User Services Platform) Controller。

## ✨ 特性

- ✅ 完整 TR-369 USP 協議支援
- ✅ 模組化架構設計（可擴展）
- ✅ 多種傳輸協議（STOMP, MQTT 接口）
- ✅ 統一介面層（CLI/GUI/Web）
- ✅ 智能腳本引擎
- ✅ 跨平台支援（Windows/Linux/macOS）
- 🆕 **GUI 內建 Broker 控制**（一鍵啟動/停止，開發測試更便捷）

## 🚀 快速開始

### 方式 1：一鍵啟動完整環境（最簡單）

**雙擊啟動**，無需任何配置：

```bash
# Windows: 雙擊批次檔
start_dev.bat

# Linux/Mac: 執行腳本
python start_dev.py
```

這會自動啟動：
- 🔧 Mini-Broker (STOMP)
- 🔄 USP Controller Daemon
- 🖥️ GUI 界面

✅ **所有服務自動管理**，關閉 GUI 會自動停止所有服務。

⚠️ **注意**：Mini-Broker 僅供開發測試，生產環境請使用 `--no-broker` 並配置 ActiveMQ/RabbitMQ。

---

### 方式 2：使用外部 Broker（生產環境）

#### 1. 啟動外部 Broker

**Docker (推薦):**
```bash
docker run -d --name activemq \
  -p 61613:61613 -p 8161:8161 \
  rmohr/activemq
```

**或手動安裝 ActiveMQ:**
- 下載：https://activemq.apache.org/
- 默認 STOMP 端口：61613

#### 2. 配置

修改 `config.json` 中的 broker 設定：

```json
{
  "usp_controller": {
    "broker_host": "127.0.0.1",
    "broker_port": 61613,
    "username": "guest",
    "password": "guest"
  }
}
```

#### 3. 啟動服務

```bash
# 使用外部 Broker
python start_dev.py --no-broker

# 或分別啟動
python usp_controller.py --daemon
python usp_gui.py
```

---

### 方式 3：手動安裝（開發者）

#### 1. 安裝依賴

```bash
pip install -r requirements.txt
```

#### 2. 安裝 Message Broker

選擇一個：

**Docker (推薦):**
```bash
docker run -d --name activemq \
  -p 61613:61613 -p 8161:8161 \
  rmohr/activemq
```

**或手動安裝 ActiveMQ:**
- 下載：https://activemq.apache.org/
- 默認 STOMP 端口：61613

#### 3. 配置

複製範例配置並修改：

```bash
cp config.example.json config.json
```

編輯 `config.json` 設定 broker 連接資訊。

#### 4. 運行

**CLI 模式（推薦）：**
```bash
python usp_main.py
```

**傳統模式：**
```bash
python usp_controller.py
```

**GUI 模式：**
```bash
# Terminal 1: 啟動 daemon
python usp_controller.py --daemon

# Terminal 2: 啟動 GUI
python usp_gui.py
```

## 📖 文檔

### 模組文檔（docs/）
- [config.md](docs/config.md) - 配置管理
- [logger.md](docs/logger.md) - 日誌系統
- [transport.md](docs/transport.md) - 傳輸層
- [protocol.md](docs/protocol.md) - USP 協議層
- [scripting.md](docs/scripting.md) - 腳本引擎
- [interface.md](docs/interface.md) - 介面層

### 快速參考

**USP 操作：**
```bash
get <endpoint> <path>           # 獲取參數
set <endpoint> <path> <value>   # 設置參數
add <endpoint> <obj_path>       # 添加對象
delete <endpoint> <obj_path>    # 刪除對象
discover <endpoint> [path]      # 發現數據模型
operate <endpoint> <command>    # 執行命令
```

**系統命令：**
```bash
help                    # 幫助
list                    # 列出設備
status                  # 狀態資訊
debug [0-2]            # 調試級別
quit                    # 退出
```

## 📁 專案結構

```
my-usp-controller/
├── usp_controller/         # 核心模組（模組化架構）
│   ├── config.py          #   配置管理
│   ├── logger.py          #   日誌系統
│   ├── transport/         #   傳輸層
│   ├── protocol/          #   協議層
│   ├── scripting/         #   腳本引擎
│   └── interface/         #   介面層
├── usp_main.py            # 新版主程式（推薦）
├── usp_controller.py      # 傳統主程式（向後兼容）
├── usp_gui.py             # GUI 應用
├── tests/                 # 測試文件
├── scripts/               # 腳本和工具
├── docs/                  # 模組文檔
└── config.json            # 配置文件
```

##  使用示例

### Python API

```python
from usp_controller.config import load_config
from usp_controller.interface import create_cli_interface

# 載入配置
config = load_config("config.json")

# 創建 CLI 介面
cli = create_cli_interface()
cli.initialize()
cli.run()
```

### 批次腳本

創建 `script.txt`：
```bash
# 變量定義
$AGENT = proto::agent-001

# 操作命令
get $AGENT Device.DeviceInfo.
set $AGENT Device.X.Parameter "value"
```

執行：
```bash
python scripts/run_test.py --script script.txt
```

## 🧪 測試

```bash
# 測試模組化架構
python tests/test_v3_architecture.py

# 測試介面層
python tests/test_interface_layer.py

# 查看使用示例
python tests/example_interface_usage.py
```

## 📋 需求

- Python 3.7+
- 標準庫（無額外依賴）

**可選增強：**
- `prompt_toolkit` - 增強 CLI（自動補全、歷史）
- `rich` - 進階終端輸出

## 📄 授權

MIT License

## 🤝 貢獻

歡迎提交 Issue 和 Pull Request。
