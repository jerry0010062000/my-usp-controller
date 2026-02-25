# USP Controller

Python 實現的 TR-369 USP (User Services Platform) Controller。

## ✨ 特性

- ✅ 完整 TR-369 USP 協議支援
- ✅ 模組化架構設計（可擴展）
- ✅ 多種傳輸協議（STOMP, MQTT 接口）
- ✅ 統一介面層（CLI/GUI/Web）
- ✅ 智能腳本引擎
- ✅ 跨平台支援（Windows/Linux/macOS）

## 🚀 快速開始

### 安裝依賴

```bash
pip install -r requirements.txt
```

### 配置

複製範例配置並修改：

```bash
cp config.example.json config.json
```

編輯 `config.json` 設定 broker 連接資訊。

### 運行

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

## 🔧 使用示例

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
