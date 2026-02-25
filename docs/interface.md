# Interface Module

## 概述

統一的使用者介面抽象層，支援多平台（CLI/GUI/Web）。

## 架構設計

```
InterfaceBase (ABC)
├── CLIInterface (CLI 實現)
│   └── EnhancedCLIInterface (可選，需 prompt_toolkit)
└── GUIAdapterBase
    └── TkinterGUIAdapter (GUI 適配器)
```

## 核心組件

### 1. InterfaceBase (抽象基類)
定義所有介面必須實現的方法：
- `initialize()`: 初始化
- `run()`: 啟動主循環
- `display_output()`: 顯示輸出
- `display_error()`: 顯示錯誤
- `prompt_input()`: 獲取輸入
- `confirm_action()`: 請求確認

### 2. CommandHandler (命令處理器)
統一的命令解析和執行：
- 命令解析（支援引號、關鍵字參數）
- 命令路由
- 參數驗證
- 結果封裝

### 3. OutputFormatter (格式化器)
支援多種輸出格式：
- `TEXT`: 純文字
- `TABLE`: ASCII 表格
- `JSON`: JSON 格式
- `COLORED`: 彩色文字（跨平台）
- `RICH`: 進階格式（可選）

## 使用方式

### 基本 CLI

```python
from usp_controller.interface import create_cli_interface

# 創建 CLI
cli = create_cli_interface(
    enhanced=False,
    prompt="usp> ",
    output_format=OutputFormat.COLORED
)

# 初始化並運行
cli.initialize()
cli.run()  # 啟動互動模式
```

### 增強 CLI（需要 prompt_toolkit）

```python
# 安裝: pip install prompt_toolkit

cli = create_cli_interface(enhanced=True)
cli.initialize()
cli.run()

# 功能：
# - Tab 鍵自動補全
# - ↑↓ 瀏覽歷史
# - Ctrl+R 反向搜索
```

### 註冊自定義命令

```python
from usp_controller.interface import CommandHandler, CommandContext, CommandResult

handler = CommandHandler()

def my_command(context: CommandContext) -> CommandResult:
    return CommandResult(
        success=True,
        message="Hello!",
        data={"result": "value"}
    )

handler.register_command(
    name='hello',
    handler=my_command,
    aliases=['hi'],
    description='Say hello',
    usage='hello [name]',
    min_args=0,
    max_args=1
)
```

### 使用工廠模式

```python
from usp_controller.interface import InterfaceFactory, InterfaceType

# 創建 CLI
cli = InterfaceFactory.create(InterfaceType.CLI, prompt="usp> ")

# 創建 GUI 適配器
gui = InterfaceFactory.create(
    InterfaceType.GUI_TKINTER,
    gui_instance=my_tkinter_gui
)

# 列出可用介面
available = InterfaceFactory.list_available()
```

## 輸出格式對比

### TABLE 格式
```
┌─────────────┬────────┐
│ Endpoint    │ Status │
├─────────────┼────────┤
│ agent-001   │ Online │
└─────────────┴────────┘
```

### JSON 格式
```json
{"endpoint": "agent-001", "status": "Online"}
```

### COLORED 格式
```
✓ agent-001: Online  (綠色)
✗ agent-002: Offline (紅色)
```

## 跨平台支援

- **Windows**: 自動啟用 ANSI 顏色支援（Windows 10+）
- **Linux**: 完整 ANSI 顏色支援
- **macOS**: 完整支援所有功能

## 相關文件

- `usp_controller/interface/base.py` - 抽象基類
- `usp_controller/interface/cli.py` - CLI 實現
- `usp_controller/interface/command_handler.py` - 命令處理器
- `usp_controller/interface/formatter.py` - 格式化器
- `usp_controller/interface/gui_adapter.py` - GUI 適配器
- `tests/example_interface_usage.py` - 使用示例
- `tests/test_interface_layer.py` - 測試套件
