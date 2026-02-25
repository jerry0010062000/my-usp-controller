# Scripting Module

## 概述

智能腳本引擎，支援變量替換和路徑自動推斷。

## 智能級別

### Level 0: 基本模式
- 直接執行命令，不做任何處理
- 適合精確控制

### Level 1: 簡單映射
- 支援變量替換
- 基本路徑驗證

### Level 2: 完全智能（推薦）
- 變量替換
- 路徑自動推斷（部分路徑 → 完整路徑）
- 參數名自動補全
- 對象路徑末尾自動添加 `.`

## 使用方式

```python
from usp_controller.scripting import SmartScriptEngine

# 創建引擎（智能級別 2）
engine = SmartScriptEngine(intelligence_level=2)

# 解析腳本
script_content = """
# 設置變量
$AGENT = proto::agent-001
$DHCP_PATH = Device.DHCPv4.Server.Pool.1

# 使用變量
get $AGENT $DHCP_PATH.Enable
set $AGENT DeviceInfo.FriendlyName "My Device"
add $AGENT DHCPv4.Server.Pool Enable=true
"""

commands = engine.parse_script(script_content)

# 執行命令
for cmd in commands:
    print(f"Command: {cmd.command}")
    print(f"Args: {cmd.args}")
```

## 腳本語法

### 註釋
```bash
# 這是註釋
// 這也是註釋
```

### 變量定義
```bash
$VAR_NAME = value
```

### 命令格式
```bash
get <endpoint> <path>
set <endpoint> <path> <value>
add <endpoint> <obj_path> [param=value...]
delete <endpoint> <obj_path>
discover <endpoint> [obj_path]
operate <endpoint> <command> [arg=value...]
```

## 路徑智能推斷

在智能級別 2 下：

```bash
# 輸入簡化路徑
set agent-001 DeviceInfo.FriendlyName "Test"

# 自動推斷為
set agent-001 Device.DeviceInfo.FriendlyName "Test"

# 對象路徑自動添加末尾點
add agent-001 DHCPv4.Server.Pool Enable=true
# 推斷為
add agent-001 Device.DHCPv4.Server.Pool. Enable=true
```

## 相關文件

- `usp_controller/scripting/__init__.py` - 實現代碼
- `scripts/` - 腳本示例目錄
