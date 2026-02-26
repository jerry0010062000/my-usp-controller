# CLI交互式功能测试指南

## 已实现的功能

### ✅ 真实命令执行
CLI现在通过IPC连接到daemon，可以执行真实的USP命令

### ✅ 命令历史优化
- 历史记录保存为**纯文本命令列表**（不再是JSON dump）
- 格式：`["command1", "command2", ...]`
- 可直接从历史中加载和执行

### ✅ 后台设备轮询
- 自动每3秒查询daemon状态
- 自动更新设备列表到快捷命令面板

## 测试步骤

### 1. 启动Daemon

首先需要启动daemon（在新的PowerShell窗口）：

```powershell
cd my-usp-controller
python usp_controller.py --daemon --force
```

或者使用Broker页面启动Mini-Broker，然后启动daemon。

### 2. 启动GUI

```powershell
python usp_gui_v3.py
# 或双击 run_gui_v3.bat
```

### 3. 使用CLI功能

#### 测试系统命令

在CLI Terminal页面输入：

```
>>> status
```

应该显示：
```
Connection Status:
  Connected: true/false
  Devices: 0
```

```
>>> devices
```

应该显示已发现的设备列表（如果有）。

```
>>> reconnect
```

重新连接broker。

#### 测试USP命令

假设有设备 `proto::agent.test`：

```
>>> get proto::agent.test Device.DeviceInfo.
```

应该返回参数值。

```
>>> get_instances proto::agent.test Device.IP.Interface.
```

应该返回实例列表。

```
>>> set proto::agent.test Device.DeviceInfo.Description "Test Device"
```

设置参数值。

#### 测试快捷命令面板

1. 在"Target Endpoint"下拉框选择设备
2. 在"Path / Object"输入 `Device.DeviceInfo.`
3. 点击"GET"按钮

命令会自动构建并执行：
```
get <endpoint> Device.DeviceInfo.
```

#### 测试命令历史

执行几个命令后：

1. 按↑键查看上一条命令
2. 按↓键查看下一条命令
3. 在右侧"Command History"列表中双击某个命令
4. 命令会加载到输入框
5. 按Enter执行

或者：
- 右键点击历史项
- 选择"Execute"直接执行
- 选择"Delete"删除该历史

## 命令格式参考

### 完整命令格式

```bash
# 系统命令
status                          # 查看状态
devices                         # 列出设备
reconnect                       # 重新连接

# USP命令
get <endpoint> <path>           # 获取参数
set <endpoint> <path> <value>   # 设置参数
add <endpoint> <object>         # 添加对象
delete <endpoint> <object>      # 删除对象
get_instances <endpoint> <path> # 获取实例
get_supported <endpoint> <path> # 获取支持的数据模型
```

### 示例命令

```bash
# 获取设备信息
get proto::agent.test Device.DeviceInfo.

# 获取所有IP接口
get_instances proto::agent.test Device.IP.Interface.

# 设置描述信息
set proto::agent.test Device.DeviceInfo.Description "My Device"

# 添加Wi-Fi SSID
add proto::agent.test Device.WiFi.SSID.

# 获取支持的数据模型
get_supported proto::agent.test Device.
```

## 响应格式

### 成功响应

```
✅ Command executed successfully
  params: {...}
```

### 错误响应

```
❌ Error: Cannot connect to daemon
   Make sure daemon is running:
   python usp_controller.py --daemon
```

### 设备列表

```
Discovered Devices (2):
  🟢 proto::agent.test1
      Last seen: 2026-02-26 10:30:45
  🔴 proto::agent.test2
      Last seen: 2026-02-25 15:20:10
```

## 历史记录文件格式

`command_history.json`:

```json
[
  "status",
  "devices",
  "get proto::agent.test Device.DeviceInfo.",
  "get_instances proto::agent.test Device.IP.Interface.",
  "reconnect"
]
```

**不再是：**
```json
{
  "history": [
    {"timestamp": "...", "command": "status", "response": {...}},
    ...
  ]
}
```

## 已修复的问题

✅ CLI可以真实执行命令（通过IPC连接daemon）
✅ 历史记录格式正确（纯文本列表）
✅ 自动更新设备列表
✅ 响应格式化显示
✅ 错误处理和提示

## 下一步建议

如果daemon未运行，CLI会显示连接错误。建议：

1. 在Broker页面先启动Mini-Broker
2. 然后在Daemon页面点击Connect
3. 或者手动启动daemon：`python usp_controller.py --daemon`

这样CLI就可以正常工作了。
