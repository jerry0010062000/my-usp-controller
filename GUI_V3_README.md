# USP Controller V3.0 - Multi-Page GUI

## 新架构说明

这是USP Controller的重构版本，采用**嵌入式多页面架构**，将所有功能集成到单个GUI应用中。

## 主要特性

### ✅ 单进程架构
- GUI、Broker、Daemon都在一个进程中运行
- 无需额外启动daemon进程
- 简化部署和使用

### ✅ 多页面设计

#### 💻 CLI Terminal（默认页面）
- **黑底绿字的终端风格界面**
- **命令历史记录**（保存到`command_history.json`）
  - 使用↑↓箭头键浏览历史
  - 双击历史项加载到输入框
  - 右键菜单：加载、执行、删除
- **快捷命令面板**
  - 目标设备选择器
  - USP操作按钮：GET、SET、ADD、DELETE、GetInstances、GetSupportedDM
  - 系统命令按钮：Status、Devices、Reconnect
- **三列布局**
  - 左：命令中心（输入+输出）
  - 中：快捷命令
  - 右：命令历史

#### 🌐 Broker
- Mini-Broker开关控制
- 实时启动/停止内嵌STOMP broker
- 配置管理（Host、Port）
- 外部Broker配置（当Mini-Broker关闭时）
- 状态日志显示

#### ⚙️ Daemon
- 连接状态监控
- 完整配置显示（JSON格式）
- 连接控制：Connect / Disconnect / Reconnect
- 配置热重载
- 设备列表（TreeView）

## 启动方式

### Windows
双击 `run_gui_v3.bat`

### 命令行
```bash
python usp_gui_v3.py
```

## 使用流程

### 1. 启动Broker（可选）
切换到 **Broker** 页面：
1. 检查配置（默认 0.0.0.0:61613）
2. 点击 "Start Broker"
3. 等待状态显示 "✅ Mini-Broker started successfully"

### 2. 建立连接
切换到 **Daemon** 页面：
1. 查看配置是否正确
2. 点击 "Connect" 连接broker
3. 观察状态指示器变为绿色

### 3. 使用CLI
切换到 **CLI Terminal** 页面（默认页面）：

#### 方式A：直接输入命令
```
>>> help
>>> status
>>> devices
>>> get <endpoint> Device.DeviceInfo.
```

#### 方式B：使用快捷命令
1. 在 "Target Endpoint" 下拉框选择设备
2. 在 "Path / Object" 输入参数路径
3. 点击对应的操作按钮（GET、SET等）

#### 方式C：使用历史记录
1. 在右侧"Command History"列表中找到之前的命令
2. 双击加载到输入框
3. 按Enter执行
4. 或直接右键选择"Execute"

## 命令参考

### 系统命令
| 命令 | 说明 |
|------|------|
| `help` | 显示帮助信息 |
| `clear` | 清空终端输出 |
| `status` | 显示连接状态 |
| `devices` | 列出已发现的设备 |
| `reconnect` | 重新连接broker |

### USP命令
| 命令 | 说明 |
|------|------|
| `get <endpoint> <path>` | 获取参数值 |
| `set <endpoint> <path> <value>` | 设置参数值 |
| `add <endpoint> <object>` | 添加对象实例 |
| `delete <endpoint> <object>` | 删除对象 |
| `get_instances <endpoint> <path>` | 获取对象实例 |
| `get_supported <endpoint> <path>` | 获取支持的数据模型 |

## 配置文件

配置保存在 `config.json`：

```json
{
  "usp_controller": {
    "broker_host": "127.0.0.1",
    "broker_port": 61613,
    "username": "guest",
    "password": "guest",
    "controller_endpoint_id": "proto::controller.jerry-laptop",
    "receive_topic": "/queue/usp.controller.jerry-laptop",
    "devices_file": "devices.json"
  },
  "mini_broker": {
    "enable": true,
    "host": "0.0.0.0",
    "port": 61613
  }
}
```

## 与旧版本比较

| 功能 | V2.0 (旧版) | V3.0 (新版) |
|------|------------|------------|
| 架构 | IPC多进程 | 嵌入式单进程 |
| 启动步骤 | 3步（Broker→Daemon→GUI） | 1步（启动GUI） |
| CLI界面 | 无 | ✅ 默认页面 |
| 命令历史 | 分散在旧GUI | ✅ 完整集成 |
| 快捷命令 | 分散的下拉框 | ✅ 专用面板 |
| 配置管理 | 混乱 | ✅ 分页清晰 |

## 独立运行模式

仍然支持传统的独立运行：

```bash
# CLI模式（独立运行）
python usp_controller.py

# Daemon模式（独立后台服务）
python usp_controller.py --daemon
```

## 技术架构

```
usp_gui_v3.py (主程序)
├── usp_core.py (核心配置模块)
├── tools/embedded_broker.py (内嵌Broker)
└── usp_controller.py (USP协议实现)

分页结构：
├── CLIPage (默认) - 命令行界面
├── BrokerPage - Broker管理
└── DaemonPage - 连接管理
```

## 下一步开发

- [ ] 集成真实的STOMP连接到Daemon页面
- [ ] CLI命令连接到实际的USP操作
- [ ] 设备发现和管理
- [ ] 实时日志显示

## 许可

与主项目相同
