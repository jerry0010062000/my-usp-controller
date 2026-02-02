# mDNS Service Discovery for USP

## 概述

USP Controller 現在支持使用 mDNS (Multicast DNS) / Zeroconf 自動發現本地網路中的 USP Agent。

## 安裝

```bash
pip install zeroconf
# 或
pip install -r requirements.txt
```

## 功能特性

### 自動發現
- 自動偵測網路中廣播 `_usp-agent._tcp.local.` 服務的 USP Agent
- 提取端點 ID、地址、端口等資訊
- 自動註冊到 devices.json

### GUI 控制
在 **Settings & Debug** 標籤的 **mDNS Agent Discovery** 區塊中：
- **Start Discovery**: 啟動 mDNS 監聽
- **Stop Discovery**: 停止 mDNS 監聽
- **Check Status**: 查看當前狀態

### 狀態指示
- 🟢 **Running**: mDNS 正在運行，監聽中
- ⚪ **Enabled**: 已啟用但未啟動
- ❌ **Not Available**: zeroconf 未安裝
- ⚪ **Disabled**: 配置中已停用

## 配置

在 `config.json` 中設定：

```json
{
  "usp_controller": {
    "enable_mdns_discovery": true
  }
}
```

## USP Agent 需求

Agent 需要廣播 mDNS 服務，TXT 記錄應包含：

```
Service Type: _usp-agent._tcp.local.
TXT Records:
  - endpoint=<endpoint_id>   (或 id=<endpoint_id>)
  - path=/usp                (可選，預設為 /usp)
```

## IPC 命令

```bash
# 查看狀態
mdns_status

# 啟動發現
mdns_start

# 停止發現
mdns_stop
```

## 日誌範例

```
[✓] mDNS discovery started - listening for USP agents
[*] mDNS: Agent discovered - proto::agent-001
[*]   Address: 192.168.1.100:8080
[*]   Path: /usp
[✓] Auto-registered device via mDNS: proto::agent-001
```

## 注意事項

1. **防火牆**: 確保允許 UDP 5353 端口 (mDNS)
2. **網路**: 僅限同一本地網路
3. **自動註冊**: 發現的設備會自動加入 devices.json
4. **STOMP 整合**: 發現後仍需通過 STOMP 進行通訊

## 故障排除

### "zeroconf not installed"
```bash
pip install zeroconf
```

### 找不到 Agent
- 確認 Agent 有廣播 mDNS 服務
- 檢查防火牆設定
- 確認在同一網段
- 使用 `avahi-browse` 或 `dns-sd` 工具驗證

### 自動註冊但無法通訊
- mDNS 只負責發現，通訊仍需 STOMP broker
- 檢查 reply_to 地址是否正確
- 查看 daemon 日誌確認 STOMP 連線狀態
