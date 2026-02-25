# 模組文檔

本目錄包含所有核心模組的詳細文檔。

## 📚 文檔索引

### 核心模組

1. **[config.md](config.md)** - 配置管理
   - 類型安全的配置系統
   - dataclass 實現
   - 配置文件載入

2. **[logger.md](logger.md)** - 日誌系統
   - 執行緒安全日誌
   - 多級別日誌支援
   - 歷史記錄管理

3. **[transport.md](transport.md)** - 傳輸層
   - 協議抽象設計
   - STOMP 實現
   - MQTT 接口保留

4. **[protocol.md](protocol.md)** - USP 協議層
   - USP 訊息構建
   - 所有操作類型支援
   - Record 封裝

5. **[scripting.md](scripting.md)** - 腳本引擎
   - 智能腳本解析
   - 變量替換
   - 路徑自動推斷

6. **[interface.md](interface.md)** - 介面層
   - 統一介面抽象
   - 跨平台 CLI
   - 多種輸出格式

## 📖 閱讀順序建議

### 初學者

1. 先閱讀 [config.md](config.md) 了解配置系統
2. 然後閱讀 [interface.md](interface.md) 學習如何使用
3. 最後根據需求選讀其他模組

### 開發者

1. [transport.md](transport.md) - 了解傳輸層架構
2. [protocol.md](protocol.md) - 學習 USP 協議實現
3. [scripting.md](scripting.md) - 理解腳本引擎
4. [interface.md](interface.md) - 掌握介面設計

### 架構師

按順序閱讀所有文檔，理解完整的分層架構設計。

## 🔍 快速查找

| 需求 | 文檔 | 章節 |
|------|------|------|
| 如何配置 broker | config.md | TransportConfig |
| 如何記錄日誌 | logger.md | 使用方式 |
| 如何發送 GET | protocol.md | GET |
| 如何寫腳本 | scripting.md | 腳本語法 |
| 如何自定義命令 | interface.md | 註冊自定義命令 |
| 如何改變輸出格式 | interface.md | 輸出格式對比 |

## 🛠️ 擴展開發

如果要擴展系統功能，參考相關模組文檔：

- **新增傳輸協議** → [transport.md](transport.md)
- **新增 USP 操作** → [protocol.md](protocol.md)
- **新增介面類型** → [interface.md](interface.md)
- **增強腳本功能** → [scripting.md](scripting.md)

## 📝 文檔維護

所有文檔遵循：
- 簡潔明瞭
- 代碼示例完整
- 定期更新
