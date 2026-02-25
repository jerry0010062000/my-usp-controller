# USP Controller 測試套件## 總覽本目錄包含 USP Controller 專案的完整測試套件，使用 pytest 框架實現。## 測試結構```tests/├── conftest.py              # Pytest 配置與共用 fixtures├── test_utils.py            # 測試輔助工具├── test_config.py           # 配置模組單元測試├── test_logger.py           # 日誌系統單元測試├── test_transport.py        # 傳輸層單元測試├── test_protocol.py         # 協議層單元測試├── test_scripting.py        # 腳本引擎單元測試├── test_integration.py      # 整合測試├── test_interface_layer.py  # 接口層測試（舊版）├── test_v3_architecture.py  # 架構測試（舊版）├── example_interface_usage.py  # 使用範例└── verify_tests.py          # 測試驗證腳本```## 測試模組說明### 單元測試 (Unit Tests)#### test_config.py配置管理模組測試（6個測試）- ✅ 配置對象創建- ✅ 從文件載入配置- ✅ 配置驗證- ✅ 默認值測試#### test_logger.py日誌系統測試（10個測試）- ✅ 單例模式- ✅ 基本日誌記錄- ✅ 調試級別設置- ✅ USP 訊息日誌- ✅ 執行緒安全性- ✅ 歷史記錄管理- ✅ 回調功能#### test_transport.py傳輸層測試（10個測試）- ✅ 傳輸狀態枚舉- ✅ 工廠模式創建- ✅ STOMP 傳輸實現- ✅ 回調註冊- ✅ 狀態追蹤#### test_protocol.pyUSP 協議層測試（11個測試）- ✅ GET 訊息創建- ✅ SET 訊息創建- ✅ ADD 訊息創建- ✅ DELETE 訊息創建- ✅ GET_INSTANCES 訊息- ✅ GET_SUPPORTED_DM 訊息- ✅ OPERATE 訊息- ✅ Record 解析#### test_scripting.py腳本引擎測試（12個測試）- ✅ 引擎創建- ✅ 簡單命令解析- ✅ 註釋處理- ✅ 變量替換- ✅ 路徑推斷（多級別）- ✅ 參數處理### 整合測試 (Integration Tests)#### test_integration.py完整工作流程測試（7個測試）- ✅ 控制器完整初始化- ✅ 訊息創建流水線- ✅ 腳本到協議層整合
- ✅ 日誌與傳輸整合
- ✅ 配置分發到各組件
- ✅ 接口層整合
- ✅ 錯誤處理鏈

### 舊版測試（保留）

#### test_v3_architecture.py
V3 架構模組化測試（7個測試）

#### test_interface_layer.py
接口抽象層測試（8個測試）

#### example_interface_usage.py
接口層使用範例（6個示例）

### 支援文件

#### conftest.py
Pytest 配置與共用 fixtures
- `temp_config_file` - 臨時配置文件
- `mock_transport_config` - 模擬傳輸配置
- `sample_usp_paths` - 常用 USP 路徑
- `sample_script` - 示例腳本
- `clean_logger` - 清理日誌器
- `mock_agent_response` - 模擬 Agent 響應
- `sample_dm_paths` - 示例數據模型路徑

#### test_utils.py
測試輔助工具函數
- `generate_endpoint_id()` - 生成隨機 endpoint ID
- `generate_serial_number()` - 生成序列號
- `create_test_path()` - 創建測試路徑
- `mock_usp_response()` - 模擬 USP 響應
- `MockTransport` - 模擬傳輸層
- `MockLogger` - 模擬日誌器
- 路徑驗證函數

#### verify_tests.py
測試驗證腳本 - 檢查所有測試模組狀態

## 運行測試

### 1. 安裝測試依賴

```bash
pip install -r requirements.txt
```

### 2. 快速運行（Windows）

```bash
# 雙擊運行
run_tests.bat

# 或命令行
python run_tests.py
```

### 3. 運行所有測試

```bash
pytest tests/ -v
```

### 4. 運行特定測試文件

```bash
# 單個模組測試
pytest tests/test_config.py -v
pytest tests/test_logger.py -v

# 整合測試
pytest tests/test_integration.py -v
```

### 5. 運行特定測試函數

```bash
pytest tests/test_config.py::test_config_file_load -v
pytest tests/test_logger.py::test_logger_singleton -v
```

### 6. 使用測試標記

```bash
# 只運行單元測試
pytest -m unit

# 只運行整合測試
pytest -m integration

# 排除慢速測試
pytest -m "not slow"
```

### 7. 生成覆蓋率報告

```bash
# HTML 報告
pytest --cov=usp_controller --cov-report=html tests/

# 使用測試腳本
python run_tests.py --coverage
```

### 8. 測試驗證

```bash
# 驗證所有測試模組
python tests/verify_tests.py
```

## 進階用法

### 使用 run_tests.py

```bash
# 基本用法
python run_tests.py

# 帶覆蓋率
python run_tests.py --coverage

# 只運行單元測試
python run_tests.py -m unit

# 運行特定關鍵字
python run_tests.py -k "test_config"

# 運行特定文件
python run_tests.py tests/test_config.py

# 遇到失敗就停止
python run_tests.py -x

# 組合使用
python run_tests.py --coverage -m unit -v
```

### 其他有用選項

```bash
# 遇到第一個失敗就停止
pytest -x

# 顯示最慢的 10 個測試
pytest --durations=10

# 先運行上次失敗的測試
pytest --failed-first

# 詳細輸出
pytest -vv

# 顯示本地變量
pytest -l
```

## 測試覆蓋狀態

### 核心模組
- ✅ Config (配置管理) - 6 個測試
- ✅ Logger (日誌系統) - 10 個測試
- ✅ Transport (傳輸層) - 10 個測試
- ✅ Protocol (協議層) - 11 個測試
- ✅ Scripting (腳本引擎) - 12 個測試
- ✅ Interface (接口層) - 8 個測試
- ✅ Integration (整合測試) - 7 個測試

**總計**: 71 個測試用例

## 測試最佳實踐

1. **隔離性**: 每個測試應該獨立運行
2. **可重複性**: 測試結果應該一致
3. **清晰性**: 測試名稱應該描述測試內容
4. **完整性**: 測試應該涵蓋正常和異常情況
5. **快速性**: 單元測試應該快速執行

## 快速驗證

運行驗證腳本檢查測試套件：

```bash
python tests/verify_tests.py
```

預期輸出：
```
✅ All test modules are ready!
✅ 所有測試模組已就緒！

📊 Test Modules: 8/8
📊 Total Test Functions: 71
```

如果所有測試通過，系統已準備就緒！
