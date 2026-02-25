"""
Test Utilities
測試輔助工具
"""

import random
import string


def generate_endpoint_id(prefix="agent"):
    """生成隨機 endpoint ID"""
    suffix = ''.join(random.choices(string.digits, k=6))
    return f"{prefix}-{suffix}"


def generate_serial_number():
    """生成隨機序列號"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))


def create_test_path(base_path="Device", levels=3):
    """創建測試路徑"""
    path = base_path
    for _ in range(levels):
        path += f".Test{random.randint(1, 100)}"
    return path + "."


def mock_usp_response(msg_type="GET", success=True):
    """創建模擬 USP 響應"""
    if msg_type == "GET":
        if success:
            return {
                "response_type": "GetResp",
                "parameters": {
                    "Device.DeviceInfo.SerialNumber": "TEST123",
                    "Device.DeviceInfo.Manufacturer": "Test Inc."
                }
            }
        else:
            return {
                "response_type": "Error",
                "error_code": 7001,
                "error_message": "Invalid path"
            }
    
    elif msg_type == "SET":
        if success:
            return {
                "response_type": "SetResp",
                "updated_params": {
                    "Device.X.TestParam": "new_value"
                }
            }
        else:
            return {
                "response_type": "Error",
                "error_code": 7006,
                "error_message": "Read-only parameter"
            }


class MockTransport:
    """模擬傳輸層"""
    
    def __init__(self, config):
        self.config = config
        self.connected = False
        self.sent_messages = []
    
    def connect(self):
        """模擬連接"""
        self.connected = True
        return True
    
    def disconnect(self):
        """模擬斷開"""
        self.connected = False
    
    def send(self, destination, body, headers=None):
        """模擬發送"""
        self.sent_messages.append({
            'destination': destination,
            'body': body,
            'headers': headers or {}
        })
        return True
    
    def is_connected(self):
        """檢查連接狀態"""
        return self.connected
    
    def get_sent_messages(self):
        """獲取已發送的消息"""
        return self.sent_messages


class MockLogger:
    """模擬日誌器"""
    
    def __init__(self):
        self.logs = []
    
    def info(self, msg):
        self.logs.append(('INFO', msg))
    
    def error(self, msg):
        self.logs.append(('ERROR', msg))
    
    def success(self, msg):
        self.logs.append(('SUCCESS', msg))
    
    def critical(self, msg):
        self.logs.append(('CRITICAL', msg))
    
    def get_logs(self):
        return self.logs


def assert_valid_usp_path(path):
    """驗證 USP 路徑格式"""
    # 基本檢查
    assert isinstance(path, str), "Path must be string"
    assert path.startswith("Device."), "Path must start with 'Device.'"
    
    # 檢查結尾
    if path.endswith('.'):
        # 對象路徑
        assert path.count('.') >= 2, "Object path needs at least 2 dots"
    else:
        # 參數路徑
        assert path.count('.') >= 2, "Parameter path needs at least 2 dots"


def assert_valid_endpoint_id(endpoint_id):
    """驗證 endpoint ID 格式"""
    assert isinstance(endpoint_id, str), "Endpoint ID must be string"
    assert len(endpoint_id) > 0, "Endpoint ID cannot be empty"
    assert '-' in endpoint_id or '.' in endpoint_id or ':' in endpoint_id, \
        "Endpoint ID should contain separator"


def create_test_config(**kwargs):
    """創建測試配置"""
    default_config = {
        'controller_endpoint_id': 'test-controller',
        'transport': {
            'protocol': 'stomp',
            'broker_host': 'localhost',
            'broker_port': 61613,
            'username': 'admin',
            'password': 'admin'
        },
        'debug_level': 0
    }
    
    # 合併自定義配置
    default_config.update(kwargs)
    return default_config


def measure_execution_time(func, *args, **kwargs):
    """測量執行時間"""
    import time
    
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    
    return result, (end - start)
