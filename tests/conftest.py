"""
Pytest Configuration and Fixtures
測試配置與共用測試夾具
"""

import sys
from pathlib import Path
import tempfile
import json

import pytest

# 添加項目根目錄到 Python 路徑
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def temp_config_file():
    """創建臨時配置文件"""
    config_data = {
        "controller_endpoint_id": "test-controller",
        "transport": {
            "protocol": "stomp",
            "broker_host": "localhost",
            "broker_port": 61613,
            "username": "admin",
            "password": "admin",
            "queue_name": "/queue/usp-controller",
            "reply_to_queue": "/queue/usp-agent-response"
        },
        "ipc": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 6001
        },
        "scripting": {
            "intelligence_level": 2,
            "enable_variable_substitution": True
        },
        "debug_level": 1
    }
    
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.json',
        delete=False
    ) as f:
        json.dump(config_data, f)
        temp_file = f.name
    
    yield temp_file
    
    # 清理
    Path(temp_file).unlink(missing_ok=True)


@pytest.fixture
def mock_transport_config():
    """模擬傳輸配置"""
    return {
        'broker_host': '127.0.0.1',
        'broker_port': 61613,
        'username': 'test',
        'password': 'test123',
        'heartbeat_send': 10000,
        'heartbeat_recv': 10000
    }


@pytest.fixture
def sample_usp_paths():
    """常用 USP 路徑"""
    return [
        "Device.",
        "Device.DeviceInfo.",
        "Device.DeviceInfo.SoftwareVersion",
        "Device.Ethernet.Interface.",
        "Device.WiFi.Radio.",
        "Device.DHCPv4.Server.Pool."
    ]


@pytest.fixture
def sample_script():
    """示例測試腳本"""
    return """
    # Test Script
    $AGENT = agent-001
    $PATH = Device.DeviceInfo.
    
    get $AGENT $PATH
    set $AGENT Device.X.TestParam "test value"
    add $AGENT Device.X.TestObject. Enable=true Value=123
    delete $AGENT Device.X.TestObject.1.
    """


@pytest.fixture
def clean_logger():
    """清理日誌器歷史"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    logger.get_history(clear=True)
    
    yield logger
    
    # 測試後清理
    logger.get_history(clear=True)


@pytest.fixture
def mock_agent_response():
    """模擬 Agent 響應數據"""
    return {
        "Device.DeviceInfo.SerialNumber": "ABC123456",
        "Device.DeviceInfo.Manufacturer": "Test Manufacturer",
        "Device.DeviceInfo.ModelName": "Test Model",
        "Device.DeviceInfo.SoftwareVersion": "1.0.0"
    }


@pytest.fixture
def sample_dm_paths():
    """示例數據模型路徑"""
    return {
        "single_params": [
            "Device.DeviceInfo.SerialNumber",
            "Device.DeviceInfo.Manufacturer"
        ],
        "objects": [
            "Device.Ethernet.Interface.",
            "Device.WiFi.Radio."
        ],
        "multi_instance": [
            "Device.DHCPv4.Server.Pool.1.",
            "Device.DHCPv4.Server.Pool.2."
        ]
    }


# 測試標記
def pytest_configure(config):
    """配置自定義測試標記"""
    config.addinivalue_line(
        "markers", "unit: Unit tests"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests"
    )
    config.addinivalue_line(
        "markers", "slow: Slow running tests"
    )
    config.addinivalue_line(
        "markers", "network: Tests requiring network"
    )
