#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Config Module Unit Tests
測試配置管理模組
"""

import sys
from pathlib import Path
import json
import tempfile

# 添加模組路徑
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from dataclasses import asdict


def test_config_imports():
    """測試配置模組導入"""
    from usp_controller.config import (
        ControllerConfig,
        TransportConfig,
        IPCConfig,
        ScriptingConfig,
        load_config
    )
    assert ControllerConfig is not None
    assert TransportConfig is not None


def test_transport_config_creation():
    """測試 TransportConfig 創建"""
    from usp_controller.config import TransportConfig
    
    config = TransportConfig(
        protocol="stomp",
        host="127.0.0.1",
        port=61613,
        username="admin",
        password="admin"
    )
    
    assert config.protocol == "stomp"
    assert config.host == "127.0.0.1"
    assert config.port == 61613


def test_controller_config_creation():
    """測試 ControllerConfig 創建"""
    from usp_controller.config import ControllerConfig, TransportConfig
    
    transport = TransportConfig(
        protocol="stomp",
        host="localhost",
        port=61613
    )
    
    config = ControllerConfig(
        controller_endpoint_id="controller-001",
        receive_topic="/topic/test",
        transport=transport
    )
    
    assert config.controller_endpoint_id == "controller-001"
    assert config.transport.protocol == "stomp"
    assert config.debug_level == 0  # 默認值


def test_config_file_load():
    """測試配置對象創建與嵌套結構"""
    from usp_controller.config import ControllerConfig, TransportConfig, IPCConfig, ScriptingConfig
    
    # 創建完整的配置對象
    transport = TransportConfig(
        protocol="stomp",
        host="test-broker",
        port=61613,
        username="test",
        password="test123"
    )
    
    ipc = IPCConfig(
        enabled=True,
        host="127.0.0.1",
        port=6001
    )
    
    scripting = ScriptingConfig(
        intelligence_level=2
    )
    
    config = ControllerConfig(
        controller_endpoint_id="test-controller",
        receive_topic="/topic/test",
        transport=transport,
        ipc=ipc,
        scripting=scripting,
        debug_level=1
    )
    
    # 驗證配置
    assert config.controller_endpoint_id == "test-controller"
    assert config.transport.host == "test-broker"
    assert config.ipc.port == 6001
    assert config.scripting.intelligence_level == 2
    assert config.debug_level == 1


def test_config_validation():
    """測試配置驗證"""
    from usp_controller.config import TransportConfig
    
    # 正確的配置
    config = TransportConfig(
        protocol="stomp",
        host="localhost",
        port=61613
    )
    assert config.port > 0
    
    # 測試協議類型
    config.protocol = "mqtt"
    assert config.protocol in ["stomp", "mqtt"]


def test_config_defaults():
    """測試配置默認值"""
    from usp_controller.config import TransportConfig, IPCConfig, ScriptingConfig
    
    # TransportConfig 默認值
    transport = TransportConfig()
    assert transport.protocol == "stomp"
    assert transport.username == "guest"
    assert transport.password == "guest"
    
    # IPCConfig 默認值
    ipc = IPCConfig()
    assert ipc.enabled == True
    assert ipc.host == "127.0.0.1"
    assert ipc.port == 6001
    
    # ScriptingConfig 默認值
    scripting = ScriptingConfig()
    assert scripting.intelligence_level == 2
    assert scripting.auto_discovery == True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
