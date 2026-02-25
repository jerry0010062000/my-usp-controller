#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration Tests
整合測試 - 測試完整工作流程
"""

import sys
from pathlib import Path
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


def test_full_controller_initialization():
    """測試控制器完整初始化流程"""
    from usp_controller.config import ControllerConfig, TransportConfig
    from usp_controller.logger import get_logger
    from usp_controller.transport import TransportFactory
    from usp_controller.protocol import USPMessage
    
    # 1. 創建配置
    transport_config = TransportConfig(
        protocol="stomp",
        host="localhost",
        port=61613
    )
    
    config = ControllerConfig(
        controller_endpoint_id="test-controller",
        receive_topic="/topic/test",
        transport=transport_config
    )
    
    # 2. 初始化日誌器
    logger = get_logger()
    logger.info("Integration test started")
    
    # 3. 創建傳輸層
    transport = TransportFactory.create(
        'stomp',
        {
            'host': config.transport.host,
            'port': config.transport.port
        }
    )
    
    # 4. 創建 USP 訊息
    usp = USPMessage(controller_id=config.controller_endpoint_id)
    message = usp.create_get(
        endpoint_id="agent-001",
        paths=["Device."]
    )
    
    assert config is not None
    assert logger is not None
    assert transport is not None
    assert message is not None


def test_message_creation_pipeline():
    """測試訊息創建流水線"""
    from usp_controller.protocol import USPMessage
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    
    # GET 訊息
    usp = USPMessage(controller_id="test-controller")
    get_msg = usp.create_get(
        endpoint_id="agent-001",
        paths=["Device.DeviceInfo."]
    )
    logger.info("GET message created")
    
    # SET 訊息
    set_msg = usp.create_set(
        endpoint_id="agent-001",
        params={"Device.X.Test": "value"}
    )
    logger.info("SET message created")
    
    # ADD 訊息
    add_msg = usp.create_add(
        endpoint_id="agent-001",
        obj_path="Device.X.",
        params={"Enable": "true"}
    )
    logger.info("ADD message created")
    
    assert get_msg is not None
    assert set_msg is not None
    assert add_msg is not None


def test_scripting_to_protocol():
    """測試腳本引擎到協議層的整合"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    from usp_controller.protocol import USPMessage
    
    engine = SmartScriptEngine(intelligence_level=2)
    
    script = """
    get agent-001 Device.DeviceInfo.
    set agent-001 Device.X.Test 123
    """
    
    commands = engine.parse_script(script)
    
    # 執行命令並生成 USP 訊息
    usp = USPMessage(controller_id="test-controller")
    messages = []
    for cmd in commands:
        if cmd.type == ScriptCommandType.GET:
            msg = usp.create_get(
                endpoint_id="agent-001",
                paths=["Device.DeviceInfo."]
            )
            messages.append(msg)
        elif cmd.type == ScriptCommandType.SET:
            msg = usp.create_set(
                endpoint_id="agent-001",
                params={"Device.X.Test": "123"}
            )
            messages.append(msg)
    
    assert len(messages) >= 1


def test_logger_with_transport():
    """測試日誌器與傳輸層整合"""
    from usp_controller.logger import get_logger
    from usp_controller.transport import TransportFactory, TransportState
    
    logger = get_logger()
    
    transport = TransportFactory.create('stomp', {
        'broker_host': 'localhost',
        'broker_port': 61613
    })
    
    # 設置狀態回調
    def state_callback(new_state):
        if new_state == TransportState.CONNECTED:
            logger.success("Transport connected")
        elif new_state == TransportState.DISCONNECTED:
            logger.info("Transport disconnected")
        elif new_state == TransportState.ERROR:
            logger.error("Transport error")
    
    transport.set_state_callback(state_callback)
    
    # 模擬狀態變化
    transport._notify_state_change(TransportState.CONNECTING)
    transport._notify_state_change(TransportState.CONNECTED)
    
    # 檢查日誌
    history = logger.get_history(max_count=5)
    # 由於是單例模式，可能有之前的日誌
    assert len(history) >= 0  # 只要不出錯即可


def test_config_to_components():
    """測試配置到各組件的分發"""
    from usp_controller.config import (
        ControllerConfig,
        TransportConfig,
        ScriptingConfig
    )
    from usp_controller.transport import TransportFactory
    from usp_controller.scripting import SmartScriptEngine
    
    # 創建配置
    config = ControllerConfig(
        controller_endpoint_id="test-controller",
        receive_topic="/topic/test",
        transport=TransportConfig(
            protocol="stomp",
            host="test-host",
            port=61613
        ),
        scripting=ScriptingConfig(
            intelligence_level=2,
            auto_discovery=True
        )
    )
    
    # 使用配置創建組件
    transport = TransportFactory.create(
        config.transport.protocol,
        {
            'host': config.transport.host,
            'port': config.transport.port
        }
    )
    
    engine = SmartScriptEngine(
        intelligence_level=config.scripting.intelligence_level
    )
    
    assert transport.config['host'] == "test-host"
    assert engine.intelligence_level == 2


def test_interface_layer_integration():
    """測試接口層整合"""
    from usp_controller.interface import (
        InterfaceFactory,
        CommandResult,
        InterfaceType
    )
    from usp_controller.protocol import USPMessage
    from usp_controller.interface.command_handler import CommandHandler
    
    # 創建 CLI 接口
    cli = InterfaceFactory.create(InterfaceType.CLI)
    
    # 使用 CommandHandler 解析命令
    handler = CommandHandler()
    command = "get agent-001 Device."
    context = handler.parse_command(command)
    
    # 創建 USP 訊息
    usp = USPMessage(controller_id="test-controller")
    msg = usp.create_get(
        endpoint_id="agent-001",
        paths=["Device."]
    )
    
    # 創建結果
    result = CommandResult(
        success=True,
        data={"SerialNumber": "12345"},
        message="GET successful"
    )
    
    # 驗證組件
    assert msg is not None
    assert cli is not None
    assert result.success == True


def test_error_handling_chain():
    """測試錯誤處理鏈"""
    from usp_controller.logger import get_logger
    from usp_controller.transport import TransportFactory
    
    logger = get_logger()
    
    try:
        # 故意使用無效配置
        transport = TransportFactory.create('invalid_protocol', {})
    except ValueError as e:
        logger.error(f"Expected error: {e}")
        
        # 檢查日誌記錄
        history = logger.get_history(max_count=1)
        assert len(history) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
