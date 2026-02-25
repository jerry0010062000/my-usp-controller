#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Transport Module Unit Tests
測試傳輸層模組
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


def test_transport_imports():
    """測試傳輸層導入"""
    from usp_controller.transport import (
        TransportProtocol,
        TransportState,
        TransportFactory,
        STOMPTransport
    )
    assert TransportProtocol is not None
    assert TransportState is not None


def test_transport_state_enum():
    """測試傳輸狀態枚舉"""
    from usp_controller.transport import TransportState
    
    assert TransportState.DISCONNECTED.value == "disconnected"
    assert TransportState.CONNECTING.value == "connecting"
    assert TransportState.CONNECTED.value == "connected"
    assert TransportState.DISCONNECTING.value == "disconnecting"
    assert TransportState.ERROR.value == "error"


def test_transport_factory_create():
    """測試傳輸工廠創建"""
    from usp_controller.transport import TransportFactory
    
    config = {
        'broker_host': '127.0.0.1',
        'broker_port': 61613,
        'username': 'admin',
        'password': 'admin'
    }
    
    # 創建 STOMP 傳輸
    transport = TransportFactory.create('stomp', config)
    assert transport is not None
    assert transport.get_protocol_name() == 'STOMP'


def test_transport_factory_list_protocols():
    """測試列出可用協議"""
    from usp_controller.transport import TransportFactory
    
    protocols = TransportFactory.list_protocols()
    assert 'stomp' in protocols


def test_transport_factory_invalid_protocol():
    """測試無效協議"""
    from usp_controller.transport import TransportFactory
    
    with pytest.raises(ValueError):
        TransportFactory.create('invalid_protocol', {})


def test_stomp_transport_creation():
    """測試 STOMP 傳輸創建"""
    from usp_controller.transport import STOMPTransport
    
    config = {
        'broker_host': 'localhost',
        'broker_port': 61613,
        'username': 'test',
        'password': 'test123'
    }
    
    transport = STOMPTransport(config)
    assert transport is not None
    assert not transport.is_connected()


def test_stomp_transport_config():
    """測試 STOMP 傳輸配置"""
    from usp_controller.transport import STOMPTransport
    
    config = {
        'broker_host': '192.168.1.100',
        'broker_port': 61613,
        'username': 'user1',
        'password': 'pass1',
        'heartbeat_send': 10000,
        'heartbeat_recv': 10000
    }
    
    transport = STOMPTransport(config)
    assert transport.config['broker_host'] == '192.168.1.100'
    assert transport.config['broker_port'] == 61613


def test_transport_callback_registration():
    """測試回調註冊"""
    from usp_controller.transport import STOMPTransport, TransportState
    
    config = {
        'broker_host': 'localhost',
        'broker_port': 61613
    }
    
    transport = STOMPTransport(config)
    
    callback_called = []
    
    def message_callback(headers, body, sender):
        callback_called.append('message')
    
    def state_callback(new_state):
        callback_called.append('state')
    
    transport.set_message_callback(message_callback)
    transport.set_state_callback(state_callback)
    
    # 觸發狀態變化
    transport._notify_state_change(TransportState.CONNECTING)
    
    assert 'state' in callback_called


def test_transport_state_tracking():
    """測試狀態追蹤"""
    from usp_controller.transport import STOMPTransport, TransportState
    
    config = {
        'broker_host': 'localhost',
        'broker_port': 61613
    }
    
    transport = STOMPTransport(config)
    
    # 初始狀態
    assert transport.get_state() == TransportState.DISCONNECTED
    
    # 改變狀態
    transport._notify_state_change(TransportState.CONNECTING)
    assert transport.get_state() == TransportState.CONNECTING


def test_mqtt_transport_interface():
    """測試 MQTT 傳輸接口"""
    from usp_controller.transport import MQTTTransport
    
    config = {
        'broker_host': 'localhost',
        'broker_port': 1883
    }
    
    # MQTT 目前只是接口
    transport = MQTTTransport(config)
    assert transport is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
