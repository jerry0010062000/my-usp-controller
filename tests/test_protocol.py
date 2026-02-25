#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Protocol Module Unit Tests
測試 USP 協議層模組
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


# 創建全局 USPMessage 實例供測試使用
@pytest.fixture
def usp_message():
    """創建 USPMessage 實例"""
    from usp_controller.protocol import USPMessage
    return USPMessage(controller_id="test-controller")


def test_protocol_imports():
    """測試協議層導入"""
    from usp_controller.protocol import USPMessage
    assert USPMessage is not None


def test_create_get_message(usp_message):
    """測試創建 GET 訊息"""
    record_bytes = usp_message.create_get(
        endpoint_id="agent-001",
        paths=["Device.DeviceInfo."]
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)
    assert len(record_bytes) > 0


def test_create_set_message(usp_message):
    """測試創建 SET 訊息"""
    record_bytes = usp_message.create_set(
        endpoint_id="agent-001",
        params={
            "Device.DeviceInfo.FriendlyName": "Test Device"
        }
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_create_add_message(usp_message):
    """測試創建 ADD 訊息"""
    record_bytes = usp_message.create_add(
        endpoint_id="agent-001",
        obj_path="Device.DHCPv4.Server.Pool.",
        params={"Enable": "true"}
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_create_delete_message(usp_message):
    """測試創建 DELETE 訊息"""
    record_bytes = usp_message.create_delete(
        endpoint_id="agent-001",
        obj_paths=["Device.DHCPv4.Server.Pool.1."]
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_create_get_instances_message(usp_message):
    """測試創建 GET_INSTANCES 訊息"""
    record_bytes = usp_message.create_get_instances(
        endpoint_id="agent-001",
        obj_paths=["Device.Ethernet.Interface."]
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_create_get_supported_dm_message(usp_message):
    """測試創建 GET_SUPPORTED_DM 訊息"""
    record_bytes = usp_message.create_get_supported_dm(
        endpoint_id="agent-001",
        obj_paths=["Device."],
        return_commands=True,
        return_events=True,
        return_params=True
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_create_operate_message(usp_message):
    """測試創建 OPERATE 訊息"""
    # 不使用空字典，使用 None
    record_bytes = usp_message.create_operate(
        endpoint_id="agent-001",
        command="Device.Reboot()",
        args=None
    )
    
    assert record_bytes is not None
    assert isinstance(record_bytes, bytes)


def test_parse_record(usp_message):
    """測試解析 Record"""
    # 創建一個訊息
    record_bytes = usp_message.create_get(
        endpoint_id="agent-001",
        paths=["Device."]
    )
    
    # 解析
    from usp_controller.protocol import USPMessage
    from_id, to_id, usp_msg = USPMessage.parse_record(record_bytes)
    
    assert to_id == "agent-001"
    assert usp_msg is not None


def test_message_with_multiple_paths(usp_message):
    """測試多路徑訊息"""
    record_bytes = usp_message.create_get(
        endpoint_id="agent-001",
        paths=[
            "Device.DeviceInfo.",
            "Device.Ethernet.",
            "Device.WiFi."
        ]
    )
    
    assert record_bytes is not None


def test_message_with_multiple_params(usp_message):
    """測試多參數訊息"""
    record_bytes = usp_message.create_set(
        endpoint_id="agent-001",
        params={
            "Device.DeviceInfo.FriendlyName": "Device1",
            "Device.X.Parameter1": "value1",
            "Device.X.Parameter2": "value2"
        }
    )
    
    assert record_bytes is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
