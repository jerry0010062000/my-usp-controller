#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit Tests for DUT Data Model Configuration & Recommendation Guide Generator
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from usp_controller.config import ControllerConfig, TransportConfig
from usp_controller.device.dut_generator import DUTConfigGenerator


def test_dut_generator_imports():
    """Verify generator import"""
    from usp_controller.device import DUTConfigGenerator, DeviceManager
    assert DUTConfigGenerator is not None
    assert DeviceManager is not None


def test_generate_guide():
    """Verify directional guide generation contains necessary TR-181 parameters"""
    cfg = ControllerConfig(
        controller_endpoint_id="proto::controller.test",
        receive_topic="/queue/usp.controller.test",
        transport=TransportConfig(
            protocol="stomp",
            host="192.168.1.88",
            port=61613,
            username="admin",
            password="secret_password"
        )
    )

    guide = DUTConfigGenerator.generate_guide(cfg, dut_endpoint_id="proto::agent-999")
    
    assert "Device.LocalAgent.EndpointID" in guide
    assert "proto::agent-999" in guide
    assert "Device.STOMP.Connection.1.Host" in guide
    assert "192.168.1.88" in guide
    assert "61613" in guide
    assert "admin" in guide
    assert "secret_password" in guide
    assert "Device.LocalAgent.Controller.1.EndpointID" in guide
    assert "proto::controller.test" in guide
    assert "/queue/usp.controller.test" in guide
    assert "/queue/usp.agent.agent-999" in guide


def test_generate_tr181_commands():
    """Verify raw TR-181 parameter list"""
    cfg = ControllerConfig(
        controller_endpoint_id="proto::ctrl",
        receive_topic="/queue/ctrl",
        transport=TransportConfig(host="10.0.0.1", port=61614)
    )
    res = DUTConfigGenerator.generate_tr181_commands(cfg, dut_endpoint_id="proto::dut-01")
    assert 'Device.LocalAgent.EndpointID = "proto::dut-01"' in res
    assert 'Device.STOMP.Connection.1.Host = "10.0.0.1"' in res
    assert 'Device.LocalAgent.Controller.1.EndpointID = "proto::ctrl"' in res


def test_loopback_lan_ip_resolution():
    """Verify 127.0.0.1 is replaced with actual LAN IP for external DUTs"""
    cfg = ControllerConfig(
        controller_endpoint_id="proto::ctrl",
        receive_topic="/queue/ctrl",
        transport=TransportConfig(host="127.0.0.1", port=61614)
    )
    res = DUTConfigGenerator.generate_tr181_commands(cfg, dut_endpoint_id="proto::dut-01")
    assert '127.0.0.1' not in res
    # Must contain a real IP (e.g. 10.x.x.x or 192.x.x.x)
    assert 'Device.STOMP.Connection.1.Host = "' in res




def test_generate_openwrt_uci():
    """Verify OpenWrt UCI commands generation"""
    cfg = ControllerConfig(
        controller_endpoint_id="proto::ctrl",
        receive_topic="/queue/ctrl",
        transport=TransportConfig(host="10.0.0.1", port=61614)
    )
    uci = DUTConfigGenerator.generate_openwrt_uci(cfg, dut_endpoint_id="proto::myrouter")
    assert "uci set usp.localagent.EndpointID='proto::myrouter'" in uci
    assert "uci set usp.stomp_conn.host='10.0.0.1'" in uci
    assert "uci commit usp" in uci


def test_command_handler_dut_config():
    """Verify CommandHandler dut_config command execution"""
    from usp_controller.interface.command_handler import CommandHandler
    from usp_controller.core.controller import USPControllerCore

    ctrl = USPControllerCore()
    handler = CommandHandler(controller=ctrl)
    
    ctx = handler.parse_command("dut_config")
    res = handler.execute(ctx)
    assert res.success is True
    assert "Device.LocalAgent.EndpointID" in res.message
    assert "Device.STOMP.Connection.1." in res.message
