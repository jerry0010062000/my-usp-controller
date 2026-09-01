#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IPC Module Unit Tests
Tests IPC server, client, request-response protocol, and port monitoring.
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from usp_controller.ipc import (
    IPCServer,
    IPCClient,
    IPCAction,
    IPCRequest,
    IPCResponse,
    check_port_listening
)
from usp_controller.interface.command_handler import CommandHandler
from usp_controller.core import USPControllerCore


def test_ipc_imports():
    """Test IPC module imports"""
    assert IPCServer is not None
    assert IPCClient is not None
    assert IPCRequest is not None
    assert IPCResponse is not None


def test_ipc_models():
    """Test IPC Request & Response serialization"""
    req = IPCRequest(action="exec_cmd", params={"cmd_line": "status"}, req_id="123")
    d = req.to_dict()
    assert d["action"] == "exec_cmd"
    assert d["params"]["cmd_line"] == "status"

    req2 = IPCRequest.from_dict(d)
    assert req2.action == "exec_cmd"
    assert req2.req_id == "123"

    resp = IPCResponse(success=True, data={"result": "ok"}, req_id="123")
    rd = resp.to_dict()
    assert rd["success"] is True

    resp2 = IPCResponse.from_dict(rd)
    assert resp2.success is True
    assert resp2.data["result"] == "ok"


def test_ipc_server_lifecycle_and_ping():
    """Test IPC server startup, ping, status and clean shutdown"""
    test_port = 6095
    server = IPCServer(host="127.0.0.1", port=test_port)
    started = server.start()
    assert started is True

    try:
        client = IPCClient(host="127.0.0.1", port=test_port, timeout=2.0)
        assert client.is_daemon_alive(timeout=1.0) is True
        assert client.ping() is True

        st = client.get_status()
        assert st.get("daemon", {}).get("running") is True

        ports = client.get_port_status()
        assert ports.get("ipc", {}).get("listening") is True

    finally:
        server.stop()
        time.sleep(0.2)
        assert client.is_daemon_alive(timeout=0.2) is False


def test_ipc_command_execution():
    """Test executing commands over IPC channel"""
    test_port = 6096
    from usp_controller.config import ConfigManager
    ctrl = USPControllerCore(config=ConfigManager.create_default())
    handler = CommandHandler(controller=ctrl)
    server = IPCServer(controller=ctrl, command_handler=handler, host="127.0.0.1", port=test_port)
    assert server.start() is True

    try:
        client = IPCClient(host="127.0.0.1", port=test_port, timeout=3.0)
        res = client.exec_cmd("help")
        assert res.success is True
        assert "Command Reference" in str(res.message)

        res_stat = client.exec_cmd("status")
        assert res_stat.success is True



    finally:
        server.stop()


def test_port_check_utility():
    """Test check_port_listening helper"""
    # A definitely closed port
    closed = check_port_listening("127.0.0.1", 59999, timeout=0.1)
    assert closed is False
