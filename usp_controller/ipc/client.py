# -*- coding: utf-8 -*-
"""
USP Controller IPC Client
Client library for communicating with the background Daemon via IPC socket.
"""

import json
import socket
import time
from typing import Dict, Any, Optional, List, Tuple

from .protocol import IPCAction, IPCRequest, IPCResponse
from ..interface.base import CommandResult
from ..logger import get_logger

logger = get_logger()


class IPCClient:
    """
    Lightweight client for communicating with the USP Controller Daemon.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 6001, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def is_daemon_alive(self, timeout: float = 0.5) -> bool:
        """Check if Daemon IPC server is reachable"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((self.host, self.port))
                return (res == 0)
        except Exception:
            return False

    def send_request(self, action: str, params: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None) -> IPCResponse:
        """Send a single request to Daemon and wait for response"""
        tout = timeout if timeout is not None else self.timeout
        req = IPCRequest(action=action, params=params or {})
        req_line = json.dumps(req.to_dict(), ensure_ascii=False) + "\n"

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(tout)
                s.connect((self.host, self.port))
                s.sendall(req_line.encode('utf-8'))

                buffer = ""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk.decode('utf-8', errors='replace')
                    if '\n' in buffer:
                        break

                line = buffer.strip().split('\n')[0]
                if not line:
                    return IPCResponse(success=False, error="Empty response from daemon")

                resp_data = json.loads(line)
                return IPCResponse.from_dict(resp_data)

        except ConnectionRefusedError:
            return IPCResponse(success=False, error=f"Cannot connect to Daemon at {self.host}:{self.port} (Connection Refused)")
        except socket.timeout:
            return IPCResponse(success=False, error=f"IPC request timed out after {tout}s")
        except Exception as e:
            return IPCResponse(success=False, error=f"IPC error: {e}")

    def ping(self) -> bool:
        """Ping Daemon server"""
        resp = self.send_request(IPCAction.PING.value, timeout=1.0)
        return resp.success

    def get_status(self) -> Dict[str, Any]:
        """Fetch status overview from Daemon"""
        resp = self.send_request(IPCAction.STATUS.value, timeout=2.0)
        if resp.success and isinstance(resp.data, dict):
            return resp.data
        return {"daemon": {"running": False}, "error": resp.error}

    def get_port_status(self) -> Dict[str, Any]:
        """Fetch port monitoring details from Daemon"""
        resp = self.send_request(IPCAction.PORT_STATUS.value, timeout=2.0)
        if resp.success and isinstance(resp.data, dict):
            return resp.data
        return {}

    def exec_cmd(self, cmd_line: str, timeout: float = 30.0) -> CommandResult:
        """Execute a CLI command string on the Daemon"""
        resp = self.send_request(IPCAction.EXEC_CMD.value, {"cmd_line": cmd_line}, timeout=timeout)
        if resp.success and isinstance(resp.data, dict):
            d = resp.data
            return CommandResult(
                success=d.get("success", True),
                message=d.get("message", ""),
                data=d.get("data"),
                error=d.get("error"),
                metadata={"command": d.get("command", cmd_line.split()[0] if cmd_line else "")}
            )
        return CommandResult(
            success=False,
            error=resp.error or "Daemon command execution failed",
            metadata={"command": cmd_line.split()[0] if cmd_line else ""}
        )


    def get_devices(self) -> Tuple[List[Dict], Optional[str]]:
        """Get all known devices and active device endpoint"""
        resp = self.send_request(IPCAction.GET_DEVICES.value, timeout=2.0)
        if resp.success and isinstance(resp.data, dict):
            return resp.data.get("devices", []), resp.data.get("active")
        return [], None

    def set_target(self, endpoint: str) -> bool:
        """Set active target device endpoint on Daemon"""
        resp = self.send_request(IPCAction.SET_TARGET.value, {"endpoint": endpoint}, timeout=2.0)
        return resp.success

    def remove_device(self, endpoint: str) -> bool:
        """Remove a device from Daemon registry"""
        resp = self.send_request("remove_device", {"endpoint": endpoint}, timeout=2.0)
        return resp.success

    def clear_offline_devices(self) -> int:
        """Clear all offline devices from Daemon registry"""
        resp = self.send_request("clear_offline", timeout=2.0)
        if resp.success and isinstance(resp.data, dict):
            return resp.data.get("cleared_count", 0)
        return 0


    def get_logs(self, since_id: int = -1, max_count: int = 50) -> List[Dict]:
        """Fetch recent log entries from Daemon"""
        resp = self.send_request(
            IPCAction.GET_LOGS.value,
            {"since_id": since_id, "max_count": max_count},
            timeout=2.0
        )
        if resp.success and isinstance(resp.data, dict):
            return resp.data.get("logs", [])
        return []

    def clear_logs(self) -> bool:
        """Clear log history on Daemon"""
        resp = self.send_request(IPCAction.CLEAR_LOGS.value, timeout=1.0)
        return resp.success

    def run_script(self, script_path: str, timeout: float = 120.0) -> Dict[str, Any]:
        """Run a test script on Daemon"""
        resp = self.send_request(IPCAction.RUN_SCRIPT.value, {"script_path": script_path}, timeout=timeout)
        if resp.success and isinstance(resp.data, dict):
            return resp.data
        return {"status": "ERROR", "error": resp.error}

    def shutdown_daemon(self) -> bool:
        """Ask Daemon to shut down gracefully"""
        resp = self.send_request(IPCAction.SHUTDOWN.value, timeout=2.0)
        return resp.success
