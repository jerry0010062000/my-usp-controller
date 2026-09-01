# -*- coding: utf-8 -*-
"""
USP Controller IPC Protocol Definitions
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


class IPCAction(str, Enum):
    PING = "ping"
    STATUS = "status"
    PORT_STATUS = "port_status"
    EXEC_CMD = "exec_cmd"
    GET_DEVICES = "get_devices"
    SET_TARGET = "set_target"
    GET_LOGS = "get_logs"
    CLEAR_LOGS = "clear_logs"
    RUN_SCRIPT = "run_script"
    SHUTDOWN = "shutdown"


@dataclass
class IPCRequest:
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    req_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "params": self.params,
            "req_id": self.req_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPCRequest':
        return cls(
            action=data.get("action", ""),
            params=data.get("params", {}),
            req_id=data.get("req_id")
        )


@dataclass
class IPCResponse:
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    req_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "req_id": self.req_id
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPCResponse':
        return cls(
            success=data.get("success", False),
            data=data.get("data"),
            error=data.get("error"),
            req_id=data.get("req_id")
        )
