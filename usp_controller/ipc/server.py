# -*- coding: utf-8 -*-
"""
USP Controller IPC Server
Threaded TCP server providing local IPC control and monitoring API.
"""

import os
import sys
import json
import time
import socket
import threading
from typing import Dict, Any, Optional, Callable

from .protocol import IPCAction, IPCRequest, IPCResponse
from ..logger import get_logger

logger = get_logger()


def check_port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is currently open and listening"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # If host is 0.0.0.0, connect to 127.0.0.1 for local probe
            probe_host = "127.0.0.1" if host in ("0.0.0.0", "", "*") else host
            res = s.connect_ex((probe_host, port))
            return (res == 0)
    except Exception:
        return False


class IPCServer:
    """
    Local TCP IPC Server for USP Controller Daemon
    Listens on 127.0.0.1:6001 by default.
    """

    def __init__(self, controller=None, command_handler=None, host: str = "127.0.0.1", port: int = 6001):
        self.controller = controller
        self.command_handler = command_handler
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.start_time = time.time()
        self.clients_count = 0
        self._server_thread: Optional[threading.Thread] = None
        self._client_threads = []
        self._lock = threading.RLock()

    def start(self) -> bool:

        """Start IPC server listening on background thread"""
        if self.running:
            return True

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0)
            self.running = True
            self.start_time = time.time()

            self._server_thread = threading.Thread(target=self._listen_loop, daemon=True, name="IPCServer-Listener")
            self._server_thread.start()

            logger.info(f"IPC Server listening on {self.host}:{self.port}", level=0)
            return True
        except Exception as e:
            logger.error(f"Failed to start IPC Server on {self.host}:{self.port}: {e}")
            self.running = False
            return False

    def stop(self):
        """Stop IPC server and close socket"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        if self._server_thread and self._server_thread.is_alive():
            if threading.current_thread() != self._server_thread:
                self._server_thread.join(timeout=1.0)

        logger.info("IPC Server stopped", level=1)

    def _listen_loop(self):
        """Background thread accepting client socket connections"""
        while self.running:
            try:
                if not self.server_socket:
                    break
                client_sock, addr = self.server_socket.accept()
                with self._lock:
                    self.clients_count += 1
                
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                    name=f"IPCClient-{addr[1]}"
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"IPC accept error: {e}")
                break

    def _handle_client(self, client_sock: socket.socket, addr):
        """Handle individual client communication session"""
        client_sock.settimeout(30.0)
        buffer = ""

        try:
            while self.running:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break

                buffer += chunk.decode('utf-8', errors='replace')
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        req_data = json.loads(line)
                        req = IPCRequest.from_dict(req_data)
                        resp = self._dispatch_action(req)
                    except Exception as ex:
                        resp = IPCResponse(success=False, error=f"Invalid request format: {ex}")

                    resp_bytes = (json.dumps(resp.to_dict(), ensure_ascii=False) + '\n').encode('utf-8')
                    client_sock.sendall(resp_bytes)

        except (ConnectionResetError, BrokenPipeError, socket.timeout):
            pass
        except Exception as e:
            logger.error(f"IPC client handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self.clients_count = max(0, self.clients_count - 1)

    def _dispatch_action(self, req: IPCRequest) -> IPCResponse:
        """Route IPC request to appropriate handler"""
        action = req.action.lower()
        params = req.params or {}

        # 1. PING
        if action == IPCAction.PING.value or action == "ping":
            return IPCResponse(
                success=True,
                data={"pong": True, "time": time.time(), "pid": os.getpid()},
                req_id=req.req_id
            )

        # 2. STATUS
        if action == IPCAction.STATUS.value or action == "status":
            return IPCResponse(success=True, data=self._get_full_status(), req_id=req.req_id)

        # 3. PORT_STATUS
        if action == IPCAction.PORT_STATUS.value or action == "port_status":
            return IPCResponse(success=True, data=self._get_port_status(), req_id=req.req_id)

        # 4. EXEC_CMD (CLI command string execution)
        if action == IPCAction.EXEC_CMD.value or action == "exec_cmd":
            cmd_line = params.get("cmd_line", "").strip()
            if not cmd_line:
                return IPCResponse(success=False, error="No command provided", req_id=req.req_id)

            if not self.command_handler:
                return IPCResponse(success=False, error="No CommandHandler configured on Daemon", req_id=req.req_id)

            ctx = self.command_handler.parse_command(cmd_line)
            res = self.command_handler.execute(ctx)
            return IPCResponse(
                success=res.success,
                data={
                    "command": ctx.command,
                    "success": res.success,
                    "message": res.message,
                    "data": res.data,
                    "error": res.error
                },
                error=res.error,
                req_id=req.req_id
            )


        # 5. GET_DEVICES
        if action == IPCAction.GET_DEVICES.value or action == "get_devices":
            if self.controller and self.controller.device_manager:
                devices = self.controller.device_manager.list_devices()
                active = self.controller.device_manager.get_active_device()
                return IPCResponse(
                    success=True,
                    data={"devices": [d.to_dict() if hasattr(d, 'to_dict') else d for d in devices], "active": active},
                    req_id=req.req_id
                )
            return IPCResponse(success=False, error="DeviceManager not initialized", req_id=req.req_id)

        # 6. SET_TARGET
        if action == IPCAction.SET_TARGET.value or action == "set_target":
            endpoint = params.get("endpoint")
            if not endpoint:
                return IPCResponse(success=False, error="Missing endpoint parameter", req_id=req.req_id)
            if self.controller and self.controller.device_manager:
                ok = self.controller.device_manager.set_active_device(endpoint)
                return IPCResponse(success=ok, data={"active_device": endpoint}, req_id=req.req_id)
            return IPCResponse(success=False, error="DeviceManager not available", req_id=req.req_id)

        # 6a. REMOVE_DEVICE
        if action == "remove_device":
            endpoint = params.get("endpoint")
            if not endpoint:
                return IPCResponse(success=False, error="Missing endpoint parameter", req_id=req.req_id)
            if self.controller and self.controller.device_manager:
                ok = self.controller.device_manager.remove_device(endpoint)
                return IPCResponse(success=ok, data={"removed": endpoint}, req_id=req.req_id)
            return IPCResponse(success=False, error="DeviceManager not available", req_id=req.req_id)

        # 6b. CLEAR_OFFLINE
        if action == "clear_offline":
            if self.controller and self.controller.device_manager:
                count = self.controller.device_manager.clear_offline_devices()
                return IPCResponse(success=True, data={"cleared_count": count}, req_id=req.req_id)
            return IPCResponse(success=False, error="DeviceManager not available", req_id=req.req_id)


        # 7. GET_LOGS
        if action == IPCAction.GET_LOGS.value or action == "get_logs":
            since_id = params.get("since_id", -1)
            max_count = params.get("max_count", 50)
            logs = logger.get_history(since_id=since_id, max_count=max_count)
            return IPCResponse(success=True, data={"logs": logs}, req_id=req.req_id)

        # 8. CLEAR_LOGS
        if action == IPCAction.CLEAR_LOGS.value or action == "clear_logs":
            logger.clear_history()
            return IPCResponse(success=True, data={"cleared": True}, req_id=req.req_id)

        # 9. RUN_SCRIPT
        if action == IPCAction.RUN_SCRIPT.value or action == "run_script":
            script_path = params.get("script_path")
            if not script_path:
                return IPCResponse(success=False, error="Missing script_path", req_id=req.req_id)
            if not self.controller or not self.controller.script_engine:
                return IPCResponse(success=False, error="ScriptEngine not available", req_id=req.req_id)

            try:
                rep = self.controller.script_engine.execute_script(
                    script_input=script_path,
                    controller=self.controller
                )
                return IPCResponse(
                    success=(rep.status == "PASS"),
                    data={
                        "script_path": rep.script_path,
                        "status": rep.status,
                        "total_steps": rep.total_steps,
                        "passed_count": rep.passed_count,
                        "failed_count": rep.failed_count,
                        "error_count": rep.error_count,
                        "elapsed_sec": rep.elapsed_sec
                    },
                    req_id=req.req_id
                )
            except Exception as e:
                return IPCResponse(success=False, error=str(e), req_id=req.req_id)

        # 10. SHUTDOWN
        if action == IPCAction.SHUTDOWN.value or action == "shutdown":
            def delayed_stop():
                time.sleep(0.2)
                if self.controller:
                    self.controller.disconnect()
                self.stop()
                os._exit(0)
            threading.Thread(target=delayed_stop, daemon=True).start()
            return IPCResponse(success=True, data={"shutting_down": True}, req_id=req.req_id)

        return IPCResponse(success=False, error=f"Unknown IPC action: {action}", req_id=req.req_id)

    def _get_full_status(self) -> Dict[str, Any]:
        """Aggregate full controller, daemon, ports, and stats status"""
        uptime = round(time.time() - self.start_time, 1)
        ctrl = self.controller

        broker_host = getattr(getattr(ctrl, 'config', None), 'transport', None)
        b_host = getattr(broker_host, 'host', '127.0.0.1') if broker_host else '127.0.0.1'
        b_port = getattr(broker_host, 'port', 61614) if broker_host else 61614
        b_proto = getattr(broker_host, 'protocol', 'stomp') if broker_host else 'stomp'

        is_conn = ctrl.is_connected() if ctrl else False
        transport_state = "DISCONNECTED"
        subscriptions = []
        if ctrl and ctrl.transport:
            if hasattr(ctrl.transport, 'state') and hasattr(ctrl.transport.state, 'value'):
                transport_state = str(ctrl.transport.state.value)
            elif is_conn:
                transport_state = "CONNECTED"
            if hasattr(ctrl.transport, 'subscriptions') and isinstance(ctrl.transport.subscriptions, dict):
                subscriptions = list(ctrl.transport.subscriptions.keys())

        active_target = ctrl.device_manager.get_active_device() if ctrl and ctrl.device_manager else None
        active_target_status = "none"
        if active_target and ctrl and ctrl.device_manager:
            active_target_status = ctrl.device_manager.get_device_status(active_target)

        known_count = len(ctrl.device_manager.list_devices()) if ctrl and ctrl.device_manager else 0


        rx_topic = getattr(getattr(ctrl, 'config', None), 'receive_topic', '/queue/usp.controller.default')
        reply_q = getattr(getattr(ctrl, 'config', None), 'reply_to_queue', f'/queue/{getattr(ctrl, "endpoint_id", "controller")}')

        return {
            "daemon": {
                "running": True,
                "pid": os.getpid(),
                "uptime": uptime,
                "active_threads": threading.active_count(),
                "connected_clients": self.clients_count
            },
            "broker": {
                "connected": is_conn,
                "state": transport_state,
                "protocol": b_proto,
                "host": b_host,
                "port": b_port,
                "receive_topic": rx_topic,
                "reply_to_queue": reply_q,
                "subscriptions": subscriptions,
                "listening": check_port_listening(b_host, b_port, timeout=0.3)
            },
            "ports": {
                "ipc_port": self.port,
                "ipc_listening": True,
                "broker_port": b_port,
                "broker_listening": check_port_listening(b_host, b_port, timeout=0.3)
            },

            "target": {
                "endpoint": active_target,
                "status": active_target_status
            },
            "stats": {
                "known_devices": known_count,
                "debug_level": getattr(ctrl, 'debug_level', 0) if ctrl else 0
            }
        }

    def _get_port_status(self) -> Dict[str, Any]:
        """Check all relevant ports status"""
        ctrl = self.controller
        broker_cfg = getattr(getattr(ctrl, 'config', None), 'transport', None)
        b_host = getattr(broker_cfg, 'host', '127.0.0.1') if broker_cfg else '127.0.0.1'
        b_port = getattr(broker_cfg, 'port', 61614) if broker_cfg else 61614

        return {
            "ipc": {
                "port": self.port,
                "host": self.host,
                "status": "LISTEN",
                "listening": True
            },
            "broker": {
                "port": b_port,
                "host": b_host,
                "status": "LISTEN" if check_port_listening(b_host, b_port) else "CLOSED",
                "listening": check_port_listening(b_host, b_port)
            },
            "timestamp": time.time()
        }
