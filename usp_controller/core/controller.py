#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller Core Engine
Central controller orchestrating Transport, Protocol, Device Management, and Synchronous Request-Response Routing.
"""

import time
import threading
from typing import Dict, Optional, Any, List, Union, Callable
from ..config import ControllerConfig, load_config
from ..logger import get_logger, set_debug_level
from ..transport import TransportFactory, TransportProtocol, TransportState
from ..protocol import USPMessage, USPParser
from ..device import DeviceManager

logger = get_logger()


class USPControllerCore:
    """
    Unified, High-Performance USP Controller Core Engine
    """

    def __init__(self, config: Optional[ControllerConfig] = None, config_path: str = "config.json"):
        if config is None:
            self.config = load_config(config_path)
        else:
            self.config = config

        self.controller_id = self.config.controller_endpoint_id
        set_debug_level(self.config.debug_level)

        self.transport: Optional[TransportProtocol] = None
        self.usp_builder: Optional[USPMessage] = None
        self.device_manager: DeviceManager = DeviceManager(
            devices_file=self.config.devices_file,
            device_timeout=self.config.heartbeat.timeout if hasattr(self.config, 'heartbeat') else 300
        )

        # Synchronous request tracking: msg_id -> {event: threading.Event, result: None, start_time: float}
        self._pending_requests: Dict[str, Dict[str, Any]] = {}
        self._pending_lock = threading.Lock()

        # Listeners for asynchronous notifications
        self._notify_listeners: List[Callable[[Dict[str, Any]], None]] = []

        self.initialize()

    def initialize(self) -> bool:
        """Initialize transport, protocol builder, and device manager"""
        try:
            # Create transport
            extra_params = getattr(self.config.transport, 'extra', {})
            transport_params = {
                'host': self.config.transport.host,
                'port': self.config.transport.port,
                'username': self.config.transport.username,
                'password': self.config.transport.password,
                **extra_params
            }
            self.transport = TransportFactory.create(
                self.config.transport.protocol,
                transport_params
            )

            self.transport.set_message_callback(self._on_transport_message)
            self.transport.set_state_callback(self._on_transport_state_change)

            # Create USP message builder
            self.usp_builder = USPMessage(self.controller_id)

            logger.info("USP Controller Core initialized successfully", level=1)
            return True
        except Exception as e:
            logger.critical(f"Failed to initialize controller core: {e}")
            return False

    def connect(self) -> bool:
        """Connect to broker and subscribe to receive queue/topic"""
        if not self.transport:
            if not self.initialize():
                return False

        if self.transport.connect():
            receive_dest = self.config.receive_topic
            self.transport.subscribe(receive_dest)

            reply_queue = getattr(self.config, 'reply_to_queue', None) or f"/queue/{self.controller_id}"
            if reply_queue != receive_dest:
                self.transport.subscribe(reply_queue)

            logger.success(f"Connected to transport ({self.config.transport.protocol.upper()}) and subscribed", level=0)
            return True

        return False

    def disconnect(self) -> bool:
        """Disconnect from transport"""
        if self.transport:
            return self.transport.disconnect()
        return True

    def is_connected(self) -> bool:
        """Check connection state"""
        return self.transport.is_connected() if self.transport else False

    def get_status(self) -> Dict[str, Any]:
        """Get summary status of controller, transport, and active device"""
        active_ep = self.device_manager.get_active_device()
        return {
            "controller_id": self.controller_id,
            "protocol": self.config.transport.protocol,
            "broker_host": self.config.transport.host,
            "broker_port": self.config.transport.port,
            "connected": self.is_connected(),
            "receive_topic": self.config.receive_topic,
            "active_device": active_ep,
            "active_device_status": self.device_manager.get_device_status(active_ep) if active_ep else "none",
            "total_devices": len(self.device_manager.devices),
            "debug_level": self.config.debug_level
        }

    def _resolve_target_endpoint(self, endpoint: Optional[str]) -> Optional[str]:
        """Resolve destination endpoint ID"""
        if endpoint and endpoint.strip():
            ep = endpoint.strip()
            # If placeholders are present, resolve active
            if ep in ("{ENDPOINT}", "$ENDPOINT", "default"):
                return self.device_manager.get_active_device()
            return ep
        return self.device_manager.get_active_device()

    def _send_sync_request(self, target_endpoint: str,
                           build_fn: Callable[[str, Optional[str]], Tuple[str, bytes]],
                           timeout: float = 5.0,
                           action_name: str = "REQ",
                           req_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send a USP request synchronously and wait for the correlated response
        """
        if not self.is_connected():
            return {
                "status": "error",
                "error": "Controller is not connected to broker. Please connect first."
            }

        if not target_endpoint:
            return {
                "status": "error",
                "error": "No target endpoint specified and no active device registered."
            }

        # Build request with new msg_id
        msg_id, record_bytes = build_fn(target_endpoint, None)
        destination = self.device_manager.get_reply_destination(target_endpoint)
        reply_to_dest = self.config.receive_topic

        event = threading.Event()
        req_entry = {
            "event": event,
            "result": None,
            "start_time": time.time(),
            "endpoint": target_endpoint,
            "msg_id": msg_id
        }

        with self._pending_lock:
            self._pending_requests[msg_id] = req_entry

        try:
            req_details = {
                "MsgID": msg_id,
                "Action": action_name,
                "Target": target_endpoint,
                "Destination": destination,
                "ReplyTo": reply_to_dest
            }
            if req_info:
                req_details.update(req_info)

            logger.usp_message("send", target_endpoint, f"{action_name} (ID: {msg_id})", details=req_details, level=1)
            sent = self.transport.send(
                destination=destination,
                body=record_bytes,
                headers={
                    'content-type': 'application/vnd.bbf.usp.msg',
                    'reply-to-dest': reply_to_dest
                }
            )

            if not sent:
                with self._pending_lock:
                    self._pending_requests.pop(msg_id, None)
                return {"status": "error", "error": f"Failed to transmit frame to {destination}"}

            # Wait for response
            got_response = event.wait(timeout=timeout)
            elapsed = time.time() - req_entry["start_time"]

            if not got_response:
                with self._pending_lock:
                    self._pending_requests.pop(msg_id, None)
                return {
                    "status": "timeout",
                    "error": f"Request to {target_endpoint} timed out after {timeout:.1f}s (msg_id: {msg_id})",
                    "elapsed_sec": round(elapsed, 3),
                    "endpoint": target_endpoint
                }

            result = req_entry["result"] or {"status": "success"}
            result["elapsed_sec"] = round(elapsed, 3)
            result["endpoint"] = target_endpoint
            return result

        except Exception as e:
            with self._pending_lock:
                self._pending_requests.pop(msg_id, None)
            logger.error(f"Error during synchronous request: {e}")
            return {"status": "error", "error": str(e), "endpoint": target_endpoint}

    def _on_transport_message(self, headers: Dict[str, str], body: bytes, sender: Optional[str]):
        """Callback when a message arrives from transport"""
        try:
            from_id, to_id, msg = USPMessage.parse_record(body)
            reply_to = headers.get('reply-to-dest')

            if from_id:
                self.device_manager.register_or_update(from_id, reply_to=reply_to)

            if not msg:
                return

            msg_id = msg.header.msg_id
            msg_type = msg.header.msg_type
            parsed = USPParser.parse_msg(msg)

            resp_details = {
                "MsgID": msg_id,
                "Type": parsed.get("msg_type", msg_type),
                "From": from_id,
                "Status": parsed.get("status", "success")
            }
            if "parameters" in parsed and parsed["parameters"]:
                resp_details["Parameters"] = parsed["parameters"]
            if "updated_params" in parsed and parsed["updated_params"]:
                resp_details["Updated"] = parsed["updated_params"]
            if "created" in parsed and parsed["created"]:
                resp_details["Created"] = [c.get("instantiated_path") for c in parsed["created"]]
            if "deleted" in parsed and parsed["deleted"]:
                resp_details["Deleted"] = parsed["deleted"]
            if "output_args" in parsed and parsed["output_args"]:
                resp_details["OutputArgs"] = parsed["output_args"]
            if "instances" in parsed and parsed["instances"]:
                resp_details["Instances"] = parsed["instances"]
            if "err_msg" in parsed and parsed["err_msg"]:
                resp_details["Error"] = f"[{parsed.get('err_code', '')}] {parsed.get('err_msg')}"
            if "event_name" in parsed:
                resp_details["Event"] = parsed.get("event_name")
            if "event_params" in parsed:
                resp_details["EventParams"] = parsed.get("event_params")

            logger.usp_message("recv", from_id or "unknown", f"RESP ({parsed.get('msg_type', msg_type)})", details=resp_details, level=1)

            # Check for correlated pending synchronous request
            with self._pending_lock:
                if msg_id in self._pending_requests:
                    req_entry = self._pending_requests.pop(msg_id)
                    req_entry["result"] = parsed
                    req_entry["event"].set()
                    return

            # If NOTIFY request, handle notification
            if msg.body.HasField('request') and msg.body.request.HasField('notify'):
                notify_req = msg.body.request.notify
                if notify_req.send_resp:
                    # Send NOTIFY_RESP back to agent
                    dest = self.device_manager.get_reply_destination(from_id)
                    _, resp_bytes = self.usp_builder.build_notify_resp(from_id, notify_req.subscription_id, msg_id)
                    self.transport.send(dest, resp_bytes)

                # Broadcast to notify listeners
                for listener in self._notify_listeners:
                    try:
                        listener(parsed)
                    except Exception as e:
                        logger.error(f"Error in notify listener: {e}")

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            logger.error(f"Error handling message in core: {e}\n{tb}")


    def _on_transport_state_change(self, new_state: TransportState):
        """Callback when transport connection state changes"""
        logger.info(f"Transport connection state changed: {new_state.value}", level=1)

    def add_notify_listener(self, listener: Callable[[Dict[str, Any]], None]):
        """Register a callback for incoming NOTIFY requests"""
        if listener not in self._notify_listeners:
            self._notify_listeners.append(listener)

    def remove_notify_listener(self, listener: Callable[[Dict[str, Any]], None]):
        """Remove a callback for incoming NOTIFY requests"""
        if listener in self._notify_listeners:
            self._notify_listeners.remove(listener)

    # ==================== Core Operations (Get, Set, Add, Delete, etc.) ====================

    def get(self, paths: Union[str, List[str]], endpoint: Optional[str] = None, timeout: float = 5.0) -> Dict[str, Any]:
        """Send GET request"""
        target = self._resolve_target_endpoint(endpoint)
        path_list = [paths] if isinstance(paths, str) else list(paths)

        def builder(ep, mid):
            return self.usp_builder.build_get(ep, path_list, mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="GET",
            req_info={"RequestedPaths": path_list}
        )

    def set(self, params: Dict[str, Any], endpoint: Optional[str] = None,
            allow_partial: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
        """Send SET request"""
        target = self._resolve_target_endpoint(endpoint)

        def builder(ep, mid):
            return self.usp_builder.build_set(ep, params, allow_partial=allow_partial, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="SET",
            req_info={"Parameters": params, "AllowPartial": allow_partial}
        )

    def add(self, obj_path: str, params: Optional[Dict[str, Any]] = None,
            endpoint: Optional[str] = None, allow_partial: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
        """Send ADD request"""
        target = self._resolve_target_endpoint(endpoint)

        def builder(ep, mid):
            return self.usp_builder.build_add(ep, obj_path, params=params, allow_partial=allow_partial, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="ADD",
            req_info={"ObjectPath": obj_path, "InitialParams": params or {}}
        )

    def delete(self, obj_paths: Union[str, List[str]], endpoint: Optional[str] = None,
               allow_partial: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
        """Send DELETE request"""
        target = self._resolve_target_endpoint(endpoint)
        paths = [obj_paths] if isinstance(obj_paths, str) else list(obj_paths)

        def builder(ep, mid):
            return self.usp_builder.build_delete(ep, paths, allow_partial=allow_partial, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="DELETE",
            req_info={"ObjectPaths": paths}
        )

    def operate(self, command: str, args: Optional[Dict[str, Any]] = None,
                endpoint: Optional[str] = None, timeout: float = 8.0) -> Dict[str, Any]:
        """Send OPERATE request"""
        target = self._resolve_target_endpoint(endpoint)

        def builder(ep, mid):
            return self.usp_builder.build_operate(ep, command, args=args, send_resp=True, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="OPERATE",
            req_info={"Command": command, "Args": args or {}}
        )

    def get_supported_dm(self, obj_paths: Optional[Union[str, List[str]]] = None,
                         endpoint: Optional[str] = None, first_level_only: bool = False,
                         timeout: float = 8.0) -> Dict[str, Any]:
        """Send GetSupportedDM request"""
        target = self._resolve_target_endpoint(endpoint)
        paths = [obj_paths] if isinstance(obj_paths, str) else ([obj_paths] if obj_paths else [])

        def builder(ep, mid):
            return self.usp_builder.build_get_supported_dm(ep, obj_paths=paths, first_level_only=first_level_only, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="GET_SUPPORTED_DM",
            req_info={"Paths": paths, "FirstLevelOnly": first_level_only}
        )

    def get_instances(self, obj_path: str, endpoint: Optional[str] = None,
                      first_level_only: bool = False, timeout: float = 5.0) -> Dict[str, Any]:
        """Send GetInstances request"""
        target = self._resolve_target_endpoint(endpoint)

        def builder(ep, mid):
            return self.usp_builder.build_get_instances(ep, obj_path, first_level_only=first_level_only, msg_id=mid)

        return self._send_sync_request(
            target, builder, timeout=timeout, action_name="GET_INSTANCES",
            req_info={"ObjectPath": obj_path, "FirstLevelOnly": first_level_only}
        )

