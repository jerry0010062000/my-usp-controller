#!/usr/bin/env python3
"""
Dual-Mode USP/STOMP Controller
Mode 1: Interactive Shell (User)
Mode 2: Background Daemon with IPC (Automation)
"""

__version__ = "2.0.0"
__author__ = "Jerry Bai"

import socket
import threading
import time
import sys
import uuid
import json
import select
from datetime import datetime
import argparse

# Import USP protobuf definitions
try:
    import usp_record_1_4_pb2 as record_pb2
    import usp_msg_1_4_pb2 as msg_pb2
except ImportError:
    print("[!] Error: Protobuf files not found or protobuf library missing.")
    sys.exit(1)

# Enable command line editing for interactive mode
try:
    import readline
    import os
    histfile = os.path.join(os.path.expanduser("~"), ".usp_controller_history")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass
    import atexit
    atexit.register(readline.write_history_file, histfile)
except ImportError:
    pass

# --- Configuration ---
BROKER_HOST = '127.0.0.1'
BROKER_PORT = 61613
USERNAME = 'admin'
PASSWORD = 'password'

# Controller Identity
CONTROLLER_ENDPOINT_ID = 'proto::controller-1'
RECEIVE_TOPIC = '/topic/my_send_q'
SEND_DESTINATION = '/topic/agent'
REPLY_TO_QUEUE = f'/queue/{CONTROLLER_ENDPOINT_ID}'
DEVICES_FILE = 'devices.json'
PID_FILE = '/tmp/usp_controller.pid'

# IPC Configuration (For Gemini/Daemon communication)
IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

# Debug Levels
DEBUG_LEVEL = 0
"""
Debug Levels:
  0 - Agent Only: Only show agent response data (DM values)
  1 - Both Payloads: Show controller requests + agent responses (USP messages)
  2 - Full Details: Show complete STOMP headers + payloads
"""

class Logger:
    """Centralized logging with debug levels"""
    
    @staticmethod
    def critical(msg):
        """Always show critical messages"""
        print(f"[!] {msg}")
    
    @staticmethod
    def info(msg, level=1):
        """Show info messages based on debug level"""
        if DEBUG_LEVEL >= level:
            print(f"[*] {msg}")
    
    @staticmethod
    def success(msg, level=1):
        """Show success messages"""
        if DEBUG_LEVEL >= level:
            print(f"[✓] {msg}")
    
    @staticmethod
    def data(msg, level=0):
        """Show response data (level 0+)"""
        if DEBUG_LEVEL >= level:
            print(msg)
    
    @staticmethod
    def stomp_frame(direction, headers, body_preview=None, level=2):
        """Display STOMP frame information"""
        if DEBUG_LEVEL < level:
            return
        
        arrow = ">>>>" if direction == "send" else "<<<<"
        print(f"\n{arrow} STOMP Frame {arrow}")
        
        # Show headers at level 2+
        if DEBUG_LEVEL >= 2 and headers:
            for key, value in headers.items():
                print(f"  {key}: {value}")
        
        # Show body preview at level 3+
        if DEBUG_LEVEL >= 3 and body_preview:
            if isinstance(body_preview, bytes):
                if len(body_preview) > 100:
                    print(f"  Body: {body_preview[:100].hex()}... ({len(body_preview)} bytes)")
                else:
                    print(f"  Body: {body_preview.hex()}")
            else:
                print(f"  Body: {body_preview}")
        print("")
    
    @staticmethod
    def usp_message(direction, endpoint, msg_type, details=None, level=1):
        """Display USP message information"""
        if DEBUG_LEVEL < level:
            return
        
        arrow = "→" if direction == "send" else "←"
        print(f"{arrow} USP {msg_type} {arrow} {endpoint}")
        
        if DEBUG_LEVEL >= 2 and details:
            for key, value in details.items():
                print(f"    {key}: {value}")

DEBUG_MODE = False  # Legacy, kept for compatibility

def check_and_kill_old_daemon(force=False):
    """Check if old daemon is running and kill it"""
    import signal
    
    if not os.path.exists(PID_FILE):
        return True
    
    try:
        with open(PID_FILE, 'r') as f:
            old_pid = int(f.read().strip())
        
        # Check if process exists
        try:
            os.kill(old_pid, 0)  # Signal 0 checks if process exists
            # Process exists
            if force:
                print(f"[*] Found old daemon (PID {old_pid}), terminating...")
                os.kill(old_pid, signal.SIGTERM)
                time.sleep(0.5)
                # Check if still alive, force kill
                try:
                    os.kill(old_pid, 0)
                    print(f"[*] Force killing old daemon...")
                    os.kill(old_pid, signal.SIGKILL)
                    time.sleep(0.3)
                except ProcessLookupError:
                    pass
                print(f"[✓] Old daemon terminated")
                return True
            else:
                print(f"[!] Daemon already running (PID {old_pid})")
                print(f"    Use --force to terminate old daemon and start new one")
                print(f"    Or manually kill it: kill {old_pid}")
                return False
        except ProcessLookupError:
            # Process doesn't exist, remove stale PID file
            os.remove(PID_FILE)
            return True
    except Exception as e:
        print(f"[!] Error checking old daemon: {e}")
        return False

def write_pid_file():
    """Write current PID to file"""
    try:
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
    except Exception as e:
        print(f"[!] Warning: Could not write PID file: {e}")

def remove_pid_file():
    """Remove PID file on exit"""
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception as e:
        print(f"[!] Warning: Could not remove PID file: {e}")

class STOMPManager:
    """Manages STOMP connection and state"""
    
    def __init__(self):
        self.sock = None
        self.connected = False
        self.running = False
        self.devices = {}  # {endpoint_id: {info}}
        self.subscription_ids = {}
        self.msg_callbacks = []
        self.last_active_device = None
        self.lock = threading.Lock()
        
    def load_devices(self):
        """Load known devices from file"""
        try:
            if os.path.exists(DEVICES_FILE):
                with open(DEVICES_FILE, 'r') as f:
                    self.devices = json.load(f)
                Logger.info(f"Loaded {len(self.devices)} devices from {DEVICES_FILE}", level=1)
                return True
        except Exception as e:
            Logger.critical(f"Failed to load devices: {e}")
        return False

    def save_devices(self):
        """Save known devices to file"""
        try:
            with open(DEVICES_FILE, 'w') as f:
                json.dump(self.devices, f, indent=2)
        except Exception as e:
            Logger.critical(f"Failed to save devices: {e}")

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((BROKER_HOST, BROKER_PORT))
            
            connect_frame = (
                f"CONNECT\n"
                f"accept-version:1.2\n"
                f"host:/\n"
                f"login:{USERNAME}\n"
                f"passcode:{PASSWORD}\n"
                f"heart-beat:0,0\n"
                f"\n\0"
            )
            
            self.sock.sendall(connect_frame.encode('utf-8'))
            
            # Wait for CONNECTED
            self.sock.settimeout(5)
            response = self._recv_frame_raw()
            
            if response and b'CONNECTED' in response:
                self.connected = True
                self.running = True
                Logger.success(f"Connected to STOMP Broker ({BROKER_HOST}:{BROKER_PORT})", level=0)
                
                # Start receiver thread
                self.recv_thread = threading.Thread(target=self._receiver_loop, daemon=True)
                self.recv_thread.start()
                
                # Subscribe to self and wildcards
                self.subscribe(RECEIVE_TOPIC)
                self.subscribe(REPLY_TO_QUEUE)
                self.subscribe("/topic/>")
                self.subscribe("/queue/>")

                # Load and subscribe to known devices
                self.load_devices()
                for endpoint, info in self.devices.items():
                    if 'reply_to' in info:
                        Logger.info(f"Restoring subscription for {endpoint}: {info['reply_to']}", level=1)
                        self.subscribe(info['reply_to'])
                
                return True
            else:
                Logger.critical(f"Connection failed. Response: {response}")
                return False
                
        except Exception as e:
            Logger.critical(f"Connection error: {e}")
            return False

    def subscribe(self, destination):
        if not self.connected: return
        
        sub_id = f"sub-{len(self.subscription_ids)}"
        frame = (
            f"SUBSCRIBE\n"
            f"id:{sub_id}\n"
            f"destination:{destination}\n"
            f"ack:auto\n"
            f"\n\0"
        )
        self.sock.sendall(frame.encode('utf-8'))
        self.subscription_ids[destination] = sub_id

    def send(self, destination, body_bytes, content_type='application/vnd.bbf.usp.msg', reply_to=None):
        if not self.connected: return False
        
        try:
            headers = {
                "destination": destination,
                "content-type": content_type,
                "content-length": str(len(body_bytes))
            }
            if reply_to:
                headers["reply-to-dest"] = reply_to
            
            # Log STOMP frame
            Logger.stomp_frame("send", headers, body_bytes, level=2)
            
            header_list = [f"SEND"]
            for k, v in headers.items():
                header_list.append(f"{k}:{v}")
            
            frame = '\n'.join(header_list).encode('utf-8') + b'\n\n' + body_bytes + b'\0'
            self.sock.sendall(frame)
            return True
        except Exception as e:
            Logger.critical(f"Send error: {e}")
            return False

    def _recv_frame_raw(self):
        """Read until NULL byte"""
        buffer = b''
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk: return None
                buffer += chunk
                if b'\0' in buffer:
                    return buffer
            except socket.timeout:
                return None
            except Exception:
                return None

    def _receiver_loop(self):
        buffer = b''
        while self.running:
            try:
                ready = select.select([self.sock], [], [], 1.0)
                if ready[0]:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        print("[!] Connection closed by broker")
                        self.connected = False
                        break
                    buffer += chunk
                    
                    while True:
                        # 1. Parse Headers
                        if b'\n\n' not in buffer:
                            break
                            
                        header_end = buffer.find(b'\n\n')
                        header_bytes = buffer[:header_end]
                        
                        # Parse content-length from header bytes
                        content_length = -1
                        header_text = header_bytes.decode('utf-8', errors='ignore')
                        for line in header_text.split('\n'):
                            if 'content-length:' in line.lower():
                                try:
                                    content_length = int(line.split(':')[1].strip())
                                except:
                                    pass
                                break
                        
                        # 2. Check if we have the full body
                        body_start = header_end + 2
                        
                        if content_length >= 0:
                            # We need body + NULL byte
                            required_len = body_start + content_length + 1
                            if len(buffer) < required_len:
                                break # Wait for more data
                            
                            # Extract frame
                            frame_data = buffer[:required_len-1] # Exclude trailing NULL
                            buffer = buffer[required_len:]
                            self._process_frame(frame_data)
                        
                        else:
                            # No content-length, read until NULL
                            if b'\0' not in buffer[body_start:]:
                                break
                            
                            null_pos = buffer.find(b'\0', body_start)
                            frame_data = buffer[:null_pos]
                            buffer = buffer[null_pos+1:]
                            self._process_frame(frame_data)
                            
            except Exception as e:
                if self.running:
                    print(f"[!] Receiver error: {e}")
                break

    def _process_frame(self, frame_bytes):
        try:
            # Separate headers and body
            if b'\n\n' in frame_bytes:
                header_part, body = frame_bytes.split(b'\n\n', 1)
            else:
                header_part = frame_bytes
                body = b''
                
            headers = {}
            header_lines = header_part.decode('utf-8', errors='ignore').split('\n')
            
            # Find the first non-empty line as the command
            command = ""
            start_idx = 0
            for i, line in enumerate(header_lines):
                if line.strip():
                    command = line.strip()
                    start_idx = i + 1
                    break
            
            for line in header_lines[start_idx:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            
            # Log STOMP frame at level 2
            if command == "MESSAGE":
                Logger.stomp_frame("recv", headers, body if len(body) < 200 else body[:200])
                self._handle_message(headers, body)
                
        except Exception as e:
            Logger.critical(f"Frame processing error: {e}")

    def _handle_message(self, headers, body):
        # 1. Device Discovery logic
        sender = None
        reply_to = headers.get('reply-to-dest')
        
        # Try to parse sender from reply-to header
        if reply_to:
            # Clean ActiveMQ format \c -> :
            clean_reply = reply_to.replace('\\c', ':')
            # Extract ID if present (simple heuristic)
            if 'proto::' in clean_reply or 'os::' in clean_reply:
                # Assuming queue name contains ID or IS the ID prefixed
                # Typical: /queue/proto::agent-1
                parts = clean_reply.split('/')
                for p in parts:
                    if '::' in p:
                        sender = p
                        break
        
        # If not found, try parsing USP record
        if 'application/vnd.bbf.usp.msg' in headers.get('content-type', ''):
            try:
                rec = record_pb2.Record()
                rec.ParseFromString(body)
                sender = rec.from_id
                
                # Parsing for logging
                if rec.HasField('no_session_context'):
                    msg = msg_pb2.Msg()
                    msg.ParseFromString(rec.no_session_context.payload)
                    mtype = msg_pb2.Header.MsgType.Name(msg.header.msg_type)
                    
                    details = {"msg_id": msg.header.msg_id} if DEBUG_LEVEL >= 2 else None
                    Logger.usp_message("recv", sender, mtype, details)
                    
                    if msg.body.HasField('response'):
                        self._handle_usp_response(sender, msg)
                    elif msg.body.HasField('request'):
                        Logger.info(f"Received USP Request from {sender}", level=2)
                    elif msg.body.HasField('error'):
                        Logger.critical(f"USP Error from {sender}: {msg.body.error.err_msg}")
                        
            except Exception as e:
                import traceback
                Logger.critical(f"USP parsing error: {e}")
                if DEBUG_LEVEL >= 2:
                    Logger.critical(f"Traceback: {traceback.format_exc()}")
        
        # 2. Store discovered device
        if sender and reply_to:
            with self.lock:
                if sender not in self.devices:
                    Logger.success(f"Discovered new device: {sender}", level=1)
                    self.subscribe(reply_to)
                
                self.devices[sender] = {
                    'reply_to': reply_to,
                    'last_seen': datetime.now().isoformat()
                }
                self.last_active_device = sender
                
                # Save to disk
                self.save_devices()
        
        # 3. Notify callbacks (IPC, UI)
        for cb in self.msg_callbacks:
            cb(headers, body, sender)
    
    def _handle_usp_response(self, sender, msg):
        """Handle and display USP response messages"""
        resp = msg.body.response
        
        if resp.HasField('get_resp'):
            for r in resp.get_resp.req_path_results:
                status = '✓' if r.err_code == 0 else '✗'
                Logger.data(f"  Path: {r.requested_path} ({status})")
                for res in r.resolved_path_results:
                    Logger.data(f"    {res.resolved_path}")
                    for p, v in res.result_params.items():
                        Logger.data(f"      {p} = {v}")
                    
        elif resp.HasField('get_supported_dm_resp'):
            count = 0
            for r in resp.get_supported_dm_resp.req_obj_results:
                for obj in r.supported_objs:
                    # Object info
                    obj_info = obj.supported_obj_path
                    if obj.is_multi_instance:
                        obj_info += " (multi-instance)"
                    Logger.data(f"    {obj_info}")
                    count += 1
                    
                    # Parameters with access rights
                    for p in obj.supported_params:
                        access = msg_pb2.GetSupportedDMResp.ParamAccessType.Name(p.access)
                        access_short = "RW" if access == "PARAM_READ_WRITE" else "R"
                        Logger.data(f"      {p.param_name} [{access_short}]")
                        count += 1
                    
                    # Commands with type
                    for c in obj.supported_commands:
                        cmd_type = msg_pb2.GetSupportedDMResp.CmdType.Name(c.command_type)
                        cmd_short = "async" if cmd_type == "CMD_ASYNC" else "sync"
                        Logger.data(f"      {c.command_name}() [{cmd_short}]")
                        count += 1
                    
                    # Events
                    for e in obj.supported_events:
                        Logger.data(f"      {e.event_name}! [event]")
                        count += 1
            Logger.data(f"  Total: {count} items")
            
        elif resp.HasField('set_resp'):
            for r in resp.set_resp.updated_obj_results:
                if r.oper_status.HasField('oper_success'):
                    Logger.data(f"  Object: {r.requested_path} (✓)")
                    for param, value in r.oper_status.oper_success.updated_inst_results[0].updated_params.items():
                        Logger.data(f"    {param} = {value}")
                elif r.oper_status.HasField('oper_failure'):
                    Logger.data(f"  Object: {r.requested_path} (✗)")
                    fail = r.oper_status.oper_failure
                    Logger.critical(f"    Error {fail.err_code}: {fail.err_msg}")
                        
        elif resp.HasField('add_resp'):
            for r in resp.add_resp.created_obj_results:
                if r.oper_status.HasField('oper_success'):
                    Logger.data(f"  Created: {r.requested_path} (✓)")
                    Logger.data(f"    Instance: {r.oper_status.oper_success.instantiated_path}")
                elif r.oper_status.HasField('oper_failure'):
                    Logger.data(f"  Created: {r.requested_path} (✗)")
                    fail = r.oper_status.oper_failure
                    Logger.critical(f"    Error {fail.err_code}: {fail.err_msg}")
                    
        elif resp.HasField('delete_resp'):
            for r in resp.delete_resp.deleted_obj_results:
                if r.oper_status.HasField('oper_success'):
                    Logger.data(f"  Deleted: {r.requested_path} (✓)")
                    for path in r.oper_status.oper_success.affected_paths:
                        Logger.data(f"    {path}")
                elif r.oper_status.HasField('oper_failure'):
                    Logger.data(f"  Deleted: {r.requested_path} (✗)")
                    fail = r.oper_status.oper_failure
                    Logger.critical(f"    Error {fail.err_code}: {fail.err_msg}")
                
        elif resp.HasField('operate_resp'):
            for r in resp.operate_resp.operation_results:
                Logger.data(f"  Command: {r.executed_command}")
                Logger.data(f"    Output: {r.output_args}")
                
        elif resp.HasField('error'):
            Logger.critical(f"Error {resp.error.err_code}: {resp.error.err_msg}")


class IPCServer(threading.Thread):
    """Local TCP Server for Gemini/External control"""
    
    def __init__(self, stomp_manager):
        super().__init__(daemon=True)
        self.stomp = stomp_manager
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = True
        self.started = False
        self.error = None
        
    def run(self):
        try:
            self.server_sock.bind((IPC_HOST, IPC_PORT))
            self.server_sock.listen(5)
            self.started = True
            print(f"[*] IPC Server listening on {IPC_HOST}:{IPC_PORT}")
            
            while self.running:
                client, addr = self.server_sock.accept()
                self._handle_client(client)
        except OSError as e:
            if e.errno == 98:  # Address already in use
                self.error = f"Port {IPC_PORT} already in use"
                print(f"[!] IPC Server: {self.error}")
                print(f"[!] Another daemon may be running. Check with: ps aux | grep 'usp_controller.py --daemon'")
                print(f"[!] To stop existing daemon: pkill -f 'usp_controller.py --daemon'")
            else:
                self.error = str(e)
                print(f"[!] IPC Server error: {e}")
        except Exception as e:
            self.error = str(e)
            print(f"[!] IPC Server error: {e}")

    def _handle_client(self, client):
        try:
            data = client.recv(4096).decode('utf-8').strip()
            if not data: return
            
            response = {"status": "error", "msg": "unknown command"}
            
            cmd_parts = data.split()
            cmd = cmd_parts[0].lower()
            
            if cmd == "status":
                response = {
                    "status": "ok",
                    "connected": self.stomp.connected,
                    "devices_count": len(self.stomp.devices),
                    "last_active": self.stomp.last_active_device
                }
            
            elif cmd == "devices":
                response = {
                    "status": "ok",
                    "devices": self.stomp.devices
                }
                
            elif cmd == "get":
                # get <endpoint> <path>
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    path = cmd_parts[2]
                    success = self._send_usp_get(endpoint, path)
                    response = {"status": "ok" if success else "failed", "msg": f"GET sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: get <endpoint> <path>"}
            
            elif cmd == "set":
                # set <endpoint> <path> <value>
                if len(cmd_parts) >= 4:
                    endpoint = cmd_parts[1]
                    path = cmd_parts[2]
                    value = " ".join(cmd_parts[3:])
                    success = self._send_usp_set(endpoint, path, value)
                    response = {"status": "ok" if success else "failed", "msg": f"SET sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: set <endpoint> <path> <value>"}
            
            elif cmd == "add":
                # add <endpoint> <obj_path>
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2]
                    success = self._send_usp_add(endpoint, obj_path)
                    response = {"status": "ok" if success else "failed", "msg": f"ADD sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: add <endpoint> <obj_path>"}
            
            elif cmd == "delete":
                # delete <endpoint> <obj_path>
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2]
                    success = self._send_usp_delete(endpoint, obj_path)
                    response = {"status": "ok" if success else "failed", "msg": f"DELETE sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: delete <endpoint> <obj_path>"}
            
            elif cmd == "get_supported" or cmd == "getsupporteddm":
                # get_supported <endpoint> [obj_path]
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2] if len(cmd_parts) >= 3 else "Device."
                    success = self._send_usp_get_supported_dm(endpoint, obj_path)
                    response = {"status": "ok" if success else "failed", "msg": f"GetSupportedDM sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: get_supported <endpoint> [obj_path]"}
            
            elif cmd == "operate":
                # operate <endpoint> <command_path> [key=value ...]
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    command_path = cmd_parts[2]
                    kwargs = {}
                    for arg in cmd_parts[3:]:
                        if '=' in arg:
                            k, v = arg.split('=', 1)
                            kwargs[k] = v
                    success = self._send_usp_operate(endpoint, command_path, **kwargs)
                    response = {"status": "ok" if success else "failed", "msg": f"OPERATE sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: operate <endpoint> <command> [key=value ...]"}
            
            client.sendall(json.dumps(response).encode('utf-8'))
            client.close()
            
        except Exception as e:
            print(f"[!] IPC Client error: {e}")
            try: client.close()
            except: pass

    def _send_usp_get(self, endpoint, path):
        """Helper to construct USP Get"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
        usp_msg.body.request.get.param_paths.append(path)
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_set(self, endpoint, path, value):
        """Helper to construct USP Set"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.SET
        
        update_obj = usp_msg.body.request.set.update_objs.add()
        # Extract object path and parameter name
        parts = path.rsplit('.', 1)
        if len(parts) == 2:
            update_obj.obj_path = parts[0] + '.'
            param_setting = update_obj.param_settings.add()
            param_setting.param = parts[1]
            param_setting.value = value
            param_setting.required = True
        else:
            update_obj.obj_path = path
            param_setting = update_obj.param_settings.add()
            param_setting.param = "Value"
            param_setting.value = value
            param_setting.required = True
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_add(self, endpoint, obj_path):
        """Helper to construct USP Add"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.ADD
        
        create_obj = usp_msg.body.request.add.create_objs.add()
        create_obj.obj_path = obj_path
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_delete(self, endpoint, obj_path):
        """Helper to construct USP Delete"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.DELETE
        
        usp_msg.body.request.delete.allow_partial = True
        usp_msg.body.request.delete.obj_paths.append(obj_path)
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_get_supported_dm(self, endpoint, obj_path="Device."):
        """Helper to construct USP GetSupportedDM"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_SUPPORTED_DM
        
        usp_msg.body.request.get_supported_dm.obj_paths.append(obj_path)
        usp_msg.body.request.get_supported_dm.first_level_only = False
        usp_msg.body.request.get_supported_dm.return_commands = True
        usp_msg.body.request.get_supported_dm.return_events = True
        usp_msg.body.request.get_supported_dm.return_params = True
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_operate(self, endpoint, command_path, **kwargs):
        """Helper to construct USP Operate"""
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.OPERATE
        
        usp_msg.body.request.operate.command = command_path
        usp_msg.body.request.operate.send_resp = True
        
        # Add input arguments if provided
        for key, value in kwargs.items():
            arg = usp_msg.body.request.operate.command_key.add()
            arg.key = key
            arg.value = str(value)
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_message(self, endpoint, usp_msg):
        """Common method to wrap USP message in Record and send"""
        msg_bytes = usp_msg.SerializeToString()
        
        usp_rec = record_pb2.Record()
        usp_rec.version = "1.4"
        usp_rec.to_id = endpoint
        usp_rec.from_id = CONTROLLER_ENDPOINT_ID
        usp_rec.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
        usp_rec.no_session_context.payload = msg_bytes
        
        rec_bytes = usp_rec.SerializeToString()
        
        # Determine destination
        device = self.stomp.devices.get(endpoint)
        dest = device['reply_to'] if device else SEND_DESTINATION
        
        return self.stomp.send(dest, rec_bytes, reply_to=REPLY_TO_QUEUE)


def interactive_mode(stomp_mgr):
    print("\n[Mode] Interactive Shell Started")
    print("Type 'help' for commands")
    
    # Create helper instance for sending USP messages
    class USPHelper:
        def __init__(self, stomp):
            self.stomp = stomp
        
        def send_get(self, endpoint, path):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
            usp_msg.body.request.get.param_paths.append(path)
            return self._wrap_and_send(endpoint, usp_msg)
        
        def send_set(self, endpoint, path, value):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.SET
            
            update_obj = usp_msg.body.request.set.update_objs.add()
            parts = path.rsplit('.', 1)
            if len(parts) == 2:
                update_obj.obj_path = parts[0] + '.'
                param_setting = update_obj.param_settings.add()
                param_setting.param = parts[1]
                param_setting.value = value
                param_setting.required = True
            else:
                update_obj.obj_path = path
                param_setting = update_obj.param_settings.add()
                param_setting.value = value
                param_setting.required = True
            return self._wrap_and_send(endpoint, usp_msg)
        
        def send_add(self, endpoint, obj_path):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.ADD
            
            create_obj = usp_msg.body.request.add.create_objs.add()
            create_obj.obj_path = obj_path
            return self._wrap_and_send(endpoint, usp_msg)
        
        def send_delete(self, endpoint, obj_path):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.DELETE
            
            usp_msg.body.request.delete.allow_partial = True
            usp_msg.body.request.delete.obj_paths.append(obj_path)
            return self._wrap_and_send(endpoint, usp_msg)
        
        def send_discover(self, endpoint, obj_path="Device."):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_SUPPORTED_DM
            
            usp_msg.body.request.get_supported_dm.obj_paths.append(obj_path)
            usp_msg.body.request.get_supported_dm.first_level_only = False
            usp_msg.body.request.get_supported_dm.return_commands = True
            usp_msg.body.request.get_supported_dm.return_events = True
            usp_msg.body.request.get_supported_dm.return_params = True
            return self._wrap_and_send(endpoint, usp_msg)
        
        def send_operate(self, endpoint, command_path, args_dict):
            msg_id = str(uuid.uuid4())
            usp_msg = msg_pb2.Msg()
            usp_msg.header.msg_id = msg_id
            usp_msg.header.msg_type = msg_pb2.Header.MsgType.OPERATE
            
            usp_msg.body.request.operate.command = command_path
            usp_msg.body.request.operate.send_resp = True
            
            for key, value in args_dict.items():
                arg = usp_msg.body.request.operate.command_key.add()
                arg.key = key
                arg.value = str(value)
            return self._wrap_and_send(endpoint, usp_msg)
        
        def _wrap_and_send(self, endpoint, usp_msg):
            msg_bytes = usp_msg.SerializeToString()
            
            usp_rec = record_pb2.Record()
            usp_rec.version = "1.4"
            usp_rec.to_id = endpoint
            usp_rec.from_id = CONTROLLER_ENDPOINT_ID
            usp_rec.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
            usp_rec.no_session_context.payload = msg_bytes
            
            dev = self.stomp.devices.get(endpoint)
            dest = dev['reply_to'] if dev else SEND_DESTINATION
            
            return self.stomp.send(dest, usp_rec.SerializeToString(), reply_to=REPLY_TO_QUEUE)
    
    helper = USPHelper(stomp_mgr)
    
    # Command aliases
    ALIASES = {
        'ls': 'list',
        'h': 'help',
        'q': 'quit',
        'exit': 'quit',
        'disc': 'discover',
        'gsdm': 'get_supported'
    }
    
    print("\n[*] Interactive mode ready. Type 'help' for commands, 'quit' to exit.")
    print("[*] Note: Use 'quit' or 'exit' to leave (Ctrl+C is disabled)\n")
    
    while True:
        try:
            cmd_str = input("usp-cli> ").strip()
            if not cmd_str: continue
            
            parts = cmd_str.split()
            cmd = parts[0].lower()
            
            # Handle aliases
            if cmd in ALIASES:
                cmd = ALIASES[cmd]
                parts[0] = cmd
            
            if cmd == 'quit':
                break
                
            elif cmd == 'help':
                print("\n" + "="*60)
                print("USP Controller - Available Commands")
                print("="*60)
                print("Basic:")
                print("  help (h)                    - Show this help")
                print("  list (ls)                   - List known devices")
                print("  status                      - Show connection status")
                print("  debug [0-2]                 - Show/set debug level")
                print("  quit (q, exit)              - Exit program")
                print("\nUSP Operations:")
                print("  get <ep> <path>             - Get parameter value")
                print("  set <ep> <path> <value>     - Set parameter value")
                print("  add <ep> <obj_path>         - Add object instance")
                print("  delete <ep> <obj_path>      - Delete object instance")
                print("  discover (disc) <ep> [obj]  - Get supported data model")
                print("  operate <ep> <cmd> [k=v...] - Execute command")
                print("\nDebug Levels:")
                print("  0 - Agent Only: Only agent response data (default)")
                print("  1 - Both Payloads: Controller + Agent USP messages")
                print("  2 - Full Details: STOMP headers + payloads")
                print("\nAdvanced:")
                print("  send <dest> <msg>           - Send raw message")
                print("\nCommand Aliases:")
                print("  ls=list, h=help, q=quit, disc=discover, gsdm=get_supported")
                print("\nExamples:")
                print("  debug 1                     - See both USP messages")
                print("  get proto::agent-001 Device.DeviceInfo.")
                print("  set proto::agent-001 Device.X_Test.Value 123")
                print("  disc proto::agent-001       - Discover data model")
                print("  operate proto::agent-001 Device.Reboot() Cause=Upgrade")
                print("="*60 + "\n")
                
            elif cmd == 'debug':
                global DEBUG_LEVEL
                if len(parts) < 2:
                    level_names = ["Agent Only", "Both Payloads", "Full Details"]
                    print(f"Current debug level: {DEBUG_LEVEL} ({level_names[DEBUG_LEVEL]})")
                    print("Usage: debug <0|1|2>")
                    print("  0 - Agent Only: Only agent response data")
                    print("  1 - Both Payloads: Controller + Agent USP messages")
                    print("  2 - Full Details: STOMP headers + payloads")
                else:
                    try:
                        new_level = int(parts[1])
                        if 0 <= new_level <= 2:
                            DEBUG_LEVEL = new_level
                            level_names = ["Agent Only", "Both Payloads", "Full Details"]
                            print(f"[✓] Debug level set to {DEBUG_LEVEL} ({level_names[DEBUG_LEVEL]})")
                        else:
                            print("[!] Debug level must be 0-2")
                    except ValueError:
                        print("[!] Invalid debug level. Use 0, 1, or 2")
                
            elif cmd == 'list':
                print(f"\nKnown Devices ({len(stomp_mgr.devices)}):")
                for ep, info in stomp_mgr.devices.items():
                    print(f"  - {ep}")
                    print(f"    Reply-To: {info['reply_to']}")
                    print(f"    Last seen: {info['last_seen']}")
                print("")
                
            elif cmd == 'status':
                level_names = ["Quiet", "Normal", "Verbose", "Full"]
                print(f"Connected: {stomp_mgr.connected}")
                print(f"Broker: {BROKER_HOST}:{BROKER_PORT}")
                print(f"Controller ID: {CONTROLLER_ENDPOINT_ID}")
                print(f"Known devices: {len(stomp_mgr.devices)}")
                print(f"Debug level: {DEBUG_LEVEL} ({level_names[DEBUG_LEVEL]})")
                
            elif cmd == 'get':
                if len(parts) < 3:
                    print("Usage: get <endpoint_id> <path>")
                    continue
                ep = parts[1]
                path = parts[2]
                Logger.usp_message("send", ep, "GET", {"path": path})
                helper.send_get(ep, path)
                
            elif cmd == 'set':
                if len(parts) < 4:
                    print("Usage: set <endpoint_id> <path> <value>")
                    continue
                ep = parts[1]
                path = parts[2]
                value = " ".join(parts[3:])
                Logger.usp_message("send", ep, "SET", {"path": path, "value": value})
                helper.send_set(ep, path, value)
            
            elif cmd == 'add':
                if len(parts) < 3:
                    print("Usage: add <endpoint_id> <obj_path>")
                    continue
                ep = parts[1]
                obj_path = parts[2]
                Logger.usp_message("send", ep, "ADD", {"obj_path": obj_path})
                helper.send_add(ep, obj_path)
            
            elif cmd == 'delete':
                if len(parts) < 3:
                    print("Usage: delete <endpoint_id> <obj_path>")
                    continue
                ep = parts[1]
                obj_path = parts[2]
                Logger.usp_message("send", ep, "DELETE", {"obj_path": obj_path})
                helper.send_delete(ep, obj_path)
            
            elif cmd == 'get_supported' or cmd == 'discover':
                if len(parts) < 2:
                    print("Usage: discover <endpoint_id> [obj_path]")
                    continue
                ep = parts[1]
                obj_path = parts[2] if len(parts) >= 3 else "Device."
                Logger.usp_message("send", ep, "GetSupportedDM", {"obj_path": obj_path})
                helper.send_discover(ep, obj_path)
            
            elif cmd == 'operate':
                if len(parts) < 3:
                    print("Usage: operate <endpoint_id> <command> [key=value ...]")
                    continue
                ep = parts[1]
                command_path = parts[2]
                args_dict = {}
                for arg in parts[3:]:
                    if '=' in arg:
                        k, v = arg.split('=', 1)
                        args_dict[k] = v
                Logger.usp_message("send", ep, "OPERATE", {"command": command_path}, level=1)
                helper.send_operate(ep, command_path, args_dict)
                
            elif cmd == 'send':
                # Raw send
                if len(parts) < 3:
                    print("Usage: send <dest> <msg>")
                    continue
                dest = parts[1]
                body = " ".join(parts[2:]).encode('utf-8')
                stomp_mgr.send(dest, body, content_type="text/plain", reply_to=REPLY_TO_QUEUE)
                print(f"[→] Sent to {dest}")
                
            else:
                print(f"Unknown command: {cmd}. Type 'help' for available commands.")
                
        except KeyboardInterrupt:
            print("\n[!] Use 'quit' or 'exit' to leave the program.")
            continue
        except EOFError:
            print("\n[*] EOF detected, exiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="USP Controller")
    parser.add_argument('--daemon', action='store_true', help='Run in headless daemon mode with IPC')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--force', action='store_true', help='Force kill old daemon if running')
    args = parser.parse_args()
    
    global DEBUG_MODE
    DEBUG_MODE = args.debug
    
    # Check for old daemon in daemon mode
    if args.daemon:
        if not check_and_kill_old_daemon(force=args.force):
            sys.exit(1)
    
    # Init STOMP
    stomp_mgr = STOMPManager()
    if not stomp_mgr.connect():
        sys.exit(1)
    
    # Start IPC Server only in daemon mode
    ipc_server = None
    if args.daemon:
        # Write PID file
        write_pid_file()
        atexit.register(remove_pid_file)
        
        ipc_server = IPCServer(stomp_mgr)
        ipc_server.start()
        time.sleep(0.2)  # Give IPC server time to start
        
        print(f"[✓] Daemon Started (PID: {os.getpid()})")
        print(f"[✓] IPC listening on {IPC_HOST}:{IPC_PORT}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping daemon...")
            remove_pid_file()
    else:
        print("\n[Mode] Interactive Shell")
        print(f"[*] To use with AI tools, start daemon with: ./usp_controller.py --daemon")
        interactive_mode(stomp_mgr)
        
    stomp_mgr.running = False
    if ipc_server:
        ipc_server.running = False
    if stomp_mgr.sock: stomp_mgr.sock.close()

if __name__ == "__main__":
    main()
