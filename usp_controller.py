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

# IPC Configuration (For Gemini/Daemon communication)
IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

DEBUG_MODE = False

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
                print(f"[*] Loaded {len(self.devices)} devices from {DEVICES_FILE}")
                return True
        except Exception as e:
            print(f"[!] Failed to load devices: {e}")
        return False

    def save_devices(self):
        """Save known devices to file"""
        try:
            with open(DEVICES_FILE, 'w') as f:
                json.dump(self.devices, f, indent=2)
        except Exception as e:
            print(f"[!] Failed to save devices: {e}")

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
                print(f"[✓] Connected to STOMP Broker ({BROKER_HOST}:{BROKER_PORT})")
                
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
                        print(f"[*] Restoring subscription for {endpoint}: {info['reply_to']}")
                        self.subscribe(info['reply_to'])
                
                return True
            else:
                print(f"[!] Connection failed. Response: {response}")
                return False
                
        except Exception as e:
            print(f"[!] Connection error: {e}")
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
        if DEBUG_MODE: print(f"[DEBUG] Subscribed to {destination}")

    def send(self, destination, body_bytes, content_type='application/vnd.bbf.usp.msg', reply_to=None):
        if not self.connected: return False
        
        try:
            headers = [
                f"SEND",
                f"destination:{destination}",
                f"content-type:{content_type}",
                f"content-length:{len(body_bytes)}"
            ]
            if reply_to:
                headers.append(f"reply-to-dest:{reply_to}")
            
            frame = '\n'.join(headers).encode('utf-8') + b'\n\n' + body_bytes + b'\0'
            self.sock.sendall(frame)
            if DEBUG_MODE: print(f"[DEBUG] Sent {len(body_bytes)} bytes to {destination}")
            return True
        except Exception as e:
            print(f"[!] Send error: {e}")
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
            
            if command:
                if DEBUG_MODE: print(f"[DEBUG] Received STOMP {command} from {headers.get('destination', 'unknown')}")
            
            if command == "MESSAGE":
                self._handle_message(headers, body)
                
        except Exception as e:
            print(f"[!] Frame processing error: {e}")

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
                    print(f"\n[<<<<] USP {mtype} from {sender}")
                    
                    if msg.body.HasField('response'):
                        resp = msg.body.response
                        if resp.HasField('get_resp'):
                            for r in resp.get_resp.req_path_results:
                                print(f"  Path: {r.requested_path} ({'✓' if r.err_code==0 else '✗'})")
                                for res in r.resolved_path_results:
                                    print(f"    - {res.resolved_path}")
                                    for p, v in res.result_params.items():
                                        print(f"      {p} = {v}")
                        elif resp.HasField('error'):
                            print(f"  [!] Error {resp.error.err_code}: {resp.error.err_msg}")
            except Exception as e:
                print(f"[!] USP Parsing Error: {e}")
                print(f"    Body Length: {len(body)}")
                print(f"    Body Hex: {body.hex()}")

        if sender and sender != CONTROLLER_ENDPOINT_ID:
            with self.lock:
                is_new = sender not in self.devices
                
                # Preserve existing reply_to if not provided in new message
                existing_reply = self.devices.get(sender, {}).get('reply_to')
                new_reply = clean_reply if reply_to else (existing_reply if existing_reply else f"/queue/{sender}")

                self.devices[sender] = {
                    'endpoint_id': sender,
                    'last_seen': datetime.now().isoformat(),
                    'reply_to': new_reply,
                    'last_msg_len': len(body)
                }
                self.last_active_device = sender
                
                if is_new:
                    print(f"\n[+] New Device Discovered: {sender}")
                    print(f"    Reply Path: {self.devices[sender]['reply_to']}")
                    # Auto subscribe to reply path to receive messages from agent
                    self.subscribe(self.devices[sender]['reply_to'])
                
                # Save to disk
                self.save_devices()
        
        # 2. Notify callbacks (IPC, UI)
        for cb in self.msg_callbacks:
            cb(headers, body, sender)


class IPCServer(threading.Thread):
    """Local TCP Server for Gemini/External control"""
    
    def __init__(self, stomp_manager):
        super().__init__(daemon=True)
        self.stomp = stomp_manager
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = True
        
    def run(self):
        try:
            self.server_sock.bind((IPC_HOST, IPC_PORT))
            self.server_sock.listen(5)
            print(f"[*] IPC Server listening on {IPC_HOST}:{IPC_PORT}")
            
            while self.running:
                client, addr = self.server_sock.accept()
                self._handle_client(client)
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"[!] IPC Server port {IPC_PORT} already in use (daemon running?)")
            else:
                print(f"[!] IPC Server error: {e}")
        except Exception as e:
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
            
            elif cmd == "discover" or cmd == "getsupporteddm":
                # discover <endpoint> [obj_path]
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2] if len(cmd_parts) >= 3 else "Device."
                    success = self._send_usp_get_supported_dm(endpoint, obj_path)
                    response = {"status": "ok" if success else "failed", "msg": f"GetSupportedDM sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: discover <endpoint> [obj_path]"}
            
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
    
    while True:
        try:
            cmd_str = input("usp-cli> ").strip()
            if not cmd_str: continue
            
            parts = cmd_str.split()
            cmd = parts[0].lower()
            
            if cmd in ['exit', 'quit']:
                break
                
            elif cmd == 'help':
                print("\n" + "="*60)
                print("USP Controller - Available Commands")
                print("="*60)
                print("Basic:")
                print("  help                        - Show this help")
                print("  list                        - List known devices")
                print("  status                      - Show connection status")
                print("  exit/quit                   - Exit program")
                print("\nUSP Operations:")
                print("  get <ep> <path>             - Get parameter value")
                print("  set <ep> <path> <value>     - Set parameter value")
                print("  add <ep> <obj_path>         - Add object instance")
                print("  delete <ep> <obj_path>      - Delete object instance")
                print("  discover <ep> [obj_path]    - Get supported data model")
                print("  operate <ep> <cmd> [k=v...] - Execute command")
                print("\nAdvanced:")
                print("  send <dest> <msg>           - Send raw message")
                print("\nExamples:")
                print("  get proto::agent-001 Device.DeviceInfo.")
                print("  set proto::agent-001 Device.X_Test.Value 123")
                print("  discover proto::agent-001")
                print("  operate proto::agent-001 Device.Reboot() Cause=Upgrade")
                print("="*60 + "\n")
                
            elif cmd == 'list':
                print(f"\nKnown Devices ({len(stomp_mgr.devices)}):")
                for ep, info in stomp_mgr.devices.items():
                    print(f"  - {ep}")
                    print(f"    Reply-To: {info['reply_to']}")
                    print(f"    Last seen: {info['last_seen']}")
                print("")
                
            elif cmd == 'status':
                print(f"Connected: {stomp_mgr.connected}")
                print(f"Broker: {BROKER_HOST}:{BROKER_PORT}")
                print(f"Controller ID: {CONTROLLER_ENDPOINT_ID}")
                print(f"Known devices: {len(stomp_mgr.devices)}")
                
            elif cmd == 'get':
                if len(parts) < 3:
                    print("Usage: get <endpoint_id> <path>")
                    continue
                ep = parts[1]
                path = parts[2]
                print(f"[→] Sending GET to {ep}...")
                helper.send_get(ep, path)
                
            elif cmd == 'set':
                if len(parts) < 4:
                    print("Usage: set <endpoint_id> <path> <value>")
                    continue
                ep = parts[1]
                path = parts[2]
                value = " ".join(parts[3:])
                print(f"[→] Sending SET to {ep}: {path} = {value}")
                helper.send_set(ep, path, value)
            
            elif cmd == 'add':
                if len(parts) < 3:
                    print("Usage: add <endpoint_id> <obj_path>")
                    continue
                ep = parts[1]
                obj_path = parts[2]
                print(f"[→] Sending ADD to {ep}: {obj_path}")
                helper.send_add(ep, obj_path)
            
            elif cmd == 'delete':
                if len(parts) < 3:
                    print("Usage: delete <endpoint_id> <obj_path>")
                    continue
                ep = parts[1]
                obj_path = parts[2]
                print(f"[→] Sending DELETE to {ep}: {obj_path}")
                helper.send_delete(ep, obj_path)
            
            elif cmd == 'discover':
                if len(parts) < 2:
                    print("Usage: discover <endpoint_id> [obj_path]")
                    continue
                ep = parts[1]
                obj_path = parts[2] if len(parts) >= 3 else "Device."
                print(f"[→] Sending GetSupportedDM to {ep} for {obj_path}")
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
                print(f"[→] Sending OPERATE to {ep}: {command_path}")
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
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="USP Controller")
    parser.add_argument('--daemon', action='store_true', help='Run in headless daemon mode with IPC')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()
    
    global DEBUG_MODE
    DEBUG_MODE = args.debug
    
    # Init STOMP
    stomp_mgr = STOMPManager()
    if not stomp_mgr.connect():
        sys.exit(1)
    
    # Start IPC Server only in daemon mode
    ipc_server = None
    if args.daemon:
        ipc_server = IPCServer(stomp_mgr)
        ipc_server.start()
        time.sleep(0.1)  # Give IPC server time to start
        print(f"[Mode] Daemon Started. IPC listening on {IPC_HOST}:{IPC_PORT}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping daemon...")
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
