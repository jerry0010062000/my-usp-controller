#!/usr/bin/env python3
"""
Dual-Mode USP/STOMP Controller
Mode 1: Interactive Shell (User)
Mode 2: Background Daemon with IPC (Automation)
"""

__version__ = "2.0.1"
__author__ = "Jerry Bai"

import socket
import threading
import time
import sys
import os
import uuid
import json
import select
from datetime import datetime
import argparse
import platform
import atexit

# mDNS Service Discovery (optional)
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo
    MDNS_AVAILABLE = True
except ImportError:
    MDNS_AVAILABLE = False
    # Create dummy classes to avoid NameError
    ServiceListener = object
    print("[*] zeroconf not installed - mDNS discovery disabled")
    print("    Install with: pip install zeroconf")

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
    
    # atexit imported globally now
    atexit.register(readline.write_history_file, histfile)
except ImportError:
    pass

# --- Load Configuration from config.json ---
def load_config(config_file='config.json'):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"[!] Config file '{config_file}' not found. Using defaults.")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing config file: {e}")
        return None

def save_config(config, config_file='config.json'):
    """Save configuration to JSON file"""
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"[!] Error saving config file: {e}")
        return False

# Configuration defaults (only for optional settings)
DEFAULT_CONFIG = {
    'broker_host': '127.0.0.1',
    'broker_port': 61613,
    'username': 'guest',
    'password': 'guest',
    'devices_file': 'devices.json',
    'ipc_host': '127.0.0.1',
    'ipc_port': 6001,
    'debug_level': 0,
    'auto_subscribe_wildcard': True
}

def validate_config(config):
    """Validate required configuration fields"""
    if not config:
        print("[!] Error: config.json not found or invalid")
        print("[!] Please create config.json from config.example.json")
        return False
    
    if 'usp_controller' not in config:
        print("[!] Error: 'usp_controller' section missing in config.json")
        return False
    
    usp_config = config['usp_controller']
    required = ['controller_endpoint_id', 'receive_topic']
    
    for field in required:
        if field not in usp_config:
            print(f"[!] Error: Required field '{field}' missing in config.json")
            print(f"[!] Please check config.example.json for reference")
            return False
    
    return True

# Load configuration
CONFIG = load_config()

if not validate_config(CONFIG):
    print("\n[!] Configuration validation failed. Exiting.")
    sys.exit(1)

# Apply configuration with defaults for optional fields
usp_config = CONFIG['usp_controller']
BROKER_HOST = usp_config.get('broker_host', DEFAULT_CONFIG['broker_host'])
BROKER_PORT = usp_config.get('broker_port', DEFAULT_CONFIG['broker_port'])
USERNAME = usp_config.get('username', DEFAULT_CONFIG['username'])
PASSWORD = usp_config.get('password', DEFAULT_CONFIG['password'])
CONTROLLER_ENDPOINT_ID = usp_config['controller_endpoint_id']  # Required
RECEIVE_TOPIC = usp_config['receive_topic']  # Required
DEVICES_FILE = usp_config.get('devices_file', DEFAULT_CONFIG['devices_file'])

# Derived configuration
REPLY_TO_QUEUE = usp_config.get('reply_to_queue', f'/queue/{CONTROLLER_ENDPOINT_ID}')

# IPC Configuration
ipc_config = CONFIG.get('ipc', {})
IPC_HOST = ipc_config.get('host', DEFAULT_CONFIG['ipc_host'])
IPC_PORT = ipc_config.get('port', DEFAULT_CONFIG['ipc_port'])

# Advanced options
AUTO_SUBSCRIBE_WILDCARD = usp_config.get('auto_subscribe_wildcard', DEFAULT_CONFIG['auto_subscribe_wildcard'])
ENABLE_MDNS_DISCOVERY = usp_config.get('enable_mdns_discovery', True)  # Enable by default

# System-specific configuration
import platform
if platform.system() == 'Windows':
    PID_FILE = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'usp_controller.pid')
else:
    PID_FILE = '/tmp/usp_controller.pid'

# Device online status timeout (seconds)
DEVICE_TIMEOUT = 300  # 5 minutes - device considered offline if no message for this duration

# Debug Levels (can be overridden by config or command line)
DEBUG_LEVEL = 2  # Default: Full Details for better troubleshooting
"""
Debug Levels:
  0 - Agent Only: Only show agent response data (DM values)
  1 - Both Payloads: Show controller requests + agent responses (USP messages)
  2 - Full Details: Show complete STOMP headers + payloads (Default)
"""

def set_debug_level(level):
    """Set debug level at runtime"""
    global DEBUG_LEVEL
    if 0 <= level <= 2:
        DEBUG_LEVEL = level
        return True
    return False

class Logger:
    """Centralized logging with debug levels and memory buffer for IPC"""
    HISTORY_SIZE = 5000
    history = []  # List of dict
    log_counter = 0
    lock = threading.Lock()

    @classmethod
    def _add_history(cls, type_str, msg):
        with cls.lock:
            ts = datetime.now().strftime("%H:%M:%S")
            entry = {
                'id': cls.log_counter,
                'time': ts, 
                'type': type_str, 
                'msg': str(msg)
            }
            cls.log_counter += 1
            cls.history.append(entry)
            if len(cls.history) > cls.HISTORY_SIZE:
                cls.history.pop(0)

    @staticmethod
    def critical(msg):
        """Always show critical messages"""
        print(f"[!] {msg}")
        Logger._add_history("critical", msg)
    
    @staticmethod
    def info(msg, level=1):
        """Show info messages based on debug level"""
        if DEBUG_LEVEL >= level:
            print(f"[*] {msg}")
            Logger._add_history("info", msg)
    
    @staticmethod
    def success(msg, level=1):
        """Show success messages"""
        if DEBUG_LEVEL >= level:
            print(f"[✓] {msg}")
            Logger._add_history("success", msg)
    
    @staticmethod
    def data(msg, level=0):
        """Show response data (level 0+)"""
        if DEBUG_LEVEL >= level:
            print(msg)
            Logger._add_history("data", msg)

    
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
        log_msg = f"{arrow} USP {msg_type} {arrow} {endpoint}"
        print(log_msg)
        Logger._add_history("usp", log_msg)
        
        if DEBUG_LEVEL >= 2 and details:
            for key, value in details.items():
                print(f"    {key}: {value}")
                Logger._add_history("detail", f"    {key}: {value}")

DEBUG_MODE = False  # Legacy, kept for compatibility

def check_and_kill_old_daemon(force=False):
    """Check if old daemon is running and kill it (Windows-compatible)"""
    if not os.path.exists(PID_FILE):
        return True
    
    try:
        with open(PID_FILE, 'r') as f:
            old_pid = int(f.read().strip())
        
        # Check if process exists (Windows-compatible method)
        if platform.system() == 'Windows':
            import subprocess
            try:
                # Use tasklist to check if PID exists
                result = subprocess.run(['tasklist', '/FI', f'PID eq {old_pid}'], 
                                       capture_output=True, text=True, timeout=2)
                process_exists = str(old_pid) in result.stdout
            except:
                # Fallback: assume stale PID file
                process_exists = False
                
            if process_exists:
                if force:
                    print(f"[*] Found old daemon (PID {old_pid}), terminating...")
                    try:
                        subprocess.run(['taskkill', '/F', '/PID', str(old_pid)], 
                                      capture_output=True, timeout=5)
                        time.sleep(0.5)
                        print(f"[✓] Old daemon terminated")
                    except Exception as e:
                        print(f"[!] Failed to kill process: {e}")
                        return False
                    return True
                else:
                    print(f"[!] Daemon already running (PID {old_pid})")
                    print(f"    Use --force to terminate old daemon and start new one")
                    return False
            else:
                # Process doesn't exist, remove stale PID file
                os.remove(PID_FILE)
                return True
        else:
            # Unix/Linux: use os.kill with signal 0
            import signal
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

class USPAgentListener(ServiceListener):
    """mDNS Service Listener for USP Agent discovery"""
    
    def __init__(self, stomp_manager):
        self.stomp = stomp_manager
    
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when a new USP agent is discovered"""
        info = zc.get_service_info(type_, name)
        if info:
            self._process_agent(info, "discovered")
    
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when an agent updates its information"""
        info = zc.get_service_info(type_, name)
        if info:
            self._process_agent(info, "updated")
    
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Called when an agent disappears"""
        Logger.info(f"mDNS: Agent removed - {name}", level=1)
    
    def _process_agent(self, info: ServiceInfo, action: str):
        """Extract USP agent information from mDNS record"""
        try:
            # Parse TXT records
            props = {}
            for key, value in info.properties.items():
                try:
                    props[key.decode('utf-8')] = value.decode('utf-8')
                except:
                    props[key.decode('utf-8')] = value
            
            endpoint_id = props.get('endpoint', props.get('id', 'unknown'))
            path = props.get('path', '/usp')
            
            # Get address
            if info.addresses:
                addr = '.'.join(str(b) for b in info.addresses[0])
                port = info.port
                
                Logger.info(f"mDNS: Agent {action} - {endpoint_id}", level=0)
                Logger.info(f"  Address: {addr}:{port}", level=1)
                Logger.info(f"  Path: {path}", level=1)
                Logger.info(f"  Service: {info.name}", level=1)
                
                # Build destination queue/topic based on protocol
                # Typically: /queue/usp.agent.<endpoint_suffix>
                if endpoint_id != 'unknown':
                    suffix = endpoint_id.split('::')[-1] if '::' in endpoint_id else endpoint_id
                    reply_to = f"/queue/usp.agent.{suffix}"
                    
                    # Auto-register device
                    with self.stomp.lock:
                        if endpoint_id not in self.stomp.devices:
                            self.stomp.devices[endpoint_id] = {
                                'reply_to': reply_to,
                                'last_seen': datetime.now().isoformat(),
                                'discovered_via': 'mdns',
                                'address': f"{addr}:{port}",
                                'path': path
                            }
                            self.stomp.save_devices()
                            Logger.success(f"Auto-registered device via mDNS: {endpoint_id}", level=0)
                
        except Exception as e:
            Logger.critical(f"mDNS: Error processing agent info - {e}")

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
        
        # mDNS Service Discovery
        self.mdns_zeroconf = None
        self.mdns_browser = None
    
    def get_device_status(self, endpoint_id):
        """Check if device is online based on last_seen timestamp"""
        if endpoint_id not in self.devices:
            return "unknown"
        
        device_info = self.devices[endpoint_id]
        last_seen_str = device_info.get('last_seen')
        
        if not last_seen_str:
            return "unknown"
        
        try:
            from datetime import datetime
            last_seen = datetime.fromisoformat(last_seen_str)
            now = datetime.now()
            elapsed = (now - last_seen).total_seconds()
            
            if elapsed < DEVICE_TIMEOUT:
                return "online"
            else:
                return "offline"
        except:
            return "unknown"
        
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
    
    def start_mdns_discovery(self):
        """Start mDNS service discovery for USP agents"""
        if not MDNS_AVAILABLE:
            Logger.info("mDNS discovery not available (zeroconf not installed)", level=0)
            return False
        
        if not ENABLE_MDNS_DISCOVERY:
            Logger.info("mDNS discovery disabled in config", level=1)
            return False
        
        try:
            self.mdns_zeroconf = Zeroconf()
            listener = USPAgentListener(self)
            
            # Browse for USP agents
            # Standard service types: _usp-agent._tcp.local.
            self.mdns_browser = ServiceBrowser(
                self.mdns_zeroconf, 
                "_usp-agent._tcp.local.",
                listener
            )
            
            Logger.success("mDNS discovery started - listening for USP agents", level=0)
            return True
            
        except Exception as e:
            Logger.critical(f"Failed to start mDNS discovery: {e}")
            return False
    
    def stop_mdns_discovery(self):
        """Stop mDNS service discovery"""
        if self.mdns_zeroconf:
            try:
                self.mdns_zeroconf.close()
                Logger.info("mDNS discovery stopped", level=1)
            except:
                pass
    
    def mdns_scan_now(self, timeout=3.0):
        """Actively scan for USP agents on the network"""
        if not MDNS_AVAILABLE:
            Logger.critical("mDNS not available - install zeroconf")
            return {"status": "error", "msg": "zeroconf not installed", "agents": []}
        
        Logger.info(f"Starting active mDNS scan (timeout: {timeout}s)...", level=0)
        discovered = []
        
        try:
            # Use a temporary Zeroconf instance for scanning
            scan_zc = Zeroconf()
            
            # Create a collector listener
            class ScanListener(ServiceListener):
                def __init__(self):
                    self.found = []
                
                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        self.found.append(info)
                
                def update_service(self, zc, type_, name):
                    pass
                
                def remove_service(self, zc, type_, name):
                    pass
            
            listener = ScanListener()
            browser = ServiceBrowser(scan_zc, "_usp-agent._tcp.local.", listener)
            
            # Wait for discovery
            time.sleep(timeout)
            
            # Process found services
            for info in listener.found:
                try:
                    props = {}
                    for key, value in info.properties.items():
                        try:
                            props[key.decode('utf-8')] = value.decode('utf-8')
                        except:
                            props[key.decode('utf-8')] = value
                    
                    endpoint_id = props.get('endpoint', props.get('id', 'unknown'))
                    path = props.get('path', '/usp')
                    
                    if info.addresses:
                        addr = '.'.join(str(b) for b in info.addresses[0])
                        port = info.port
                        
                        agent_info = {
                            'endpoint_id': endpoint_id,
                            'address': f"{addr}:{port}",
                            'host': addr,
                            'port': port,
                            'path': path,
                            'service_name': info.name,
                            'properties': props
                        }
                        discovered.append(agent_info)
                        
                        Logger.success(f"Found agent: {endpoint_id} at {addr}:{port}", level=0)
                        
                        # Auto-register if not already known
                        if endpoint_id != 'unknown':
                            suffix = endpoint_id.split('::')[-1] if '::' in endpoint_id else endpoint_id
                            reply_to = f"/queue/usp.agent.{suffix}"
                            
                            with self.lock:
                                if endpoint_id not in self.devices:
                                    self.devices[endpoint_id] = {
                                        'reply_to': reply_to,
                                        'last_seen': datetime.now().isoformat(),
                                        'discovered_via': 'mdns_scan',
                                        'address': f"{addr}:{port}",
                                        'path': path
                                    }
                                    self.save_devices()
                                    Logger.success(f"Auto-registered: {endpoint_id}", level=0)
                
                except Exception as e:
                    Logger.critical(f"Error processing scan result: {e}")
            
            # Cleanup
            scan_zc.close()
            
            Logger.info(f"Scan complete - found {len(discovered)} agent(s)", level=0)
            return {"status": "ok", "count": len(discovered), "agents": discovered}
            
        except Exception as e:
            Logger.critical(f"mDNS scan failed: {e}")
            return {"status": "error", "msg": str(e), "agents": []}

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
                
                # Controller 只訂閱自己的接收佇列
                self.subscribe(RECEIVE_TOPIC)
                Logger.info(f"Subscribed to: {RECEIVE_TOPIC}", level=1)
                
                # 如果 reply_to_queue 不同，也訂閱
                if RECEIVE_TOPIC != REPLY_TO_QUEUE:
                    self.subscribe(REPLY_TO_QUEUE)
                    Logger.info(f"Subscribed to: {REPLY_TO_QUEUE}", level=1)
                
                # 載入已知設備（只記錄 reply_to，不訂閱）
                self.load_devices()
                if self.devices:
                    Logger.info(f"Loaded {len(self.devices)} known devices (reply addresses stored)", level=1)
                
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
        """
        處理收到的 STOMP 訊息
        
        處理流程:
        1. 提取 reply-to 地址 (用於回覆)
        2. 從 USP Record 提取 sender endpoint ID
        3. 解析 USP 訊息內容
        4. 根據訊息類型分發處理 (Response/Request/Error)
        5. 註冊/更新設備資訊到 devices.json
        6. 通知 callback (IPC, UI)
        """
        
        # ==================== Step 1: 提取回覆地址 ====================
        # reply-to-dest 是 agent 告訴我們的回覆目的地，直接使用即可
        reply_to = headers.get('reply-to-dest')
        sender = None  # endpoint ID，需從 USP Record.from_id 獲取
        
        # Debug: 顯示收到的訊息基本資訊
        Logger.info(f"Incoming message from destination: {headers.get('destination', 'unknown')}", level=1)
        if reply_to:
            Logger.info(f"  reply-to address: {reply_to}", level=1)
        else:
            Logger.critical(f"  ⚠ No reply-to-dest header! Cannot reply to this agent.")
        
        # ==================== Step 2: 解析 USP Record 獲取 endpoint ID ====================
        # 如果是 USP 訊息，從 protobuf 中提取 from_id 和訊息內容
        if 'application/vnd.bbf.usp.msg' in headers.get('content-type', ''):
            try:
                # 解析 USP Record（外層封裝）
                rec = record_pb2.Record()
                rec.ParseFromString(body)
                
                # 從 USP Record 獲取 sender endpoint ID（標準做法）
                sender = rec.from_id
                Logger.info(f"  Endpoint ID (from_id): {sender}", level=1)
                Logger.info(f"  Target (to_id): {rec.to_id}", level=2)
                
                # ==================== Step 3: 解析 USP Message（內層訊息）====================
                # USP Record 可能使用 no_session_context 或 session_context
                payload = None
                
                if rec.HasField('no_session_context'):
                    # 無會話上下文（最常見）
                    payload = rec.no_session_context.payload
                    Logger.info(f"  ✓ Found no_session_context", level=2)
                    
                elif rec.HasField('session_context'):
                    # 有會話上下文
                    payload = rec.session_context.payload
                    Logger.info(f"  ✓ Found session_context (session_id: {rec.session_context.session_id})", level=1)
                    
                else:
                    # 可能是連接/斷線訊息 - 顯示詳細內容
                    Logger.info(f"  ⚠ No payload context found in USP record", level=1)
                    
                    if rec.HasField('websocket_connect'):
                        Logger.info(f"    → WebSocket Connect message", level=0)
                        
                    elif rec.HasField('mqtt_connect'):
                        Logger.info(f"    → MQTT Connect message", level=0)
                        mqtt = rec.mqtt_connect
                        Logger.info(f"       Version: {mqtt.version}", level=0)
                        Logger.info(f"       Subscribed Topic: {mqtt.subscribed_topic}", level=0)
                        
                    elif rec.HasField('stomp_connect'):
                        Logger.info(f"    → STOMP Connect message", level=0)
                        stomp = rec.stomp_connect
                        Logger.info(f"       Version: {stomp.version}", level=0)
                        Logger.info(f"       Subscribed Destination: {stomp.subscribed_destination}", level=0)
                        if DEBUG_LEVEL >= 2:
                            Logger.info(f"       Full STOMP Connect data: {stomp}", level=2)
                        
                    elif rec.HasField('disconnect'):
                        Logger.info(f"    → Disconnect message", level=0)
                        disc = rec.disconnect
                        Logger.info(f"       Reason: {disc.reason if disc.reason else 'Normal disconnect'}", level=0)
                        Logger.info(f"       Reason Code: {disc.reason_code}", level=0)
                        
                    elif rec.HasField('uds_connect'):
                        Logger.info(f"    → UDS Connect message", level=0)
                        
                    else:
                        Logger.critical(f"    ❌ Unknown record type!")
                        if DEBUG_LEVEL >= 2:
                            Logger.critical(f"       Record fields: {rec.ListFields()}")
                
                # 如果有 payload，解析 USP 訊息
                if payload:
                    # 解析實際的 USP 訊息
                    msg = msg_pb2.Msg()
                    msg.ParseFromString(payload)
                    mtype = msg_pb2.Header.MsgType.Name(msg.header.msg_type)
                    
                    # 記錄收到的 USP 訊息類型
                    details = {"msg_id": msg.header.msg_id} if DEBUG_LEVEL >= 2 else None
                    Logger.usp_message("recv", sender, mtype, details)
                    
                    # ==================== Step 5: 根據訊息類型分發處理 ====================
                    if msg.body.HasField('response'):
                        # Response: agent 回覆 controller 的查詢（GET_RESP, SET_RESP 等）
                        self._handle_usp_response(sender, msg)
                        
                    elif msg.body.HasField('request'):
                        # Request: agent 主動發送請求給 controller（通常是 NOTIFY）
                        Logger.info(f"Received USP Request from {sender}", level=0)
                        self._handle_usp_request(sender, msg)
                        
                    elif msg.body.HasField('error'):
                        # Error: agent 回報錯誤
                        Logger.critical(f"USP Error from {sender}: {msg.body.error.err_msg}")
                        
            except Exception as e:
                # ==================== 解析失敗處理 ====================
                import traceback
                Logger.critical(f"❌ USP parsing error: {e}")
                Logger.critical(f"  Headers: {headers}")
                Logger.critical(f"  Body length: {len(body)} bytes")
                if DEBUG_LEVEL >= 1:
                    Logger.critical(f"  Body hex (first 100 bytes): {body[:100].hex()}...")
                if DEBUG_LEVEL >= 2:
                    Logger.critical(f"Traceback: {traceback.format_exc()}")
        else:
            # ==================== 非 USP 訊息 ====================
            content_type = headers.get('content-type', 'unknown')
            Logger.info(f"  ℹ Non-USP message, content-type: {content_type}", level=1)
            Logger.info(f"  Body preview: {body[:200]}", level=2)
        
        # ==================== Step 5: 註冊/更新設備資訊 ====================
        # 只有同時有 sender 和 reply_to 才能註冊設備
        if sender and reply_to:
            with self.lock:
                is_new_device = sender not in self.devices
                
                if is_new_device:
                    Logger.success(f"✓ Discovered new device: {sender}", level=0)
                    Logger.info(f"  Reply address stored: {reply_to}", level=1)
                else:
                    Logger.info(f"  ↻ Updated existing device: {sender}", level=1)
                
                # 儲存設備資訊（endpoint_id -> reply_to 的映射）
                self.devices[sender] = {
                    'reply_to': reply_to,
                    'last_seen': datetime.now().isoformat()
                }
                self.last_active_device = sender
                
                # 持久化到 devices.json
                self.save_devices()
                
        elif sender:
            # 有 sender 但沒有 reply_to：agent 沒告訴我們回覆地址
            Logger.critical(f"⚠ Endpoint ID identified ({sender}) but no reply-to-dest header!")
            Logger.critical(f"    Cannot reply to this agent - missing reply address")
            
        elif reply_to:
            # 有 reply_to 但沒有 sender：無法識別是哪個設備（USP 解析失敗？）
            Logger.critical(f"⚠ Reply address provided ({reply_to}) but endpoint ID unknown!")
            Logger.critical(f"    Check if USP record parsing failed or non-USP message")
            
        else:
            # 兩者都沒有：無法處理的訊息
            Logger.info(f"  ℹ No endpoint ID or reply address, message not stored", level=1)
        
        # ==================== Step 6: 通知 callbacks ====================
        # 將訊息轉發給所有註冊的 callback（例如 IPC Server）
        for cb in self.msg_callbacks:
            cb(headers, body, sender)
    
    def _handle_usp_response(self, sender, msg):
        """Handle and display USP response messages"""
        resp = msg.body.response
        
        if resp.HasField('get_resp'):
            total_params = 0
            Logger.data(f"  === GET Response Start ===")
            for r in resp.get_resp.req_path_results:
                status = '✓' if r.err_code == 0 else '✗'
                Logger.data(f"  Path: {r.requested_path} ({status})")
                for res in r.resolved_path_results:
                    Logger.data(f"    {res.resolved_path}")
                    for p, v in res.result_params.items():
                        Logger.data(f"      {p} = {v}")
                        total_params += 1
            Logger.data(f"  === Total: {total_params} parameters ===")
                    
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
    
    def _handle_usp_request(self, sender, msg):
        """Handle USP request from agent and send appropriate response"""
        req = msg.body.request
        msg_id = msg.header.msg_id
        
        # Determine request type for logging
        req_type = "UNKNOWN"
        if req.HasField('get'):
            req_type = "GET"
        elif req.HasField('set'):
            req_type = "SET"
        elif req.HasField('add'):
            req_type = "ADD"
        elif req.HasField('delete'):
            req_type = "DELETE"
        elif req.HasField('operate'):
            req_type = "OPERATE"
        elif req.HasField('get_supported_dm'):
            req_type = "GET_SUPPORTED_DM"
        elif req.HasField('get_instances'):
            req_type = "GET_INSTANCES"
        elif req.HasField('notify'):
            req_type = "NOTIFY"
            # Notify is special - it doesn't expect a response (unless send_resp is true)
            Logger.info(f"  Received NOTIFY from {sender}", level=0)
            
            # Extract and display notify details
            if DEBUG_LEVEL >= 1:
                Logger.data(f"    Subscription ID: {req.notify.subscription_id}")
                Logger.data(f"    Send Response: {req.notify.send_resp}")
                
                # Check notification type
                if req.notify.HasField('event'):
                    Logger.data(f"    Type: Event")
                    Logger.data(f"      Object Path: {req.notify.event.obj_path}")
                    Logger.data(f"      Event Name: {req.notify.event.event_name}")
                    if req.notify.event.params:
                        for key, val in req.notify.event.params.items():
                            Logger.data(f"      Param {key}: {val}")
                elif req.notify.HasField('value_change'):
                    Logger.data(f"    Type: ValueChange")
                    Logger.data(f"      Param Path: {req.notify.value_change.param_path}")
                    Logger.data(f"      Param Value: {req.notify.value_change.param_value}")
                elif req.notify.HasField('obj_creation'):
                    Logger.data(f"    Type: ObjectCreation")
                    Logger.data(f"      Object Path: {req.notify.obj_creation.obj_path}")
                elif req.notify.HasField('obj_deletion'):
                    Logger.data(f"    Type: ObjectDeletion")
                    Logger.data(f"      Object Path: {req.notify.obj_deletion.obj_path}")
                elif req.notify.HasField('oper_complete'):
                    Logger.data(f"    Type: OperationComplete")
                    Logger.data(f"      Command Name: {req.notify.oper_complete.command_name}")
                elif req.notify.HasField('on_board_req'):
                    Logger.data(f"    Type: OnBoardRequest")
            
            # If agent requests a response, send NotifyResp
            if req.notify.send_resp:
                Logger.info(f"  Sending NotifyResp to {sender}", level=1)
                resp_msg = msg_pb2.Msg()
                resp_msg.header.msg_id = str(uuid.uuid4())
                resp_msg.header.msg_type = msg_pb2.Header.MsgType.NOTIFY_RESP
                
                notify_resp = resp_msg.body.response.notify_resp
                notify_resp.subscription_id = req.notify.subscription_id
                
                self._send_usp_msg(sender, resp_msg)
            
            return  # Don't send error response for notify
        
        Logger.info(f"  Request type: {req_type} (not yet supported by controller)", level=1)
        
        # Create error response
        resp_msg = msg_pb2.Msg()
        resp_msg.header.msg_id = str(uuid.uuid4())
        resp_msg.header.msg_type = msg_pb2.Header.MsgType.ERROR
        
        error = resp_msg.body.error
        error.err_code = 7004  # Request denied
        error.err_msg = f"Controller does not process {req_type} requests from agents"
        
        # Send error response
        device = self.devices.get(sender)
        if device and 'reply_to' in device:
            # Wrap in USP Record
            usp_rec = record_pb2.Record()
            usp_rec.version = "1.4"
            usp_rec.to_id = sender
            usp_rec.from_id = CONTROLLER_ENDPOINT_ID
            usp_rec.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
            usp_rec.no_session_context.payload = resp_msg.SerializeToString()
            
            self.send(device['reply_to'], usp_rec.SerializeToString(), reply_to=REPLY_TO_QUEUE)
            Logger.info(f"  Sent error response to {sender}", level=1)
        else:
            Logger.critical(f"Cannot send response: device {sender} not registered")


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
                # Include online status for each device
                devices_with_status = {}
                for ep_id, info in self.stomp.devices.items():
                    device_data = info.copy()
                    device_data['status'] = self.stomp.get_device_status(ep_id)
                    devices_with_status[ep_id] = device_data
                
                response = {
                    "status": "ok",
                    "devices": devices_with_status
                }
            
            elif cmd == "remove_device":
                # remove_device <endpoint_id>
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    if endpoint in self.stomp.devices:
                        del self.stomp.devices[endpoint]
                        self.stomp.save_devices()
                        Logger.info(f"Device removed: {endpoint}", level=0)
                        response = {"status": "ok", "msg": f"Device '{endpoint}' removed"}
                    else:
                        response = {"status": "error", "msg": f"Device '{endpoint}' not found"}
                else:
                    response = {"status": "error", "msg": "usage: remove_device <endpoint_id>"}
            
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

            elif cmd == "get_config":
                # Returns current configuration and debug level
                response = {
                    "status": "ok",
                    "config": {
                        "broker_host": BROKER_HOST,
                        "broker_port": BROKER_PORT,
                        "controller_id": CONTROLLER_ENDPOINT_ID,
                        "receive_topic": RECEIVE_TOPIC,
                        "debug_level": DEBUG_LEVEL,
                        "username": USERNAME,
                        "ipc_port": IPC_PORT
                    }
                }
            
            elif cmd == "update_config":
                # update_config <field> <value>
                # Supports: broker_host, broker_port, controller_id, receive_topic, username, password
                if len(cmd_parts) >= 3:
                    field = cmd_parts[1]
                    value = " ".join(cmd_parts[2:])
                    
                    # Load current config
                    config = load_config()
                    if not config:
                        response = {"status": "error", "msg": "Failed to load config.json"}
                    else:
                        try:
                            # Update the appropriate field
                            if field == "broker_host":
                                config['usp_controller']['broker_host'] = value
                            elif field == "broker_port":
                                config['usp_controller']['broker_port'] = int(value)
                            elif field == "controller_id":
                                config['usp_controller']['controller_endpoint_id'] = value
                                # Also update receive_topic if not custom
                                if 'receive_topic' not in config['usp_controller'] or \
                                   config['usp_controller']['receive_topic'].endswith(CONTROLLER_ENDPOINT_ID.split('::')[-1]):
                                    config['usp_controller']['receive_topic'] = f'/queue/usp.controller.{value.split("::")[-1]}'
                            elif field == "receive_topic":
                                config['usp_controller']['receive_topic'] = value
                            elif field == "username":
                                config['usp_controller']['username'] = value
                            elif field == "password":
                                config['usp_controller']['password'] = value
                            elif field == "ipc_port":
                                if 'ipc' not in config:
                                    config['ipc'] = {}
                                config['ipc']['port'] = int(value)
                            else:
                                response = {"status": "error", "msg": f"Unknown field: {field}"}
                                client.sendall(json.dumps(response).encode('utf-8'))
                                client.close()
                                return
                            
                            # Save updated config
                            if save_config(config):
                                response = {"status": "ok", "msg": f"Config updated. Restart daemon to apply changes."}
                            else:
                                response = {"status": "error", "msg": "Failed to save config.json"}
                        except ValueError as e:
                            response = {"status": "error", "msg": f"Invalid value: {str(e)}"}
                        except Exception as e:
                            response = {"status": "error", "msg": f"Error: {str(e)}"}
                else:
                    response = {"status": "error", "msg": "usage: update_config <field> <value>"}
            
            elif cmd == "set_debug":
                # set_debug <level>
                if len(cmd_parts) >= 2:
                    try: 
                        level = int(cmd_parts[1])
                        if set_debug_level(level):
                            response = {"status": "ok", "msg": f"Debug level set to {level}"}
                        else:
                            response = {"status": "error", "msg": "Invalid debug level (0-2)"}
                    except ValueError:
                        response = {"status": "error", "msg": "Level must be an integer"}
                else:
                    response = {"status": "error", "msg": "usage: set_debug <level>"}
            
            elif cmd == "reconnect":
                # Attempt STOMP reconnection
                try:
                    if self.stomp.connected:
                        self.stomp.sock.close()
                        self.stomp.connected = False
                        time.sleep(1) # Wait for close
                    
                    if self.stomp.connect():
                        response = {"status": "ok", "msg": "Reconnected to STOMP Broker"}
                    else:
                        response = {"status": "error", "msg": "Reconnection failed (Check logs)"}
                except Exception as e:
                    response = {"status": "error", "msg": f"Reconnection error: {str(e)}"}
            
            elif cmd == "mdns_status":
                # Get mDNS discovery status
                if not MDNS_AVAILABLE:
                    response = {"status": "ok", "mdns_available": False, "mdns_running": False, "msg": "zeroconf not installed"}
                else:
                    running = self.stomp.mdns_zeroconf is not None
                    response = {"status": "ok", "mdns_available": True, "mdns_running": running, "enabled": ENABLE_MDNS_DISCOVERY}
            
            elif cmd == "mdns_start":
                # Start mDNS discovery
                if self.stomp.start_mdns_discovery():
                    response = {"status": "ok", "msg": "mDNS discovery started"}
                else:
                    response = {"status": "error", "msg": "Failed to start mDNS discovery"}
            
            elif cmd == "mdns_stop":
                # Stop mDNS discovery
                self.stomp.stop_mdns_discovery()
                response = {"status": "ok", "msg": "mDNS discovery stopped"}
            
            elif cmd == "mdns_scan":
                # Active mDNS scan
                # mdns_scan [timeout]
                timeout = 3.0
                if len(cmd_parts) >= 2:
                    try:
                        timeout = float(cmd_parts[1])
                    except:
                        pass
                
                result = self.stomp.mdns_scan_now(timeout)
                response = result

            elif cmd == "poll_logs":
                # poll_logs [last_id]
                last_id = -1

                if len(cmd_parts) >= 2:
                    try: last_id = int(cmd_parts[1])
                    except: pass
                
                with Logger.lock:
                    # Provide logs with id > last_id (limited to 200 per request)
                    new_logs = [log for log in Logger.history if log['id'] > last_id]
                    # Limit to prevent UI freeze
                    if len(new_logs) > 200:
                        new_logs = new_logs[:200]
                    response = {
                        "status": "ok", 
                        "logs": new_logs, 
                        "last_id": Logger.history[-1]['id'] if Logger.history else -1
                    }
            
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
        
        # Determine destination from device info (agent must have registered)
        device = self.stomp.devices.get(endpoint)
        if not device or 'reply_to' not in device:
            print(f"[!] Unknown device {endpoint}. Wait for agent to register first.")
            return False
        dest = device['reply_to']
        
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
            if not dev or 'reply_to' not in dev:
                print(f"[!] Unknown device {endpoint}. Wait for agent to register first.")
                return False
            dest = dev['reply_to']
            
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
    parser = argparse.ArgumentParser(
        description="USP STOMP Controller - Dual Mode (Interactive/Daemon)",
        epilog="Example: python usp_controller.py --daemon --debug 1"
    )
    parser.add_argument('--daemon', action='store_true', 
                       help='Run as background daemon with IPC')
    parser.add_argument('--debug', type=int, choices=[0, 1, 2], metavar='LEVEL',
                       help='Set debug level: 0=Agent Only, 1=Both Payloads, 2=Full Details')
    parser.add_argument('--force', action='store_true', 
                       help='Force kill old daemon before starting')
    parser.add_argument('--config', type=str, default='config.json', 
                       help='Config file path (default: config.json)')
    parser.add_argument('--endpoint-id', type=str, 
                       help='Override controller endpoint ID from config')
    parser.add_argument('--broker', type=str, 
                       help='Override broker address (format: host:port)')
    args = parser.parse_args()
    
    # Apply command line overrides
    global DEBUG_LEVEL, CONTROLLER_ENDPOINT_ID, BROKER_HOST, BROKER_PORT, REPLY_TO_QUEUE
    
    if args.debug is not None:
        DEBUG_LEVEL = args.debug
    
    # 顯示當前 debug level
    debug_names = ["Agent Only", "Both Payloads", "Full Details"]
    print(f"[*] Debug Level: {DEBUG_LEVEL} ({debug_names[DEBUG_LEVEL]})")
    
    if args.endpoint_id:
        CONTROLLER_ENDPOINT_ID = args.endpoint_id
        REPLY_TO_QUEUE = f'/queue/{CONTROLLER_ENDPOINT_ID}'
        print(f"[*] Controller Endpoint ID overridden: {CONTROLLER_ENDPOINT_ID}")
    
    if args.broker:
        if ':' in args.broker:
            host, port = args.broker.split(':', 1)
            BROKER_HOST = host
            BROKER_PORT = int(port)
        else:
            BROKER_HOST = args.broker
        print(f"[*] Broker overridden: {BROKER_HOST}:{BROKER_PORT}")
    
    # Check for old daemon in daemon mode
    if args.daemon:
        if not check_and_kill_old_daemon(force=args.force):
            sys.exit(1)
    
    # 顯示配置資訊
    print(f"[*] Controller: {CONTROLLER_ENDPOINT_ID}")
    print(f"[*] Broker: {BROKER_HOST}:{BROKER_PORT}")
    print(f"[*] Receive Topic: {RECEIVE_TOPIC}")
    
    # Init STOMP
    stomp_mgr = STOMPManager()
    if not stomp_mgr.connect():
        if args.daemon:
            print("[!] Warning: STOMP connection failed. Starting daemon anyway to allow IPC access.")
        else:
            print("[!] Critical: STOMP connection failed. Exiting.")
            sys.exit(1)
    
    # Start mDNS discovery if enabled
    if ENABLE_MDNS_DISCOVERY:
        stomp_mgr.start_mdns_discovery()
    
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
    stomp_mgr.stop_mdns_discovery()
    if ipc_server:
        ipc_server.running = False
    if stomp_mgr.sock: stomp_mgr.sock.close()

if __name__ == "__main__":
    main()
