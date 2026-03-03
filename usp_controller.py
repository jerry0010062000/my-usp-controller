#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dual-Mode USP/STOMP Controller
Mode 1: Interactive Shell (User)
Mode 2: Background Daemon with IPC (Automation)
"""

__version__ = "2.0.4"
__author__ = "Jerry Bai"

import sys
import io

# Set UTF-8 encoding for stdout/stderr on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)

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
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"[!] Config file '{config_file}' not found. Using defaults.")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing config file: {e}")
        return None
    except UnicodeDecodeError as e:
        print(f"[!] Config file encoding error: {e}")
        print(f"[!] Please ensure config.json is saved in UTF-8 encoding.")
        return None

def save_config(config, config_file='config.json'):
    """Save configuration to JSON file"""
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
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
CONFIG_VALID = validate_config(CONFIG)

if not CONFIG_VALID:
    print("\n[!] Configuration validation failed.")
    print("[!] In daemon mode, IPC will still start to allow GUI access for configuration.")
    # Use fallback defaults to allow daemon to start
    usp_config = {}
    mini_broker_config = {}
else:
    # Apply configuration with defaults for optional fields
    usp_config = CONFIG['usp_controller']

# Initialize all variables with defaults (allows daemon to start even with invalid config)
BROKER_HOST = usp_config.get('broker_host', DEFAULT_CONFIG['broker_host'])
BROKER_PORT = usp_config.get('broker_port', DEFAULT_CONFIG['broker_port'])
USERNAME = usp_config.get('username', DEFAULT_CONFIG['username'])
PASSWORD = usp_config.get('password', DEFAULT_CONFIG['password'])
CONTROLLER_ENDPOINT_ID = usp_config.get('controller_endpoint_id', 'controller.default')
RECEIVE_TOPIC = usp_config.get('receive_topic', '/topic/agent')
DEVICES_FILE = usp_config.get('devices_file', DEFAULT_CONFIG['devices_file'])

# Mini-Broker configuration (overrides broker settings when enabled)
if CONFIG_VALID:
    mini_broker_config = CONFIG.get('mini_broker', {})
else:
    mini_broker_config = {}
    
MINI_BROKER_ENABLED = mini_broker_config.get('enable', False)

if MINI_BROKER_ENABLED:
    # When mini-broker is enabled, use its configuration and lock broker settings
    BROKER_HOST = mini_broker_config.get('host', '127.0.0.1')
    BROKER_PORT = mini_broker_config.get('port', 61613)
    print(f"[*] Mini-Broker enabled: {BROKER_HOST}:{BROKER_PORT}")
    print(f"[*] Broker configuration locked (cannot be overridden via command line)")

# Derived configuration
REPLY_TO_QUEUE = usp_config.get('reply_to_queue', f'/queue/{CONTROLLER_ENDPOINT_ID}')

# IPC Configuration
ipc_config = CONFIG.get('ipc', {})
IPC_HOST = ipc_config.get('host', DEFAULT_CONFIG['ipc_host'])
IPC_PORT = ipc_config.get('port', DEFAULT_CONFIG['ipc_port'])

# Advanced options
AUTO_SUBSCRIBE_WILDCARD = usp_config.get('auto_subscribe_wildcard', DEFAULT_CONFIG['auto_subscribe_wildcard'])
ENABLE_MDNS_DISCOVERY = usp_config.get('enable_mdns_discovery', True)  # Enable by default
HEARTBEAT_CHECK_ENABLED_CONFIG = usp_config.get('heartbeat_check_enabled', True)
HEARTBEAT_CHECK_INTERVAL_CONFIG = usp_config.get('heartbeat_check_interval', 60)

# System-specific configuration
import platform
if platform.system() == 'Windows':
    PID_FILE = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'usp_controller.pid')
else:
    PID_FILE = '/tmp/usp_controller.pid'

# Device online status timeout (seconds)
DEVICE_TIMEOUT = 300  # 5 minutes - device considered offline if no message for this duration

# Active heartbeat check settings - loaded from config
HEARTBEAT_CHECK_ENABLED = HEARTBEAT_CHECK_ENABLED_CONFIG
HEARTBEAT_CHECK_INTERVAL = HEARTBEAT_CHECK_INTERVAL_CONFIG
HEARTBEAT_CHECK_PATH = "Device.DeviceInfo.UpTime"  # Lightweight parameter to check

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
    def error(msg, level=0):
        """Show error messages based on debug level"""
        if DEBUG_LEVEL >= level:
            print(f"[✗] {msg}")
            Logger._add_history("error", msg)
    
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
        self.recv_thread = None
        self.heartbeat_thread = None
        self.last_heartbeat_sent = None
        self.heartbeat_interval = 30  # seconds
        self.heartbeat_check_thread = None
        self.pending_heartbeat_checks = {}  # {msg_id: {endpoint, timestamp}}
        self.pending_ipc_requests = {}  # {msg_id: {endpoint, command, result_queue, timestamp}}
        self.pending_requests = {}  # {(endpoint, command, path): msg_id} - track duplicate requests
        
        # Test data cache for SET testing (Test 1.4)
        self.writable_params_cache = {}  # {endpoint: {param_path: access_info}}
        self.param_values_cache = {}     # {endpoint: {param_path: value}}
        
        # mDNS Service Discovery
        self.mdns_zeroconf = None
        self.mdns_browser = None
    
    def _match_param_to_template(self, instance_path, template_paths):
        """Match instance path to template path with {i} placeholders
        
        Args:
            instance_path: Actual path like 'Device.IP.Interface.1.Enable'
            template_paths: Dict of template paths like 'Device.IP.Interface.{i}.Enable'
        
        Returns:
            Matching template path or None
        """
        import re
        
        for template_path in template_paths:
            # Convert template to regex pattern
            # Replace {i} with \d+ to match instance numbers
            pattern = re.escape(template_path)
            pattern = pattern.replace(r'\{i\}', r'\d+')
            pattern = pattern.replace(r'\{instance\}', r'\d+')
            pattern = '^' + pattern + '$'
            
            if re.match(pattern, instance_path, re.IGNORECASE):
                return template_path
        
        return None
    
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
            devices_path = os.path.abspath(DEVICES_FILE)
            Logger.info(f"Loading devices from: {devices_path}", level=1)
            if os.path.exists(DEVICES_FILE):
                with open(DEVICES_FILE, 'r', encoding='utf-8') as f:
                    self.devices = json.load(f)
                Logger.info(f"Loaded {len(self.devices)} devices: {list(self.devices.keys())}", level=0)
                return True
            else:
                Logger.info(f"Devices file not found: {devices_path}", level=1)
        except Exception as e:
            Logger.critical(f"Failed to load devices: {e}")
        return False

    def save_devices(self):
        """Save known devices to file"""
        try:
            with open(DEVICES_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.devices, f, indent=2, ensure_ascii=False)
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
            
            # heart-beat: send,receive (milliseconds)
            # 0,0 = disable heartbeat (heartbeat thread is disabled)
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
                
                # Start heartbeat thread (DISABLED to test if it causes timing issues)
                # self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
                # self.heartbeat_thread.start()
                Logger.info("Heartbeat thread disabled for testing", level=1)
                
                # Controller only subscribes to its own receive queue
                self.subscribe(RECEIVE_TOPIC)
                Logger.info(f"Subscribed to: {RECEIVE_TOPIC}", level=1)
                
                # If reply_to_queue is different, subscribe to it as well
                if RECEIVE_TOPIC != REPLY_TO_QUEUE:
                    self.subscribe(REPLY_TO_QUEUE)
                    Logger.info(f"Subscribed to: {REPLY_TO_QUEUE}", level=1)
                
                # Load known devices (only record reply_to, don't subscribe)
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

    def disconnect(self):
        """Disconnect from STOMP broker"""
        try:
            self.running = False
            self.connected = False
            
            if self.sock:
                try:
                    # Send DISCONNECT frame
                    disconnect_frame = "DISCONNECT\n\n\0"
                    self.sock.sendall(disconnect_frame.encode('utf-8'))
                    time.sleep(0.1)  # Give broker time to process
                except:
                    pass
                
                try:
                    self.sock.close()
                except:
                    pass
                
                self.sock = None
            
            # Clear subscription IDs
            self.subscription_ids = {}
            
            Logger.info("Disconnected from STOMP broker", level=0)
            return True
            
        except Exception as e:
            Logger.critical(f"Disconnect error: {e}")
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
                    Logger.critical(f"Receiver error: {e}")
                break

    def _heartbeat_loop(self):
        """Send STOMP heartbeat frames periodically"""
        from datetime import datetime
        import time
        
        Logger.info(f"Heartbeat thread started (interval: {self.heartbeat_interval}s)", level=1)
        
        while self.running and self.connected:
            try:
                time.sleep(self.heartbeat_interval)
                
                if not self.connected:
                    break
                
                # Send heartbeat (single newline)
                self.sock.sendall(b"\\n")
                self.last_heartbeat_sent = datetime.now()
                Logger.info(f"♥ Heartbeat sent to broker", level=2)
                
            except Exception as e:
                Logger.critical(f"Heartbeat error: {e}")
                if not self.connected:
                    break
        
        Logger.info("Heartbeat thread stopped", level=1)

    def _heartbeat_check_loop(self):
        """Periodically send Get requests to agents to verify they're alive"""
        import time
        
        Logger.info(f"Active heartbeat check started (interval: {HEARTBEAT_CHECK_INTERVAL}s)", level=1)
        
        while self.running and self.connected:
            try:
                # Check each known device
                devices_to_check = list(self.devices.keys())
                Logger.info(f"♥ Checking {len(devices_to_check)} device(s) for heartbeat", level=1)
                for endpoint_id in devices_to_check:
                    self._send_heartbeat_check(endpoint_id)
                
                time.sleep(HEARTBEAT_CHECK_INTERVAL)
                
                if not self.connected:
                    break
                
            except Exception as e:
                Logger.critical(f"Heartbeat check error: {e}")
                if not self.connected:
                    break
        
        Logger.info("Heartbeat check thread stopped", level=1)
    
    def _send_heartbeat_check(self, endpoint_id):
        """Send a lightweight Get request to check if agent is alive"""
        try:
            import uuid
            from datetime import datetime
            
            device_info = self.devices.get(endpoint_id)
            if not device_info:
                return
            
            reply_to = device_info.get('reply_to')
            if not reply_to:
                return
            
            # Create Get request for UpTime (lightweight parameter)
            msg = msg_pb2.Msg()
            msg.header.msg_id = str(uuid.uuid4())
            msg.header.msg_type = msg_pb2.Header.MsgType.GET
            
            get_req = msg.body.request.get
            get_req.param_paths.append(HEARTBEAT_CHECK_PATH)
            
            # Track this heartbeat check
            self.pending_heartbeat_checks[msg.header.msg_id] = {
                'endpoint': endpoint_id,
                'timestamp': datetime.now(),
                'path': HEARTBEAT_CHECK_PATH
            }
            
            # Wrap in USP Record
            usp_rec = record_pb2.Record()
            usp_rec.version = "1.4"
            usp_rec.to_id = endpoint_id
            usp_rec.from_id = CONTROLLER_ENDPOINT_ID
            usp_rec.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
            usp_rec.no_session_context.payload = msg.SerializeToString()
            
            Logger.info(f"♥ Sending heartbeat check to {endpoint_id}", level=1)
            self.send(reply_to, usp_rec.SerializeToString(), reply_to=REPLY_TO_QUEUE)
            
        except Exception as e:
            Logger.critical(f"Failed to send heartbeat check to {endpoint_id}: {e}")

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
        
        # Check if this is a heartbeat check response
        msg_id = msg.header.msg_id
        if msg_id in self.pending_heartbeat_checks:
            check_info = self.pending_heartbeat_checks.pop(msg_id)
            from datetime import datetime
            elapsed = (datetime.now() - check_info['timestamp']).total_seconds()
            Logger.success(f"♥ Heartbeat response from {check_info['endpoint']} (RTT: {elapsed:.2f}s)", level=2)
            # Continue to process response normally (but don't display verbose output)
            if DEBUG_LEVEL < 2:
                return  # Skip verbose output for heartbeat checks at lower debug levels
        
        # Check if this is an IPC request waiting for response
        ipc_req = None
        if msg_id in self.pending_ipc_requests:
            ipc_req = self.pending_ipc_requests.pop(msg_id)
        
        if resp.HasField('get_resp'):
            total_params = 0
            result_data = {}
            Logger.data(f"  === GET Response Start ===")
            for r in resp.get_resp.req_path_results:
                status = '✓' if r.err_code == 0 else '✗'
                Logger.data(f"  Path: {r.requested_path} ({status})")
                for res in r.resolved_path_results:
                    Logger.data(f"    {res.resolved_path}")
                    for p, v in res.result_params.items():
                        Logger.data(f"      {p} = {v}")
                        # Build full parameter path
                        full_param_path = res.resolved_path + p
                        result_data[full_param_path] = v
                        total_params += 1
            Logger.data(f"  === Total: {total_params} parameters ===")
            
            # Cache parameter values for SET testing
            if sender and result_data:
                if sender not in self.param_values_cache:
                    self.param_values_cache[sender] = {}
                self.param_values_cache[sender].update(result_data)
                Logger.info(f"[Cache] Stored {len(result_data)} parameter values for {sender}", level=1)
            
            # Return result to IPC caller if waiting
            if ipc_req and 'result_queue' in ipc_req:
                if result_data:
                    # Format result as readable text
                    result_text = "\n".join([f"{k}={v}" for k, v in result_data.items()])
                    ipc_req['result_queue'].put({"status": "ok", "msg": result_text, "data": result_data})
                else:
                    ipc_req['result_queue'].put({"status": "error", "msg": "No parameters returned"})
                    
        elif resp.HasField('get_supported_dm_resp'):
            count = 0
            writable_params = {}  # Cache writable parameters
            
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
                        
                        # Cache writable parameters (READ_WRITE or WRITE_ONLY)
                        if access in ["PARAM_READ_WRITE", "PARAM_WRITE_ONLY"]:
                            full_param_path = obj.supported_obj_path + p.param_name
                            writable_params[full_param_path] = {
                                'access': access,
                                'type': msg_pb2.GetSupportedDMResp.ParamValueType.Name(p.value_type) if p.value_type else 'unknown'
                            }
                    
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
            
            # Cache writable parameters for SET testing
            if sender and writable_params:
                self.writable_params_cache[sender] = writable_params
                Logger.info(f"[Cache] Stored {len(writable_params)} writable parameters for {sender}", level=1)
            
        elif resp.HasField('get_instances_resp'):
            total_instances = 0
            instance_paths = []
            Logger.data(f"  === GET_INSTANCES Response Start ===")
            for r in resp.get_instances_resp.req_path_results:
                status = '✓' if r.err_code == 0 else '✗'
                Logger.data(f"  Path: {r.requested_path} ({status})")
                if r.err_code != 0:
                    Logger.data(f"    Error: {r.err_msg}")
                else:
                    for inst in r.curr_insts:
                        Logger.data(f"    Instance: {inst.instantiated_obj_path}")
                        instance_paths.append(inst.instantiated_obj_path)
                        if inst.unique_keys:
                            for key, value in inst.unique_keys.items():
                                Logger.data(f"      {key} = {value}")
                        total_instances += 1
            Logger.data(f"  === Total: {total_instances} instances ===")
            
            # Return result to IPC caller if waiting
            if ipc_req and 'result_queue' in ipc_req:
                if instance_paths:
                    # Extract instance numbers from paths
                    import re
                    instance_numbers = []
                    for path in instance_paths:
                        # Extract number from path like "Device.DHCPv4.Server.Pool.2."
                        match = re.search(r'\.(\d+)\.$', path)
                        if match:
                            instance_numbers.append(match.group(1))
                    
                    result_text = "\n".join(instance_paths)
                    ipc_req['result_queue'].put({
                        "status": "ok", 
                        "msg": result_text,
                        "instances": instance_numbers,
                        "paths": instance_paths
                    })
                else:
                    ipc_req['result_queue'].put({"status": "ok", "msg": "No instances found", "instances": []})
            
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
            self.server_sock.settimeout(1.0)  # Allow periodic checks for shutdown
            self.started = True
            print(f"[*] IPC Server listening on {IPC_HOST}:{IPC_PORT}")
            
            while self.running:
                try:
                    client, addr = self.server_sock.accept()
                    self._handle_client(client)
                except socket.timeout:
                    # Normal timeout, continue checking self.running
                    continue
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
        # Declare global variables that may be modified by IPC commands
        global CONFIG, CONFIG_VALID, BROKER_HOST, BROKER_PORT, USERNAME, PASSWORD
        global CONTROLLER_ENDPOINT_ID, RECEIVE_TOPIC, REPLY_TO_QUEUE, MINI_BROKER_ENABLED
        
        try:
            data = client.recv(4096).decode('utf-8').strip()
            if not data: return
            
            response = {"status": "error", "msg": "unknown command"}
            
            cmd_parts = data.split()
            cmd = cmd_parts[0].lower()
            
            if cmd == "status":
                response = {
                    "status": "ok",
                    "daemon_running": True,  # IPC server is responding
                    "broker_connected": self.stomp.connected,
                    "broker_host": BROKER_HOST,
                    "broker_port": BROKER_PORT,
                    "config_valid": CONFIG_VALID,
                    "devices_count": len(self.stomp.devices),
                    "last_active": self.stomp.last_active_device,
                    "subscriptions": list(self.stomp.subscription_ids.keys())
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
                # get <endpoint> <path> [--timeout seconds]
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    path = cmd_parts[2]
                    
                    # Parse optional timeout
                    timeout = 30.0
                    if "--timeout" in cmd_parts:
                        try:
                            timeout_idx = cmd_parts.index("--timeout")
                            if timeout_idx + 1 < len(cmd_parts):
                                timeout = float(cmd_parts[timeout_idx + 1])
                        except (ValueError, IndexError):
                            pass
                    
                    # Wait for actual response
                    result = self._send_usp_get(endpoint, path, wait_response=True, timeout=timeout)
                    if result and isinstance(result, dict):
                        response = result
                    else:
                        response = {"status": "failed", "msg": "GET request failed"}
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
                # get_supported <endpoint> [obj_path] [first_level_only] [return_commands] [return_events] [return_params]
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2] if len(cmd_parts) >= 3 else "Device."
                    
                    # Parse optional boolean arguments (default: first_level_only=False, others=True)
                    first_level_only = False
                    return_commands = True
                    return_events = True
                    return_params = True
                    
                    if len(cmd_parts) >= 4:
                        first_level_only = cmd_parts[3].lower() in ['true', '1', 'yes']
                    if len(cmd_parts) >= 5:
                        return_commands = cmd_parts[4].lower() in ['true', '1', 'yes']
                    if len(cmd_parts) >= 6:
                        return_events = cmd_parts[5].lower() in ['true', '1', 'yes']
                    if len(cmd_parts) >= 7:
                        return_params = cmd_parts[6].lower() in ['true', '1', 'yes']
                    
                    success = self._send_usp_get_supported_dm(endpoint, obj_path, first_level_only, 
                                                             return_commands, return_events, return_params)
                    response = {"status": "ok" if success else "failed", "msg": f"GetSupportedDM sent to {endpoint}"}
                else:
                    response = {"status": "error", "msg": "usage: get_supported <endpoint> [obj_path] [first_level_only] [return_commands] [return_events] [return_params]"}
            
            elif cmd == "get_instances" or cmd == "getinstances":
                # get_instances <endpoint> <obj_path>
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    obj_path = cmd_parts[2]
                    # Wait for actual response
                    result = self._send_usp_get_instances(endpoint, obj_path, wait_response=True, timeout=30.0)
                    if result and isinstance(result, dict):
                        response = result
                    else:
                        response = {"status": "failed", "msg": "GetInstances request failed"}
                else:
                    response = {"status": "error", "msg": "usage: get_instances <endpoint> <obj_path>"}
            
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
                    
                    # Check if trying to modify broker config when mini-broker is enabled
                    if field in ["broker_host", "broker_port"] and MINI_BROKER_ENABLED:
                        response = {
                            "status": "error", 
                            "msg": f"Cannot modify {field}: Mini-Broker enabled, broker config is locked"
                        }
                    else:
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
            
            elif cmd == "start_broker" or cmd == "connect_broker":
                # Start/Connect to STOMP broker
                if not CONFIG_VALID:
                    response = {"status": "error", "msg": "Configuration invalid. Fix config first."}
                elif self.stomp.connected:
                    response = {"status": "ok", "msg": "Broker already connected"}
                else:
                    try:
                        if self.stomp.connect():
                            # Start mDNS discovery if enabled
                            if ENABLE_MDNS_DISCOVERY:
                                self.stomp.start_mdns_discovery()
                            response = {"status": "ok", "msg": f"Connected to broker {BROKER_HOST}:{BROKER_PORT}"}
                        else:
                            response = {"status": "error", "msg": "Failed to connect to broker"}
                    except Exception as e:
                        response = {"status": "error", "msg": f"Connection error: {str(e)}"}
            
            elif cmd == "stop_broker" or cmd == "disconnect_broker":
                # Disconnect from STOMP broker
                if not self.stomp.connected:
                    response = {"status": "ok", "msg": "Broker already disconnected"}
                else:
                    try:
                        # Stop mDNS discovery
                        self.stomp.stop_mdns_discovery()
                        
                        if self.stomp.disconnect():
                            response = {"status": "ok", "msg": "Disconnected from broker"}
                        else:
                            response = {"status": "error", "msg": "Disconnect failed"}
                    except Exception as e:
                        response = {"status": "error", "msg": f"Disconnect error: {str(e)}"}
            
            elif cmd == "restart_broker" or cmd == "reconnect":
                # Restart STOMP broker connection
                if not CONFIG_VALID:
                    response = {"status": "error", "msg": "Configuration invalid. Fix config first."}
                else:
                    try:
                        # Disconnect if connected
                        if self.stomp.connected:
                            self.stomp.stop_mdns_discovery()
                            self.stomp.disconnect()
                            time.sleep(0.5)  # Wait for clean disconnect
                        
                        # Reconnect
                        if self.stomp.connect():
                            if ENABLE_MDNS_DISCOVERY:
                                self.stomp.start_mdns_discovery()
                            response = {"status": "ok", "msg": f"Reconnected to broker {BROKER_HOST}:{BROKER_PORT}"}
                        else:
                            response = {"status": "error", "msg": "Reconnection failed"}
                    except Exception as e:
                        response = {"status": "error", "msg": f"Reconnection error: {str(e)}"}
            
            elif cmd == "get_config":
                # Return current configuration
                try:
                    response = {
                        "status": "ok",
                        "config": {
                            "broker_host": BROKER_HOST,
                            "broker_port": BROKER_PORT,
                            "username": USERNAME,
                            "password": "***" if PASSWORD else "",  # Don't expose password
                            "controller_endpoint_id": CONTROLLER_ENDPOINT_ID,
                            "receive_topic": RECEIVE_TOPIC,
                            "reply_to_queue": REPLY_TO_QUEUE,
                            "mini_broker_enabled": MINI_BROKER_ENABLED,
                            "mdns_discovery": ENABLE_MDNS_DISCOVERY,
                            "config_valid": CONFIG_VALID
                        }
                    }
                except Exception as e:
                    response = {"status": "error", "msg": f"Error: {str(e)}"}
            
            elif cmd == "reload_config":
                # Reload configuration from config.json and reconnect if valid
                try:
                    # Reload config file
                    CONFIG = load_config()
                    CONFIG_VALID = validate_config(CONFIG)
                    
                    if not CONFIG_VALID:
                        response = {"status": "error", "msg": "Configuration validation failed. Check config.json"}
                    else:
                        # Update global variables
                        usp_config = CONFIG['usp_controller']
                        BROKER_HOST = usp_config.get('broker_host', DEFAULT_CONFIG['broker_host'])
                        BROKER_PORT = usp_config.get('broker_port', DEFAULT_CONFIG['broker_port'])
                        USERNAME = usp_config.get('username', DEFAULT_CONFIG['username'])
                        PASSWORD = usp_config.get('password', DEFAULT_CONFIG['password'])
                        CONTROLLER_ENDPOINT_ID = usp_config['controller_endpoint_id']
                        RECEIVE_TOPIC = usp_config['receive_topic']
                        REPLY_TO_QUEUE = usp_config.get('reply_to_queue', f'/queue/{CONTROLLER_ENDPOINT_ID}')
                        
                        # Update mini-broker configuration
                        mini_broker_config = CONFIG.get('mini_broker', {})
                        MINI_BROKER_ENABLED = mini_broker_config.get('enable', False)
                        if MINI_BROKER_ENABLED:
                            BROKER_HOST = mini_broker_config.get('host', '127.0.0.1')
                            BROKER_PORT = mini_broker_config.get('port', 61613)
                        
                        # Try to reconnect with new configuration
                        if self.stomp.connected:
                            self.stomp.sock.close()
                            self.stomp.connected = False
                            time.sleep(1)
                        
                        if self.stomp.connect():
                            response = {"status": "ok", "msg": f"Configuration reloaded and connected to {BROKER_HOST}:{BROKER_PORT}"}
                        else:
                            response = {"status": "partial", "msg": "Configuration reloaded but connection failed. Check broker availability."}
                except Exception as e:
                    response = {"status": "error", "msg": f"Reload config error: {str(e)}"}
            
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
            
            elif cmd == "list_writable":
                # list_writable [endpoint] [--simple]
                # List cached writable parameters for an endpoint
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    simple_mode = "--simple" in cmd_parts or "--fast" in cmd_parts
                    
                    if endpoint in self.stomp.writable_params_cache:
                        writable = self.stomp.writable_params_cache[endpoint]
                        writable_count = len(writable)
                        values_count = len(self.stomp.param_values_cache.get(endpoint, {}))
                        
                        if simple_mode:
                            # Fast mode: only return counts, no detailed matching
                            response = {
                                "status": "ok",
                                "endpoint": endpoint,
                                "mode": "simple",
                                "total_writable_templates": writable_count,
                                "total_cached_values": values_count,
                                "msg": f"Found {writable_count} writable templates and {values_count} cached values. Use without --simple for detailed analysis."
                            }
                        else:
                            # Detailed mode: perform matching (may be slow for large datasets)
                            Logger.info(f"[ListWritable] Analyzing {writable_count} templates against {values_count} values...", level=0)
                            
                            params_with_values = []
                            params_no_values = []
                            
                            for idx, (template_path, access_info) in enumerate(writable.items(), 1):
                                # Progress logging for large datasets
                                if idx % 100 == 0:
                                    Logger.info(f"[ListWritable] Progress: {idx}/{writable_count}", level=1)
                                
                                # Check for exact match first
                                has_value = (endpoint in self.stomp.param_values_cache and 
                                           template_path in self.stomp.param_values_cache[endpoint])
                                
                                if not has_value and endpoint in self.stomp.param_values_cache:
                                    # Try to find matching instance paths (limit check for performance)
                                    matching_count = 0
                                    example_instance = None
                                    for instance_path in self.stomp.param_values_cache[endpoint].keys():
                                        matched = self.stomp._match_param_to_template(instance_path, [template_path])
                                        if matched:
                                            matching_count += 1
                                            if not example_instance:
                                                example_instance = instance_path
                                    
                                    if matching_count > 0:
                                        params_with_values.append({
                                            'path': template_path,
                                            'access': access_info['access'],
                                            'type': access_info['type'],
                                            'instances': matching_count,
                                            'example': example_instance
                                        })
                                    else:
                                        params_no_values.append({
                                            'path': template_path,
                                            'access': access_info['access'],
                                            'type': access_info['type']
                                        })
                                elif has_value:
                                    value = self.stomp.param_values_cache[endpoint][template_path]
                                    params_with_values.append({
                                        'path': template_path,
                                        'access': access_info['access'],
                                        'type': access_info['type'],
                                        'value': value,
                                        'instances': 1
                                    })
                                else:
                                    params_no_values.append({
                                        'path': template_path,
                                        'access': access_info['access'],
                                        'type': access_info['type']
                                    })
                            
                            # Count total instances that can be tested
                            total_testable = sum(p.get('instances', 1) for p in params_with_values)
                            
                            Logger.info(f"[ListWritable] Analysis complete: {total_testable} testable parameters", level=0)
                            
                            response = {
                                "status": "ok",
                                "endpoint": endpoint,
                                "mode": "detailed",
                                "total_templates": writable_count,
                                "templates_with_values": len(params_with_values),
                                "templates_without_values": len(params_no_values),
                                "total_testable_params": total_testable,
                                "params_ready": params_with_values,
                                "params_need_get": params_no_values
                            }
                    else:
                        response = {
                            "status": "error",
                            "msg": f"No cached writable parameters for {endpoint}. Run 'get_supported {endpoint} Device.' first."
                        }
                else:
                    # List all endpoints with cached data
                    endpoints_info = {}
                    for ep in self.stomp.writable_params_cache.keys():
                        writable_count = len(self.stomp.writable_params_cache[ep])
                        values_count = len(self.stomp.param_values_cache.get(ep, {}))
                        endpoints_info[ep] = {
                            'writable_params': writable_count,
                            'cached_values': values_count
                        }
                    
                    response = {
                        "status": "ok",
                        "endpoints": endpoints_info
                    }
            
            elif cmd == "test_set":
                # test_set <endpoint> <param_path>
                # Test setting a specific writable parameter to its cached value
                if len(cmd_parts) >= 3:
                    endpoint = cmd_parts[1]
                    param_path = " ".join(cmd_parts[2:])  # Allow spaces in path
                    
                    # Check if parameter is in writable cache
                    if endpoint not in self.stomp.writable_params_cache:
                        response = {
                            "status": "error",
                            "msg": f"No cached writable parameters for {endpoint}. Run 'get_supported {endpoint} Device.' first."
                        }
                    elif endpoint not in self.stomp.param_values_cache or param_path not in self.stomp.param_values_cache[endpoint]:
                        response = {
                            "status": "error",
                            "msg": f"No cached value for {param_path}. Run 'get {endpoint} <path>' first."
                        }
                    else:
                        # Check if parameter is writable (exact or fuzzy match)
                        is_writable = param_path in self.stomp.writable_params_cache[endpoint]
                        if not is_writable:
                            # Try fuzzy match
                            matched_template = self.stomp._match_param_to_template(
                                param_path, 
                                self.stomp.writable_params_cache[endpoint].keys()
                            )
                            is_writable = matched_template is not None
                        
                        if not is_writable:
                            response = {
                                "status": "error",
                                "msg": f"Parameter {param_path} not found in writable cache. It may not be writable."
                            }
                        else:
                            # Get cached value and attempt SET
                            value = self.stomp.param_values_cache[endpoint][param_path]
                            success = self._send_usp_set(endpoint, param_path, value)
                            response = {
                                "status": "ok" if success else "failed",
                                "msg": f"SET {param_path} = '{value}' {'sent successfully' if success else 'failed'}",
                                "param": param_path,
                                "value": value
                            }
                else:
                    response = {"status": "error", "msg": "usage: test_set <endpoint> <param_path>"}
            
            elif cmd == "test_set_all":
                # test_set_all <endpoint> [--delay seconds] [--batch-size N] [--batch-delay seconds] [--stop-on-fail]
                # Test setting all writable parameters with cached values
                delay = 0.5  # Default delay between SETs (increased for Agent protection)
                batch_size = 100  # Progress report every N parameters
                batch_delay = 2.0  # Additional delay between batches (Agent recovery time)
                stop_on_fail = False  # Stop test immediately on first failure
                
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    
                    # Parse optional --delay parameter
                    if "--delay" in cmd_parts:
                        try:
                            delay_idx = cmd_parts.index("--delay")
                            if delay_idx + 1 < len(cmd_parts):
                                delay = float(cmd_parts[delay_idx + 1])
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse optional --batch-size parameter
                    if "--batch-size" in cmd_parts:
                        try:
                            batch_idx = cmd_parts.index("--batch-size")
                            if batch_idx + 1 < len(cmd_parts):
                                batch_size = int(cmd_parts[batch_idx + 1])
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse optional --batch-delay parameter
                    if "--batch-delay" in cmd_parts:
                        try:
                            batch_delay_idx = cmd_parts.index("--batch-delay")
                            if batch_delay_idx + 1 < len(cmd_parts):
                                batch_delay = float(cmd_parts[batch_delay_idx + 1])
                        except (ValueError, IndexError):
                            pass
                    
                    # Parse optional --stop-on-fail flag
                    if "--stop-on-fail" in cmd_parts:
                        stop_on_fail = True
                    
                    # Check if we have cached data
                    if endpoint not in self.stomp.writable_params_cache:
                        response = {
                            "status": "error",
                            "msg": f"No cached writable parameters for {endpoint}. Run 'get_supported {endpoint} Device.' first."
                        }
                    elif endpoint not in self.stomp.param_values_cache:
                        response = {
                            "status": "error",
                            "msg": f"No cached values for {endpoint}. Run 'get {endpoint} Device.' first."
                        }
                    else:
                        # Build test parameter list with optimized matching
                        Logger.info(f"[TestSetAll] Analyzing writable parameters for {endpoint}...", level=0)
                        
                        writable = self.stomp.writable_params_cache[endpoint]
                        values = self.stomp.param_values_cache[endpoint]
                        
                        # Optimize: separate exact matches from fuzzy matches
                        test_params = []
                        
                        # First pass: exact matches (very fast)
                        Logger.info(f"[TestSetAll] Finding exact matches...", level=0)
                        exact_matches = 0
                        for param_path in values.keys():
                            if param_path in writable:
                                test_params.append((param_path, values[param_path]))
                                exact_matches += 1
                        
                        Logger.info(f"[TestSetAll] Found {exact_matches} exact matches", level=0)
                        
                        # Second pass: fuzzy matches only if needed (slower)
                        if exact_matches < len(writable):
                            Logger.info(f"[TestSetAll] Finding fuzzy matches (templates with {{i}})...", level=0)
                            
                            # Build regex pattern cache for efficiency
                            import re
                            template_patterns = {}
                            fuzzy_templates = []
                            
                            for template_path in writable.keys():
                                if '{i}' in template_path or '{instance}' in template_path:
                                    fuzzy_templates.append(template_path)
                                    # Pre-compile regex pattern
                                    pattern = re.escape(template_path)
                                    pattern = pattern.replace(r'\{i\}', r'\d+')
                                    pattern = pattern.replace(r'\{instance\}', r'\d+')
                                    pattern = '^' + pattern + '$'
                                    template_patterns[template_path] = re.compile(pattern, re.IGNORECASE)
                            
                            Logger.info(f"[TestSetAll] Checking {len(fuzzy_templates)} templates against {len(values)} values...", level=0)
                            
                            # Match values against fuzzy templates
                            fuzzy_matches = 0
                            checked = 0
                            for value_path, value in values.items():
                                if value_path in writable:  # Skip already matched
                                    continue
                                
                                checked += 1
                                if checked % 1000 == 0:
                                    Logger.info(f"[TestSetAll] Checked {checked}/{len(values)} values...", level=1)
                                
                                for template_path, pattern in template_patterns.items():
                                    if pattern.match(value_path):
                                        test_params.append((value_path, value))
                                        fuzzy_matches += 1
                                        break  # Found match, no need to check other templates
                            
                            Logger.info(f"[TestSetAll] Found {fuzzy_matches} fuzzy matches", level=0)
                        
                        if not test_params:
                            response = {
                                "status": "error",
                                "msg": f"No writable parameters found. Mismatch between get_supported and get results."
                            }
                        else:
                            Logger.info(f"[TestSetAll] Total testable parameters: {len(test_params)}", level=0)
                            
                            # Schedule batch test (non-blocking)
                            import threading
                            def run_batch_test():
                                total = len(test_params)
                                start_time = datetime.now()
                                Logger.info(f"[Test] Starting batch SET test for {endpoint}: {total} parameters", level=0)
                                Logger.info(f"[Test] Strategy: Wait for each SET response, adaptive delay based on Agent status", level=0)
                                if stop_on_fail:
                                    Logger.info(f"[Test] Mode: STOP-ON-FAIL enabled (test will abort on first failure)", level=0)
                                
                                success_count = 0
                                fail_count = 0
                                timeout_count = 0
                                test_aborted = False
                                
                                # Adaptive delay parameters
                                current_delay = max(0.1, delay)  # Start with specified delay, min 0.1s
                                consecutive_success = 0
                                consecutive_fails = 0
                                
                                Logger.info(f"[Test] Initial delay={current_delay}s, batch_delay={batch_delay}s between batches", level=0)
                                
                                for idx, (param_path, value) in enumerate(test_params, 1):
                                    # First SET may take longer (Agent warm-up), use extended timeout
                                    set_timeout = 60.0 if idx == 1 else 30.0
                                    
                                    if idx == 1:
                                        Logger.info(f"[Test] First SET using extended timeout ({set_timeout}s) for Agent warm-up", level=0)
                                    
                                    # Send SET and wait for response
                                    resp = self._send_usp_set(endpoint, param_path, value, wait_response=True, timeout=set_timeout)
                                    
                                    if resp and resp.get('status') == 'ok':
                                        success_count += 1
                                        consecutive_success += 1
                                        consecutive_fails = 0
                                        
                                        if DEBUG_LEVEL >= 1:
                                            Logger.info(f"  ✓ [{idx}/{total}] {param_path} = '{value}'", level=1)
                                        
                                        # Gradually reduce delay if many consecutive successes
                                        if consecutive_success >= 20 and current_delay > 0.1:
                                            current_delay = max(0.1, current_delay * 0.9)
                                            Logger.info(f"[Adaptive] Reducing delay to {current_delay:.2f}s (consecutive success: {consecutive_success})", level=0)
                                            consecutive_success = 0
                                    
                                    elif resp and resp.get('status') == 'timeout':
                                        timeout_count += 1
                                        fail_count += 1
                                        consecutive_fails += 1
                                        consecutive_success = 0
                                        
                                        Logger.error(f"  ⏱ [{idx}/{total}] {param_path} = '{value}' TIMEOUT (waited {set_timeout}s)", level=0)
                                        
                                        # Stop on fail if requested
                                        if stop_on_fail:
                                            Logger.error(f"[Test] ABORTED: Timeout on parameter '{param_path}' (stop-on-fail enabled)", level=0)
                                            Logger.error(f"[Test] Failed parameter: {param_path} = '{value}'", level=0)
                                            test_aborted = True
                                            break
                                        
                                        # Increase delay significantly on timeout (Agent overloaded)
                                        if consecutive_fails >= 3:
                                            current_delay = min(5.0, current_delay * 2.0)
                                            Logger.info(f"[Adaptive] Increasing delay to {current_delay:.2f}s (consecutive timeouts: {consecutive_fails})", level=0)
                                            consecutive_fails = 0
                                    
                                    else:
                                        fail_count += 1
                                        consecutive_fails += 1
                                        consecutive_success = 0
                                        
                                        error_msg = resp.get('msg', 'Unknown error') if resp else 'No response'
                                        Logger.error(f"  ✗ [{idx}/{total}] {param_path} = '{value}' - {error_msg}", level=1)
                                        
                                        # Stop on fail if requested
                                        if stop_on_fail:
                                            Logger.error(f"[Test] ABORTED: Failed to set parameter '{param_path}' (stop-on-fail enabled)", level=0)
                                            Logger.error(f"[Test] Failed parameter: {param_path} = '{value}' - {error_msg}", level=0)
                                            test_aborted = True
                                            break
                                        
                                        # Moderate delay increase on errors
                                        if consecutive_fails >= 5:
                                            current_delay = min(3.0, current_delay * 1.5)
                                            Logger.info(f"[Adaptive] Increasing delay to {current_delay:.2f}s (consecutive failures: {consecutive_fails})", level=0)
                                            consecutive_fails = 0
                                    
                                    # Progress report every batch_size parameters
                                    if idx % batch_size == 0:
                                        elapsed = (datetime.now() - start_time).total_seconds()
                                        rate = idx / elapsed if elapsed > 0 else 0
                                        remaining = (total - idx) / rate if rate > 0 else 0
                                        Logger.info(f"[Progress] {idx}/{total} ({idx*100/total:.1f}%) - "
                                                  f"Success: {success_count}, Failed: {fail_count}, Timeout: {timeout_count}, "
                                                  f"Rate: {rate:.1f} params/s, Delay: {current_delay:.2f}s, ETA: {remaining:.0f}s", level=0)
                                        
                                        # Additional delay between batches to let Agent recover
                                        if idx < total and batch_delay > 0:
                                            Logger.info(f"[Progress] Pausing {batch_delay}s for Agent recovery...", level=0)
                                            time.sleep(batch_delay)
                                    elif idx == total:
                                        # Final progress report
                                        elapsed = (datetime.now() - start_time).total_seconds()
                                        rate = idx / elapsed if elapsed > 0 else 0
                                        Logger.info(f"[Progress] {idx}/{total} (100.0%) - "
                                                  f"Success: {success_count}, Failed: {fail_count}, Timeout: {timeout_count}, "
                                                  f"Rate: {rate:.1f} params/s", level=0)
                                    
                                    # Adaptive delay between SETs
                                    if current_delay > 0:
                                        time.sleep(current_delay)
                                
                                elapsed = (datetime.now() - start_time).total_seconds()
                                if test_aborted:
                                    Logger.error(f"[Test] Batch SET test ABORTED after {elapsed:.1f}s ({elapsed/60:.1f} min)", level=0)
                                else:
                                    Logger.info(f"[Test] Batch SET test completed in {elapsed:.1f}s ({elapsed/60:.1f} min)", level=0)
                                Logger.info(f"[Test] Results: {success_count} succeeded, {fail_count} failed ({timeout_count} timeouts), Success rate: {success_count*100/total:.1f}%", level=0)
                                
                                if test_aborted:
                                    Logger.error(f"[Test] ⚠ Test did not complete - stopped at {idx}/{total} ({idx*100/total:.1f}%)", level=0)
                            
                            thread = threading.Thread(target=run_batch_test, daemon=True)
                            thread.start()
                            
                            # Calculate estimated time (including batch delays)
                            num_batches = (len(test_params) + batch_size - 1) // batch_size
                            estimated_time = len(test_params) * delay
                            if batch_delay > 0 and num_batches > 1:
                                estimated_time += (num_batches - 1) * batch_delay
                            
                            response = {
                                "status": "ok",
                                "msg": f"Batch SET test started for {len(test_params)} parameters (delay: {delay}s, batch_size: {batch_size}, batch_delay: {batch_delay}s, stop_on_fail: {stop_on_fail})",
                                "async": True,  # Mark as background operation
                                "total_params": len(test_params),
                                "delay": delay,
                                "batch_size": batch_size,
                                "batch_delay": batch_delay,
                                "stop_on_fail": stop_on_fail,
                                "rate_limit": f"{1/delay:.1f} SET/s" if delay > 0 else "unlimited",
                                "estimated_seconds": estimated_time,
                                "estimated_minutes": estimated_time / 60 if estimated_time > 0 else 0
                            }
                else:
                    response = {"status": "error", "msg": "usage: test_set_all <endpoint> [--delay seconds] [--batch-size N] [--batch-delay seconds] [--stop-on-fail]"}
            
            elif cmd == "export_cache":
                # export_cache <endpoint> [output_prefix]
                # Export cached data to JSON files for inspection (async)
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    output_prefix = cmd_parts[2] if len(cmd_parts) >= 3 else "test_data"
                    
                    # Check if we have cache data
                    if endpoint not in self.stomp.writable_params_cache and endpoint not in self.stomp.param_values_cache:
                        response = {
                            "status": "error",
                            "msg": f"No cache data found for {endpoint}. Run get_supported and get first."
                        }
                    else:
                        # Run export in background thread to avoid IPC timeout
                        import threading
                        import os
                        
                        def export_async():
                            try:
                                # Create temp directory if not exists
                                temp_dir = "temp"
                                if not os.path.exists(temp_dir):
                                    os.makedirs(temp_dir)
                                    Logger.info(f"[Export] Created {temp_dir}/ directory", level=0)
                                
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                exported_files = []
                                
                                Logger.info(f"[Export] Starting cache export for {endpoint} to {temp_dir}/...", level=0)
                                
                                # Export writable parameters (from get_supported)
                                if endpoint in self.stomp.writable_params_cache:
                                    writable_file = os.path.join(temp_dir, f"{output_prefix}_writable_{timestamp}.json")
                                    Logger.info(f"[Export] Writing {writable_file}...", level=0)
                                    with open(writable_file, 'w', encoding='utf-8') as f:
                                        data = {
                                            "endpoint": endpoint,
                                            "timestamp": timestamp,
                                            "source": "get_supported",
                                            "total_writable": len(self.stomp.writable_params_cache[endpoint]),
                                            "parameters": self.stomp.writable_params_cache[endpoint]
                                        }
                                        json.dump(data, f, indent=2, ensure_ascii=False)
                                    exported_files.append(writable_file)
                                    Logger.info(f"[Export] ✓ Exported {len(self.stomp.writable_params_cache[endpoint])} writable parameters", level=0)
                                
                                # Export parameter values (from get)
                                if endpoint in self.stomp.param_values_cache:
                                    values_file = os.path.join(temp_dir, f"{output_prefix}_values_{timestamp}.json")
                                    Logger.info(f"[Export] Writing {values_file} (this may take a while for large datasets)...", level=0)
                                    with open(values_file, 'w', encoding='utf-8') as f:
                                        data = {
                                            "endpoint": endpoint,
                                            "timestamp": timestamp,
                                            "source": "get",
                                            "total_values": len(self.stomp.param_values_cache[endpoint]),
                                            "parameters": self.stomp.param_values_cache[endpoint]
                                        }
                                        json.dump(data, f, indent=2, ensure_ascii=False)
                                    exported_files.append(values_file)
                                    Logger.info(f"[Export] ✓ Exported {len(self.stomp.param_values_cache[endpoint])} parameter values", level=0)
                                
                                # Create matching report
                                if endpoint in self.stomp.writable_params_cache and endpoint in self.stomp.param_values_cache:
                                    match_file = os.path.join(temp_dir, f"{output_prefix}_matched_{timestamp}.json")
                                    Logger.info(f"[Export] Analyzing matches and writing {match_file}...", level=0)
                                    
                                    writable = self.stomp.writable_params_cache[endpoint]
                                    values = self.stomp.param_values_cache[endpoint]
                                    
                                    matched_params = []
                                    unmatched_templates = []
                                    
                                    for template_path, access_info in writable.items():
                                        # Try exact match
                                        if template_path in values:
                                            matched_params.append({
                                                "template": template_path,
                                                "instance": template_path,
                                                "value": values[template_path],
                                                "access": access_info['access'],
                                                "type": access_info['type'],
                                                "match_type": "exact"
                                            })
                                        else:
                                            # Try fuzzy match
                                            matching_instances = []
                                            for instance_path in values.keys():
                                                if self.stomp._match_param_to_template(instance_path, [template_path]):
                                                    matching_instances.append({
                                                        "instance": instance_path,
                                                        "value": values[instance_path]
                                                    })
                                            
                                            if matching_instances:
                                                for match in matching_instances:
                                                    matched_params.append({
                                                        "template": template_path,
                                                        "instance": match["instance"],
                                                        "value": match["value"],
                                                        "access": access_info['access'],
                                                        "type": access_info['type'],
                                                        "match_type": "fuzzy"
                                                    })
                                            else:
                                                unmatched_templates.append({
                                                    "template": template_path,
                                                    "access": access_info['access'],
                                                    "type": access_info['type'],
                                                    "reason": "No matching instances found in get results"
                                                })
                                    
                                    with open(match_file, 'w', encoding='utf-8') as f:
                                        data = {
                                            "endpoint": endpoint,
                                            "timestamp": timestamp,
                                            "source": "matching_analysis",
                                            "total_writable_templates": len(writable),
                                            "total_value_instances": len(values),
                                            "matched_count": len(matched_params),
                                            "unmatched_count": len(unmatched_templates),
                                            "matched_parameters": matched_params,
                                            "unmatched_templates": unmatched_templates
                                        }
                                        json.dump(data, f, indent=2, ensure_ascii=False)
                                    exported_files.append(match_file)
                                    Logger.info(f"[Export] ✓ Matched {len(matched_params)} parameters, {len(unmatched_templates)} unmatched", level=0)
                                
                                # Final summary
                                Logger.info(f"[Export] ✓ Export complete! Created {len(exported_files)} file(s):", level=0)
                                for f in exported_files:
                                    Logger.info(f"[Export]   • {f}", level=0)
                                    
                            except Exception as e:
                                Logger.error(f"[Export] Failed: {e}", level=0)
                        
                        # Start export in background
                        thread = threading.Thread(target=export_async, daemon=True)
                        thread.start()
                        
                        # Immediate response
                        writable_count = len(self.stomp.writable_params_cache.get(endpoint, {}))
                        values_count = len(self.stomp.param_values_cache.get(endpoint, {}))
                        
                        response = {
                            "status": "ok",
                            "msg": f"Export started in background for {endpoint} ({writable_count} writable templates, {values_count} values). Check logs for progress.",
                            "async": True,
                            "writable_count": writable_count,
                            "values_count": values_count
                        }
                else:
                    response = {"status": "error", "msg": "Usage: export_cache <endpoint> [output_prefix]"}
            
            elif cmd == "clear_temp":
                # clear_temp
                # Clear temporary files from temp/ directory
                import os
                import shutil
                
                temp_dir = "temp"
                if os.path.exists(temp_dir):
                    try:
                        file_count = len([f for f in os.listdir(temp_dir) if os.path.isfile(os.path.join(temp_dir, f))])
                        shutil.rmtree(temp_dir)
                        Logger.info(f"[Cleanup] Removed {temp_dir}/ directory with {file_count} file(s)", level=0)
                        response = {
                            "status": "ok",
                            "msg": f"Cleared {file_count} temporary file(s)"
                        }
                    except Exception as e:
                        response = {
                            "status": "error",
                            "msg": f"Failed to clear temp directory: {e}"
                        }
                else:
                    response = {
                        "status": "ok",
                        "msg": "No temp directory found (nothing to clear)"
                    }
            
            elif cmd == "clear_cache":
                # clear_cache [endpoint]
                # Clear cached writable parameters and values
                if len(cmd_parts) >= 2:
                    endpoint = cmd_parts[1]
                    cleared = 0
                    if endpoint in self.stomp.writable_params_cache:
                        del self.stomp.writable_params_cache[endpoint]
                        cleared += 1
                    if endpoint in self.stomp.param_values_cache:
                        del self.stomp.param_values_cache[endpoint]
                        cleared += 1
                    
                    response = {
                        "status": "ok",
                        "msg": f"Cleared cache for {endpoint}" if cleared > 0 else f"No cache found for {endpoint}"
                    }
                else:
                    # Clear all caches
                    writable_count = len(self.stomp.writable_params_cache)
                    values_count = len(self.stomp.param_values_cache)
                    self.stomp.writable_params_cache.clear()
                    self.stomp.param_values_cache.clear()
                    
                    response = {
                        "status": "ok",
                        "msg": f"Cleared all caches ({writable_count} endpoints with writable params, {values_count} with values)"
                    }
            
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

            elif cmd == "shutdown" or cmd == "quit":
                # Shutdown daemon gracefully
                response = {"status": "ok", "msg": "Daemon shutting down..."}
                client.sendall(json.dumps(response).encode('utf-8'))
                client.close()
                
                # Schedule shutdown
                print("[*] Shutdown command received via IPC")
                self.running = False
                
                # Disconnect from broker
                if self.stomp.connected:
                    print("[*] Disconnecting from broker...")
                    self.stomp.stop_mdns_discovery()
                    self.stomp.disconnect()
                
                # Exit daemon
                import sys
                sys.exit(0)

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
            
        except socket.timeout:
            print(f"[!] IPC Client timeout")
            try: client.close()
            except: pass
        except BrokenPipeError:
            print(f"[!] IPC Client disconnected unexpectedly")
            try: client.close()
            except: pass
        except Exception as e:
            print(f"[!] IPC Client error: {e}")
            try: 
                error_response = {"status": "error", "msg": f"Server error: {str(e)}"}
                client.sendall(json.dumps(error_response).encode('utf-8'))
                client.close()
            except: 
                pass

    def _send_usp_get(self, endpoint, path, wait_response=False, timeout=30.0):
        """Helper to construct USP Get"""
        import queue
        from datetime import datetime
        
        # Check for duplicate request
        request_key = (endpoint, 'get', path)
        if wait_response and request_key in self.stomp.pending_requests:
            existing_msg_id = self.stomp.pending_requests[request_key]
            if existing_msg_id in self.stomp.pending_ipc_requests:
                return {"status": "error", "msg": "Duplicate request already pending"}
        
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
        usp_msg.body.request.get.param_paths.append(path)
        
        # If wait_response, register for response tracking
        result_queue = None
        if wait_response:
            result_queue = queue.Queue()
            self.stomp.pending_ipc_requests[msg_id] = {
                'endpoint': endpoint,
                'command': 'get',
                'path': path,
                'result_queue': result_queue,
                'timestamp': datetime.now()
            }
            self.stomp.pending_requests[request_key] = msg_id
        
        success = self._send_usp_message(endpoint, usp_msg)
        
        if not success:
            if wait_response and msg_id in self.stomp.pending_ipc_requests:
                del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
            return None if wait_response else False
        
        # Wait for response if requested
        if wait_response:
            try:
                result = result_queue.get(timeout=timeout)
                # Clean up tracking
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return result
            except queue.Empty:
                # Timeout - clean up
                if msg_id in self.stomp.pending_ipc_requests:
                    del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return {"status": "timeout", "msg": f"No response after {timeout}s"}
        
        return True
    
    def _send_usp_set(self, endpoint, path, value, wait_response=False, timeout=30.0):
        """Helper to construct USP Set
        
        Args:
            endpoint: Target device endpoint ID
            path: Parameter path to set
            value: Value to set
            wait_response: If True, wait for and return the response
            timeout: Timeout in seconds when wait_response=True
            
        Returns:
            If wait_response=True: response dict with status/msg, or timeout dict
            If wait_response=False: True/False for send success
        """
        import queue
        from datetime import datetime
        
        # Check for duplicate request
        request_key = (endpoint, 'set', path)
        if wait_response and request_key in self.stomp.pending_requests:
            existing_msg_id = self.stomp.pending_requests[request_key]
            if existing_msg_id in self.stomp.pending_ipc_requests:
                return {"status": "error", "msg": "Duplicate request already pending"}
        
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
        
        # If wait_response, register for response tracking
        result_queue = None
        if wait_response:
            result_queue = queue.Queue()
            self.stomp.pending_ipc_requests[msg_id] = {
                'endpoint': endpoint,
                'command': 'set',
                'path': path,
                'result_queue': result_queue,
                'timestamp': datetime.now()
            }
            self.stomp.pending_requests[request_key] = msg_id
        
        success = self._send_usp_message(endpoint, usp_msg)
        
        if not success:
            if wait_response and msg_id in self.stomp.pending_ipc_requests:
                del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
            return None if wait_response else False
        
        # Wait for response if requested
        if wait_response:
            try:
                result = result_queue.get(timeout=timeout)
                # Clean up tracking
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return result
            except queue.Empty:
                # Timeout - clean up
                if msg_id in self.stomp.pending_ipc_requests:
                    del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return {"status": "timeout", "msg": f"No response after {timeout}s"}
        
        return True
    
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
    
    def _send_usp_get_supported_dm(self, endpoint, obj_path="Device.", 
                                   first_level_only=False, return_commands=True, 
                                   return_events=True, return_params=True):
        """Helper to construct USP GetSupportedDM
        
        Args:
            endpoint: Target device endpoint ID
            obj_path: Data model path to query (default: "Device.")
            first_level_only: Only return first level children (default: False)
            return_commands: Include commands in response (default: True)
            return_events: Include events in response (default: True)
            return_params: Include parameters in response (default: True)
        """
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_SUPPORTED_DM
        
        usp_msg.body.request.get_supported_dm.obj_paths.append(obj_path)
        usp_msg.body.request.get_supported_dm.first_level_only = first_level_only
        usp_msg.body.request.get_supported_dm.return_commands = return_commands
        usp_msg.body.request.get_supported_dm.return_events = return_events
        usp_msg.body.request.get_supported_dm.return_params = return_params
        
        return self._send_usp_message(endpoint, usp_msg)
    
    def _send_usp_get_instances(self, endpoint, obj_path, wait_response=False, timeout=30.0):
        """Helper to construct USP GetInstances"""
        import queue
        from datetime import datetime
        
        # Check for duplicate request
        request_key = (endpoint, 'get_instances', obj_path)
        if wait_response and request_key in self.stomp.pending_requests:
            existing_msg_id = self.stomp.pending_requests[request_key]
            if existing_msg_id in self.stomp.pending_ipc_requests:
                return {"status": "error", "msg": "Duplicate request already pending"}
        
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_INSTANCES
        
        usp_msg.body.request.get_instances.obj_paths.append(obj_path)
        usp_msg.body.request.get_instances.first_level_only = False
        
        # If wait_response, register for response tracking
        result_queue = None
        if wait_response:
            result_queue = queue.Queue()
            self.stomp.pending_ipc_requests[msg_id] = {
                'endpoint': endpoint,
                'command': 'get_instances',
                'path': obj_path,
                'result_queue': result_queue,
                'timestamp': datetime.now()
            }
            self.stomp.pending_requests[request_key] = msg_id
        
        success = self._send_usp_message(endpoint, usp_msg)
        
        if not success:
            if wait_response and msg_id in self.stomp.pending_ipc_requests:
                del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
            return None if wait_response else False
        
        # Wait for response if requested
        if wait_response:
            try:
                result = result_queue.get(timeout=timeout)
                # Clean up tracking
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return result
            except queue.Empty:
                # Timeout - clean up
                if msg_id in self.stomp.pending_ipc_requests:
                    del self.stomp.pending_ipc_requests[msg_id]
                if request_key in self.stomp.pending_requests:
                    del self.stomp.pending_requests[request_key]
                return {"status": "timeout", "msg": f"No response after {timeout}s"}
        
        return True
    
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
    
    # Check configuration validity - exit only in non-daemon mode
    global DEBUG_LEVEL, CONTROLLER_ENDPOINT_ID, BROKER_HOST, BROKER_PORT, REPLY_TO_QUEUE, CONFIG_VALID
    
    if not CONFIG_VALID:
        if args.daemon:
            print("[!] Warning: Configuration invalid. Starting daemon to allow GUI configuration access.")
        else:
            print("[!] Critical: Configuration invalid. Cannot start in interactive mode.")
            print("[!] Please fix config.json or run in daemon mode (--daemon) to use GUI.")
            sys.exit(1)
    
    if args.debug is not None:
        DEBUG_LEVEL = args.debug
    
    # Show current debug level
    debug_names = ["Agent Only", "Both Payloads", "Full Details"]
    print(f"[*] Debug Level: {DEBUG_LEVEL} ({debug_names[DEBUG_LEVEL]})")
    
    if args.endpoint_id:
        CONTROLLER_ENDPOINT_ID = args.endpoint_id
        REPLY_TO_QUEUE = f'/queue/{CONTROLLER_ENDPOINT_ID}'
        print(f"[*] Controller Endpoint ID overridden: {CONTROLLER_ENDPOINT_ID}")
    
    if args.broker:
        if MINI_BROKER_ENABLED:
            print(f"[!] Warning: Mini-Broker enabled, cannot modify broker config via command line")
            print(f"[!] Currently using: {BROKER_HOST}:{BROKER_PORT}")
        else:
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
            print("[!] Warning: Could not clean up old daemon, but continuing anyway...")
            print("[!] If port conflicts occur, the new daemon may fail to bind IPC port.")
            # Don't exit - try to start anyway. IPC bind failure will be caught later.
    
    # Display configuration information
    sys.stdout.flush()  # Ensure previous output is visible
    print(f"[*] Controller: {CONTROLLER_ENDPOINT_ID}")
    print(f"[*] Broker: {BROKER_HOST}:{BROKER_PORT}")
    print(f"[*] Receive Topic: {RECEIVE_TOPIC}")
    sys.stdout.flush()
    
    # Init STOMP (skip if config is invalid)
    stomp_mgr = STOMPManager()
    if CONFIG_VALID and not stomp_mgr.connect():
        if args.daemon:
            print("[!] Warning: STOMP connection failed. Starting daemon anyway to allow IPC access.")
        else:
            print("[!] Critical: STOMP connection failed. Exiting.")
            sys.exit(1)
    elif not CONFIG_VALID:
        print("[!] Warning: Configuration invalid. STOMP connection skipped.")
        if args.daemon:
            print("[!] IPC server will start. Use GUI to fix configuration and reconnect.")
    
    # Start mDNS discovery if enabled and connected
    if CONFIG_VALID and stomp_mgr.connected and ENABLE_MDNS_DISCOVERY:
        stomp_mgr.start_mdns_discovery()
    
    # Start IPC Server only in daemon mode
    ipc_server = None
    if args.daemon:
        # Write PID file
        write_pid_file()
        atexit.register(remove_pid_file)
        
        ipc_server = IPCServer(stomp_mgr)
        ipc_server.start()
        
        # Wait for IPC server to start (or fail)
        time.sleep(0.5)
        
        sys.stdout.flush()  # Ensure previous output is visible
        print("="*60)
        print(f"[OK] USP Controller Daemon Started")
        print(f"[OK] PID: {os.getpid()}")
        
        # Check IPC server status
        if ipc_server.started:
            print(f"[OK] IPC Server: {IPC_HOST}:{IPC_PORT}")
        elif ipc_server.error:
            print(f"[ERROR] IPC Server failed to start: {ipc_server.error}")
            print(f"[WARNING] GUI will not be able to connect!")
            if "already in use" in str(ipc_server.error).lower() or "98" in str(ipc_server.error):
                print(f"[TIP] Port {IPC_PORT} is already in use. Kill old daemon or change port in config.json")
        else:
            print(f"[WARNING] IPC Server status unknown")
        
        # Show STOMP status
        if stomp_mgr.connected:
            print(f"[OK] STOMP Broker: {BROKER_HOST}:{BROKER_PORT}")
        else:
            print(f"[WARNING] STOMP Broker: NOT CONNECTED")
            print(f"[INFO] Use GUI to fix configuration and reconnect")
        
        print("="*60)
        print("[WARNING] This is a background daemon process")
        print("[WARNING] DO NOT close this window - GUI depends on it")
        print("[INFO] You can minimize this window safely")
        print("="*60)
        print("")
        sys.stdout.flush()  # Force output to display
        
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
