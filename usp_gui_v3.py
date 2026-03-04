#!/usr/bin/env python3
"""
USP Controller GUI - Multi-Page Architecture
Embedded mode: Runs CLI, Daemon, and Broker management in single process
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import queue
import json
import sys
import os
import socket
import time
import subprocess
import atexit
import re
from pathlib import Path
from datetime import datetime
from usp_version import FULL_VERSION, GUI_VERSION

# Constants
HISTORY_FILE = 'command_history.json'
MAX_HISTORY = 50
IPC_HOST = '127.0.0.1'
IPC_PORT = 6001


class ConfigManager:
    """Centralized configuration management with caching"""
    _instance = None
    _config_cache = None
    _cache_time = 0
    _cache_ttl = 5  # Cache valid for 5 seconds
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def get_config(self, ipc_client=None, force_reload=False):
        """Get configuration with caching strategy
        
        Priority:
        1. If force_reload: skip cache
        2. If cache is fresh (< TTL): use cache
        3. Try IPC (if daemon running)
        4. Fallback to file
        """
        current_time = time.time()
        
        # Return cached config if fresh and not forcing reload
        if not force_reload and self._config_cache and (current_time - self._cache_time < self._cache_ttl):
            return self._config_cache
        
        config = None
        
        # Try IPC first if client provided
        if ipc_client:
            try:
                resp = ipc_client.send_command('get_config')
                if resp and resp.get('status') == 'ok':
                    config = resp.get('config', {})

                    # Normalize legacy flat config shape from daemon
                    if isinstance(config, dict) and 'usp_controller' not in config:
                        controller_id = config.get('controller_endpoint_id') or config.get('controller_id', '')
                        config['usp_controller'] = {
                            'controller_endpoint_id': controller_id,
                            'receive_topic': config.get('receive_topic', ''),
                            'broker_host': config.get('broker_host', ''),
                            'broker_port': config.get('broker_port', ''),
                            'username': config.get('username', ''),
                        }
                        ipc_port = config.get('ipc_port')
                        if ipc_port:
                            config['ipc'] = {
                                'host': config.get('ipc_host', '127.0.0.1'),
                                'port': ipc_port,
                            }
            except:
                pass
        
        # Fallback to file if IPC failed
        if not config:
            from usp_core import load_config as load_config_from_file
            config = load_config_from_file() or {}
        
        # Update cache
        self._config_cache = config
        self._cache_time = current_time
        
        return config
    
    def invalidate_cache(self):
        """Force cache invalidation (e.g., after config save)"""
        self._cache_time = 0


class IPCClient:
    """IPC Client for communicating with daemon"""
    def __init__(self, host=IPC_HOST, port=IPC_PORT):
        # Strict type validation to avoid WinError 10022
        self.host = str(host) if host else '127.0.0.1'
        
        # Validate and convert port
        try:
            self.port = int(port)
            if not (1 <= self.port <= 65535):
                raise ValueError(f"Port {self.port} out of range (1-65535)")
        except (ValueError, TypeError) as e:
            print(f"[!] Invalid IPC port: {port!r} - using default 6001")
            self.port = 6001
    
    def send_command(self, cmd):
        """Send command string and return JSON response. Blocking call."""
        try:
            timeout_seconds = self._resolve_timeout(cmd)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_seconds)
            
            # Validate before connect  
            if not isinstance(self.host, str) or not self.host:
                raise ValueError(f"Invalid host: {self.host!r}")
            if not isinstance(self.port, int):
                raise ValueError(f"Invalid port type: {type(self.port)}")
            
            s.connect((self.host, self.port))
            s.sendall(cmd.encode('utf-8'))
            
            # Receive data in chunks until complete
            data_chunks = []
            while True:
                chunk = s.recv(65536)  # 64KB chunks
                if not chunk:
                    break
                data_chunks.append(chunk)
                # Check if we got complete JSON (ends with })
                if chunk.endswith(b'}'):
                    break
            
            s.close()
            
            if not data_chunks:
                return None
                
            data = b''.join(data_chunks).decode('utf-8')
            return json.loads(data)
        except socket.timeout:
            return {"status": "error", "msg": f"Connection timeout ({int(timeout_seconds)}s) - daemon may be busy"}
        except ConnectionRefusedError:
            return None
        except ConnectionResetError:
            return {"status": "error", "msg": "Connection reset by daemon"}
        except json.JSONDecodeError as e:
            return {"status": "error", "msg": f"Invalid response from daemon: {e}"}
        except OSError as e:
            # Catch Windows socket errors
            error_msg = f"Socket error: {e}"
            if hasattr(e, 'winerror'):
                error_msg += f" (WinError {e.winerror})"
            print(f"[!] IPC Error: {error_msg}")
            print(f"[!] Connection details: host={self.host!r} ({type(self.host)}), port={self.port!r} ({type(self.port)})")
            return {"status": "error", "msg": error_msg}
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"[!] IPC Error: {e}")
            print(error_details)
            return {"status": "error", "msg": f"{type(e).__name__}: {str(e)}"}

    def _resolve_timeout(self, cmd):
        """Resolve IPC socket timeout with buffer to avoid racing daemon-side wait timeout."""
        default_timeout = 45.0
        buffer_seconds = 15.0

        try:
            text = (cmd or "").strip()
            if not text:
                return default_timeout

            parts = text.split()
            if '--timeout' in parts:
                idx = parts.index('--timeout')
                if idx + 1 < len(parts):
                    requested = float(parts[idx + 1])
                    return max(default_timeout, requested + buffer_seconds)

            verb = parts[0].lower()
            if verb in {'get', 'set', 'get_instances'}:
                return default_timeout
        except Exception:
            pass

        return default_timeout

# Add tools directory for embedded broker
sys.path.insert(0, str(Path(__file__).parent / "tools"))
try:
    from embedded_broker import EmbeddedBroker
    BROKER_AVAILABLE = True
except ImportError:
    BROKER_AVAILABLE = False

# Import core modules
from usp_core import load_config, save_config, validate_config, DEFAULT_CONFIG

# Hide console window on Windows
if sys.platform == 'win32':
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)


class BrokerPage(ttk.Frame):
    """Mini Broker Management Page - Only for embedded mini-broker"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.broker = None
        self.broker_thread = None
        self.broker_running = False
        self.debug_auto_refresh = tk.BooleanVar(value=True)
        self._last_subscription_signature = None
        
        # Use centralized config manager
        self.config_manager = ConfigManager()
        self.config = self.config_manager.get_config()
        
        self._create_widgets()
        self.after(1500, self._poll_broker_debug)
    
    def _create_widgets(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(title_frame, text="Mini STOMP Broker (Embedded)", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        
        # Info
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(info_frame, text="💡 Mini Broker用於測試環境，無需外部broker", 
                 font=('Arial', 9), foreground='blue').pack(anchor=tk.W)
        ttk.Label(info_frame, text="💡 支援即時狀態監控與測試訊息注入（debug）", 
             font=('Arial', 9), foreground='#666').pack(anchor=tk.W)
        
        # Configuration
        config_frame = ttk.LabelFrame(self, text="Mini Broker 設定", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Host
        host_row = ttk.Frame(config_frame)
        host_row.pack(fill=tk.X, pady=5)
        ttk.Label(host_row, text="Listen Host:", width=15).pack(side=tk.LEFT)
        self.host_entry = ttk.Entry(host_row, width=25)
        default_host = self.config.get('mini_broker', {}).get('host', '0.0.0.0')
        self.host_entry.insert(0, default_host)
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        # Port
        port_row = ttk.Frame(config_frame)
        port_row.pack(fill=tk.X, pady=5)
        ttk.Label(port_row, text="Listen Port:", width=15).pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(port_row, width=25)
        default_port = self.config.get('mini_broker', {}).get('port', 61613)
        self.port_entry.insert(0, str(default_port))
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Mini Broker", command=self._start_broker)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self._stop_broker, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="Refresh Status", command=self._refresh_broker_status).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Show Snapshot", command=self._show_broker_snapshot).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(btn_frame, text="Auto Debug Refresh", variable=self.debug_auto_refresh).pack(side=tk.RIGHT, padx=5)

        # Broker runtime status
        status_frame = ttk.LabelFrame(self, text="Runtime Status", padding=10)
        status_frame.pack(fill=tk.X, padx=10, pady=5)

        self.broker_state_label = ttk.Label(status_frame, text="State: ⚪ Stopped", font=('Arial', 9, 'bold'))
        self.broker_state_label.pack(side=tk.LEFT, padx=(0, 15))

        self.clients_label = ttk.Label(status_frame, text="Clients: 0", font=('Arial', 9))
        self.clients_label.pack(side=tk.LEFT, padx=10)

        self.subscriptions_label = ttk.Label(status_frame, text="Subscriptions: 0", font=('Arial', 9))
        self.subscriptions_label.pack(side=tk.LEFT, padx=10)

        self.queued_label = ttk.Label(status_frame, text="Queued Msgs: 0", font=('Arial', 9))
        self.queued_label.pack(side=tk.LEFT, padx=10)

        # Debug tools
        debug_tools_frame = ttk.LabelFrame(self, text="Debug Tools", padding=10)
        debug_tools_frame.pack(fill=tk.X, padx=10, pady=5)

        test_msg_row = ttk.Frame(debug_tools_frame)
        test_msg_row.pack(fill=tk.X, pady=2)
        ttk.Label(test_msg_row, text="Destination:", width=12).pack(side=tk.LEFT)
        self.test_destination_entry = ttk.Entry(test_msg_row, width=32)
        self.test_destination_entry.insert(0, "/topic/test")
        self.test_destination_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(test_msg_row, text="Body:", width=6).pack(side=tk.LEFT)
        self.test_body_entry = ttk.Entry(test_msg_row, width=32)
        self.test_body_entry.insert(0, "hello from mini-broker debug")
        self.test_body_entry.pack(side=tk.LEFT, padx=5)

        ttk.Button(test_msg_row, text="Send Test Msg", command=self._send_test_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(test_msg_row, text="Clear Log", command=self._clear_broker_log).pack(side=tk.LEFT, padx=5)
        
        # Status/Log
        log_frame = ttk.LabelFrame(self, text="Status & Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED, 
                                                      bg='#f0f0f0', font=('Courier', 9))
        self.status_text.pack(fill=tk.BOTH, expand=True)
        
        self._log("Mini Broker ready to start")
        self._log("Note: Agents will connect to this broker instead of external broker")
        self._refresh_broker_status()
        
    
    def _start_broker(self):
        """Start mini broker"""
        if not BROKER_AVAILABLE:
            messagebox.showerror("Error", "Mini-Broker module not available")
            self._log("ERROR: embedded_broker module not found")
            return
        
        if self.broker_running:
            messagebox.showinfo("Info", "Broker is already running")
            return
        
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            # Save mini_broker config to config.json
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, 'config.json')
            full_config = load_config(config_file) or {}
            
            if 'mini_broker' not in full_config:
                full_config['mini_broker'] = {}
            
            full_config['mini_broker']['host'] = host
            full_config['mini_broker']['port'] = port
            full_config['mini_broker']['enable'] = True
            
            save_config(full_config, config_file)
            
            self._log(f"Starting Mini-Broker on {host}:{port}...")
            self._log(f"Saved Mini-Broker config: {host}:{port}")
            
            self.broker = EmbeddedBroker(host=host, port=port)
            
            def run_broker():
                try:
                    self.broker.start()
                    self.broker_running = True
                except Exception as e:
                    self._log(f"ERROR: Broker failed - {e}")
                    self.broker_running = False
            
            self.broker_thread = threading.Thread(target=run_broker, daemon=True)
            self.broker_thread.start()
            
            # Wait a bit to check if it started
            self.after(1000, self._check_broker_started)
            
        except ValueError:
            self._log("❌ Invalid port number", 'error')
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            self._log(f"❌ Failed to start broker: {e}", 'error')
            messagebox.showerror("Error", f"Failed to start broker: {e}")
    
    def _check_broker_started(self):
        """Check if broker started successfully"""
        if self.broker_running:
            self._log("✅ Mini-Broker started successfully")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.broker_state_label.config(text="State: ✅ Running", foreground='green')
            self._last_subscription_signature = self._get_subscription_signature()
            self._show_broker_snapshot()
        else:
            self._log("❌ Mini-Broker failed to start")
            self.broker_state_label.config(text="State: ❌ Failed", foreground='red')
    
    def _stop_broker(self):
        """Stop mini broker"""
        if self.broker:
            self._log("Stopping Mini-Broker...")
            try:
                self.broker.stop()
                self.broker_running = False
                self._last_subscription_signature = None
                self._log("✅ Mini-Broker stopped")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.broker_state_label.config(text="State: ⚪ Stopped", foreground='#666')
                self._refresh_broker_status()
            except Exception as e:
                self._log(f"ERROR: {e}")

    def _get_subscription_signature(self):
        """Get subscription-only signature for auto snapshot trigger."""
        if not self.broker_running or not self.broker:
            return ("stopped",)

        try:
            with self.broker.lock:
                subscriber_map = tuple(sorted(
                    (dest, len(subs)) for dest, subs in self.broker.subscribers.items() if subs
                ))

            return (
                "running",
                subscriber_map,
            )
        except Exception:
            return ("error",)

    def _refresh_broker_status(self):
        """Refresh runtime broker metrics"""
        try:
            if not self.broker_running or not self.broker:
                self.clients_label.config(text="Clients: 0")
                self.subscriptions_label.config(text="Subscriptions: 0")
                self.queued_label.config(text="Queued Msgs: 0")
                if not self.broker_running:
                    self.broker_state_label.config(text="State: ⚪ Stopped", foreground='#666')
                return

            with self.broker.lock:
                client_count = len(self.broker.clients)
                subscription_count = sum(len(v) for v in self.broker.subscribers.values())
                queued_count = sum(len(v) for v in self.broker.destinations.values())

            self.clients_label.config(text=f"Clients: {client_count}")
            self.subscriptions_label.config(text=f"Subscriptions: {subscription_count}")
            self.queued_label.config(text=f"Queued Msgs: {queued_count}")
            self.broker_state_label.config(text="State: ✅ Running", foreground='green')
        except Exception as e:
            self._log(f"[DEBUG] status refresh error: {e}")

    def _show_broker_snapshot(self):
        """Print detailed broker state snapshot to log"""
        if not self.broker_running or not self.broker:
            self._log("[DEBUG] Broker snapshot unavailable: broker is not running")
            return

        try:
            with self.broker.lock:
                clients = list(self.broker.clients)
                subscriber_map = {dest: len(subs) for dest, subs in self.broker.subscribers.items() if subs}
                queued_map = {dest: len(msgs) for dest, msgs in self.broker.destinations.items() if msgs}

            self._log("[DEBUG] ===== Mini-Broker Snapshot =====")
            self._log(f"[DEBUG] Clients: {len(clients)}")
            for idx, client in enumerate(clients, start=1):
                self._log(f"[DEBUG]   #{idx} {client.addr} | session={client.session_id} | subs={len(client.subscriptions)}")

            if subscriber_map:
                self._log("[DEBUG] Active subscriptions:")
                for dest, count in subscriber_map.items():
                    self._log(f"[DEBUG]   {dest} -> {count} subscriber(s)")
            else:
                self._log("[DEBUG] Active subscriptions: none")

            if queued_map:
                self._log("[DEBUG] Queued messages:")
                for dest, count in queued_map.items():
                    self._log(f"[DEBUG]   {dest} -> {count} message(s)")
            else:
                self._log("[DEBUG] Queued messages: none")

            self._log("[DEBUG] =================================")
            self._refresh_broker_status()
        except Exception as e:
            self._log(f"[DEBUG] snapshot error: {e}")

    def _send_test_message(self):
        """Inject a test message into broker for debug validation"""
        if not self.broker_running or not self.broker:
            messagebox.showwarning("Broker Not Running", "Start Mini-Broker first.")
            return

        destination = self.test_destination_entry.get().strip()
        body = self.test_body_entry.get().strip()

        if not destination:
            messagebox.showwarning("Invalid Destination", "Destination cannot be empty.")
            return

        try:
            payload = body.encode('utf-8') if body else b''

            with self.broker.lock:
                subscribers = list(self.broker.subscribers.get(destination, []))
                if subscribers:
                    for subscriber in subscribers:
                        self.broker._send_message_to_client(subscriber, destination, payload)
                else:
                    self.broker.destinations[destination].append(payload)

            self._log(f"[DEBUG] Test message sent to {destination} ({len(payload)} bytes)")
            self._refresh_broker_status()
        except Exception as e:
            self._log(f"[DEBUG] Failed to send test message: {e}")

    def _clear_broker_log(self):
        """Clear broker status log"""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.status_text.config(state=tk.DISABLED)
        self._log("Broker log cleared")

    def _poll_broker_debug(self):
        """Periodic broker status polling"""
        try:
            if self.debug_auto_refresh.get():
                self._refresh_broker_status()

                signature = self._get_subscription_signature()
                if signature != self._last_subscription_signature:
                    self._last_subscription_signature = signature
                    self._log("[DEBUG] Subscription changed, auto snapshot dump")
                    self._show_broker_snapshot()
        except Exception:
            pass
        self.after(1500, self._poll_broker_debug)
    
    def _log(self, message):
        """Log message to status text"""
        self.status_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)


class DaemonPage(ttk.Frame):
    """Daemon Management Page - Simplified to work only with Mini Broker"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.ipc = IPCClient()  # IPC client for daemon communication
        self.daemon_process = None  # Daemon subprocess
        self.output_reader = None  # Output reader thread
        self.output_reader_running = False  # Output reader control flag
        self.controls_visible = True
        self.daemon_start_retry_count = 0
        self.daemon_start_max_retries = 5
        self.show_config_controls = False
        
        # Use centralized config manager
        self.config_manager = ConfigManager()
        
        self._create_widgets()
        
        # Start background status updater
        self.polling = True
        self.poll_thread = threading.Thread(target=self._status_poller, daemon=True)
        self.poll_thread.start()
        
        # Perform initial status check
        self.after(500, self._initial_status_check)
    
    def _initial_status_check(self):
        """Perform initial status check and provide guidance"""
        try:
            resp = self.ipc.send_command('status')
            if resp and resp.get('status') == 'ok':
                self._log("✅ Daemon is already running", 'success')
                if not resp.get('broker_connected'):
                    self._log("⚠️ Daemon is not connected to broker", 'warning')
                    self._log("💡 Use 'Connect' button to connect to Mini-Broker", 'info')
                else:
                    self._log("✅ Daemon is connected to broker", 'success')
            else:
                self._log("ℹ️ No daemon detected", 'info')
                self._log("💡 Start daemon from this page or run externally", 'info')
        except:
            self._log("ℹ️ No daemon detected", 'info')
            self._log("💡 Click 'Start Daemon' to begin", 'info')
    
    def _status_poller(self):
        """Background thread to poll daemon and broker status"""
        while self.polling:
            try:
                self._update_status()
            except:
                pass
            
            import time
            time.sleep(1.5)  # Poll every 1.5 seconds
    
    def _create_widgets(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(title_frame, text="Daemon Management", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        self.toggle_config_btn = ttk.Button(title_frame, text="Show Config", command=self._toggle_config_controls)
        self.toggle_config_btn.pack(side=tk.RIGHT, padx=(5, 0))
        self.toggle_controls_btn = ttk.Button(title_frame, text="Show Controls", command=self._toggle_controls)
        self.toggle_controls_btn.pack(side=tk.RIGHT)
        
        # Info banner - dynamically show broker port from config
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, padx=10, pady=(0,5))
        
        # Get mini broker port from config manager
        config = self.config_manager.get_config(self.ipc)
        broker_port = config.get('mini_broker', {}).get('port', 61613)
        
        ttk.Label(info_frame, text=f"💡 Daemon自動連接到Mini Broker (localhost:{broker_port})", 
                 font=('Arial', 9), foreground='blue').pack(anchor=tk.W)
        
        # Top control area (collapsible to reserve more space for output)
        self.top_controls_frame = ttk.Frame(self)
        self.top_controls_frame.pack(fill=tk.X, padx=10, pady=5)

        # Compact Status Display (side-by-side)
        status_display_frame = ttk.LabelFrame(self.top_controls_frame, text="Status", padding=10)
        status_display_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Single line with statuses
        self.daemon_status_label = ttk.Label(status_display_frame, text="Daemon: ⚪ Checking", font=('Arial', 9, 'bold'))
        self.daemon_status_label.pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Separator(status_display_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        self.broker_status_label = ttk.Label(status_display_frame, text="Mini-Broker: ⚪ Unknown", font=('Arial', 9, 'bold'))
        self.broker_status_label.pack(side=tk.LEFT)
        
        # Daemon Process + Diagnostics (merged)
        daemon_control_frame = ttk.LabelFrame(self.top_controls_frame, text="Daemon Process & Diagnostics", padding=10)
        daemon_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        daemon_btn_frame = ttk.Frame(daemon_control_frame)
        daemon_btn_frame.pack(fill=tk.X)
        
        self.start_btn = ttk.Button(daemon_btn_frame, text="Start Daemon", command=self._start_daemon)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.force_stop_btn = ttk.Button(daemon_btn_frame, text="🚫 Stop Daemon (Force)", command=self._force_stop_daemon, state=tk.DISABLED)
        self.force_stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.restart_btn = ttk.Button(daemon_btn_frame, text="🔄 Restart Daemon", command=self._restart_daemon, state=tk.DISABLED)
        self.restart_btn.pack(side=tk.LEFT, padx=5)

        # Config controls (hidden by default, toggled via Show Config button)
        self.config_controls_frame = ttk.Frame(self.top_controls_frame)

        config_button_row = ttk.Frame(self.config_controls_frame)
        config_button_row.pack(fill=tk.X, padx=10, pady=(0, 5))
        ttk.Separator(config_button_row, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, pady=(0, 6))
        ttk.Button(config_button_row, text="Reload Config", command=self._reload_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_button_row, text="📝 Advanced...", command=self._view_config).pack(side=tk.LEFT, padx=5)

        self.quick_settings_frame = ttk.LabelFrame(self.config_controls_frame, text="Daemon Quick Settings", padding=10)
        self.quick_settings_frame.pack(fill=tk.X, padx=10, pady=5)

        row1 = ttk.Frame(self.quick_settings_frame)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Controller ID:", width=14).pack(side=tk.LEFT)
        self.daemon_controller_id_entry = ttk.Entry(row1, width=42)
        self.daemon_controller_id_entry.pack(side=tk.LEFT, padx=5)

        row2 = ttk.Frame(self.quick_settings_frame)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="IPC Host:", width=14).pack(side=tk.LEFT)
        self.daemon_ipc_host_entry = ttk.Entry(row2, width=22)
        self.daemon_ipc_host_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(row2, text="IPC Port:", width=10).pack(side=tk.LEFT)
        self.daemon_ipc_port_entry = ttk.Entry(row2, width=10)
        self.daemon_ipc_port_entry.pack(side=tk.LEFT, padx=5)

        row3 = ttk.Frame(self.quick_settings_frame)
        row3.pack(fill=tk.X, pady=(6, 2))
        ttk.Button(row3, text="💾 Save Settings", command=self._save_daemon_quick_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="💾 Save + Reload", command=lambda: self._save_daemon_quick_settings(reload_daemon=True)).pack(side=tk.LEFT, padx=5)

        self._load_daemon_quick_settings()
        
        # Diagnostic tools
        ttk.Separator(daemon_control_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        diag_frame = ttk.Frame(daemon_control_frame)
        diag_frame.pack(fill=tk.X)
        
        ttk.Label(diag_frame, text="Diagnostics:", font=('Arial', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        ttk.Button(diag_frame, text="🔍 Test IPC", command=self._test_ipc).pack(side=tk.LEFT, padx=5)
        ttk.Button(diag_frame, text="📊 Show Status", command=self._show_detailed_status).pack(side=tk.LEFT, padx=5)
        
        # Broker Connection Control
        broker_control_frame = ttk.LabelFrame(self.top_controls_frame, text="Mini-Broker Connection Control", padding=10)
        broker_control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        broker_btn_frame = ttk.Frame(broker_control_frame)
        broker_btn_frame.pack(fill=tk.X)
        
        ttk.Button(broker_btn_frame, text="▶️ Connect", command=self._connect_broker).pack(side=tk.LEFT, padx=5)
        ttk.Button(broker_btn_frame, text="⏹️ Disconnect", command=self._disconnect_broker).pack(side=tk.LEFT, padx=5)
        ttk.Button(broker_btn_frame, text="🔄 Restart", command=self._restart_broker).pack(side=tk.LEFT, padx=5)
        
        # Daemon Output Display
        output_frame = ttk.LabelFrame(self, text="Daemon Output (Real-time)", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        output_header = ttk.Frame(output_frame)
        output_header.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(output_header, text="Clear Output", command=self._clear_output).pack(side=tk.RIGHT)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=10,
            bg='#000000',
            fg='#00ff00',
            font=('Consolas', 9),
            wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Add context menu for output text
        self._add_output_context_menu()
        
        # Initial messages
        self._log("Daemon control panel initialized", 'info')
        self._log("Click 'Start Daemon' to launch daemon process", 'info')
        self._log("", 'info')
        self._log("💡 Tips:", 'info')
        self._log("  - Use '🔍 Test IPC' to verify daemon connection", 'info')
        self._log("  - Use '📊 Show Status' to see detailed daemon info", 'info')
        self._log("  - Daemon must be running for CLI commands to work", 'info')
        self._apply_config_controls_visibility()
        self._apply_controls_visibility()

    def _toggle_controls(self):
        """Toggle visibility of top control area to maximize output space"""
        self.controls_visible = not self.controls_visible
        self._apply_controls_visibility()

    def _toggle_config_controls(self):
        """Toggle hidden config controls on daemon page."""
        self.show_config_controls = not self.show_config_controls
        self._apply_config_controls_visibility()

    def _apply_config_controls_visibility(self):
        """Apply visibility state of config controls section."""
        if self.show_config_controls:
            self.config_controls_frame.pack(fill=tk.X, padx=0, pady=0)
            self.toggle_config_btn.config(text="Hide Config")
        else:
            self.config_controls_frame.pack_forget()
            self.toggle_config_btn.config(text="Show Config")

    def _apply_controls_visibility(self):
        """Apply control area visibility state"""
        if self.controls_visible:
            self.top_controls_frame.pack(fill=tk.X, padx=10, pady=5, before=self.output_text.master.master)
            self.toggle_controls_btn.config(text="Hide Controls")
        else:
            self.top_controls_frame.pack_forget()
            self.toggle_controls_btn.config(text="Show Controls")
    
    def _add_output_context_menu(self):
        """Add context menu to output text widget"""
        menu = tk.Menu(self.output_text, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self.output_text.event_generate("<<Copy>>"))
        menu.add_command(label="Select All", command=lambda: self.output_text.tag_add(tk.SEL, "1.0", tk.END))
        menu.add_separator()
        menu.add_command(label="Clear", command=self._clear_output)
        
        def show_menu(event):
            menu.post(event.x_root, event.y_root)
        
        self.output_text.bind("<Button-3>", show_menu)
    
    def _update_status(self):
        """Update daemon and mini-broker status"""
        try:
            resp = self.ipc.send_command('status')
            if resp and resp.get('status') == 'ok':
                # Daemon status
                self.daemon_status_label.config(text="Daemon: ✅ Running", foreground='green')
                self.start_btn.config(state=tk.DISABLED)
                self.force_stop_btn.config(state=tk.NORMAL)
                self.restart_btn.config(state=tk.NORMAL)
                
                # Mini-Broker connection status (daemon connects to it)
                broker_connected = resp.get('broker_connected', False)
                
                if broker_connected:
                    self.broker_status_label.config(
                        text="Mini-Broker: ✅ Connected",
                        foreground='green'
                    )
                else:
                    self.broker_status_label.config(
                        text="Mini-Broker: ❌ Not Connected",
                        foreground='red'
                    )
            else:
                # Daemon not reachable
                self.daemon_status_label.config(text="Daemon: ❌ Not Running", foreground='red')
                self.broker_status_label.config(text="Mini-Broker: ⚪ Unknown", foreground='gray')
                self.start_btn.config(state=tk.NORMAL)
                self.force_stop_btn.config(state=tk.DISABLED)
                self.restart_btn.config(state=tk.DISABLED)
        except:
            self.daemon_status_label.config(text="Daemon: ❌ Not Running", foreground='red')
            self.broker_status_label.config(text="Mini-Broker: ⚪ Unknown", foreground='gray')
            self.start_btn.config(state=tk.NORMAL)
            self.force_stop_btn.config(state=tk.DISABLED)
            self.restart_btn.config(state=tk.DISABLED)
    
    def _reload_config(self):
        """Reload configuration via IPC"""
        try:
            resp = self.ipc.send_command('reload_config')
            
            # Handle no response
            if resp is None:
                self._log("❌ Daemon not responding (connection refused)", 'error')
                messagebox.showerror("Error", "Daemon not responding (connection refused)")
                return
            
            # Handle error response
            if resp.get('status') != 'ok':
                error_msg = resp.get('msg', 'Reload failed')
                self._log(f"❌ {error_msg}", 'error')
                messagebox.showerror("Error", error_msg)
            else:
                # Success - invalidate config cache
                self.config_manager.invalidate_cache()
                self._load_daemon_quick_settings()
                success_msg = resp.get('msg', 'Config reloaded')
                messagebox.showinfo("Success", success_msg)
            
            self._update_status()
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            self._log(f"❌ Reload config error: {e}", 'error')
            print(f"[!] Reload config error: {e}")
            print(error_details)
            messagebox.showerror("Error", f"Failed to reload config: {e}")

    def _load_daemon_quick_settings(self):
        """Load daemon quick settings from config"""
        try:
            config = self.config_manager.get_config(self.ipc, force_reload=True) or {}
            usp_cfg = config.get('usp_controller', {})
            ipc_cfg = config.get('ipc', {})

            endpoint_id = (
                usp_cfg.get('controller_endpoint_id')
                or config.get('controller_endpoint_id')
                or config.get('controller_id', '')
            )
            ipc_host = ipc_cfg.get('host', '127.0.0.1')
            ipc_port = ipc_cfg.get('port', 6001)

            self.daemon_controller_id_entry.delete(0, tk.END)
            self.daemon_controller_id_entry.insert(0, endpoint_id)
            self.daemon_ipc_host_entry.delete(0, tk.END)
            self.daemon_ipc_host_entry.insert(0, str(ipc_host))
            self.daemon_ipc_port_entry.delete(0, tk.END)
            self.daemon_ipc_port_entry.insert(0, str(ipc_port))
            self._apply_ipc_target(ipc_host, ipc_port, log_change=False)
        except Exception as e:
            self._log(f"⚠️ Failed to load quick settings: {e}", 'warning')

    def _apply_ipc_target(self, host, port, log_change=True):
        """Apply IPC host/port to current IPC client."""
        try:
            target_host = str(host).strip() if host else '127.0.0.1'
            target_port = int(port)
            old_host = self.ipc.host
            old_port = self.ipc.port
            self.ipc.host = target_host
            self.ipc.port = target_port

            if log_change and (old_host != target_host or old_port != target_port):
                self._log(f"ℹ️ IPC target updated: {target_host}:{target_port}", 'info')
        except Exception as e:
            self._log(f"⚠️ Failed to apply IPC target: {e}", 'warning')

    def _save_daemon_quick_settings(self, reload_daemon=False):
        """Save daemon quick settings directly from page"""
        endpoint_id = self.daemon_controller_id_entry.get().strip()
        ipc_host = self.daemon_ipc_host_entry.get().strip() or '127.0.0.1'
        ipc_port_raw = self.daemon_ipc_port_entry.get().strip()

        if not endpoint_id:
            messagebox.showerror("Validation Error", "Controller ID cannot be empty")
            return

        try:
            ipc_port = int(ipc_port_raw)
            if not (1 <= ipc_port <= 65535):
                raise ValueError("out of range")
        except Exception:
            messagebox.showerror("Validation Error", "IPC Port must be a valid number between 1 and 65535")
            return

        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, 'config.json')
            full_config = load_config(config_file) or {}

            full_config.setdefault('usp_controller', {})
            full_config.setdefault('ipc', {})

            suffix = endpoint_id.split('::')[-1]
            full_config['usp_controller']['controller_endpoint_id'] = endpoint_id
            full_config['usp_controller']['receive_topic'] = f'/queue/usp.controller.{suffix}'

            full_config['ipc']['host'] = ipc_host
            full_config['ipc']['port'] = ipc_port

            # Keep top-level mirror for backward compatibility with legacy readers
            full_config['controller_endpoint_id'] = endpoint_id

            if not save_config(full_config, config_file):
                messagebox.showerror("Error", "Failed to save config.json")
                return

            self.config_manager.invalidate_cache()
            self._apply_ipc_target(ipc_host, ipc_port)
            self._log(f"✅ Settings saved (Controller ID: {endpoint_id}, IPC: {ipc_host}:{ipc_port})", 'success')

            if reload_daemon:
                resp = self.ipc.send_command('reload_config')
                if resp and resp.get('status') == 'ok':
                    messagebox.showinfo("Success", "Settings saved and daemon reloaded")
                else:
                    messagebox.showwarning("Partial Success", "Settings saved, but daemon reload failed (daemon may be offline)")
            else:
                messagebox.showinfo("Success", "Settings saved to config.json")
        except Exception as e:
            self._log(f"❌ Failed to save quick settings: {e}", 'error')
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def _connect_broker(self):
        """Connect to broker via IPC"""
        try:
            resp = self.ipc.send_command('start_broker')
            if resp:
                if resp.get('status') == 'ok':
                    messagebox.showinfo("Success", resp.get('msg', 'Connecting to Mini-Broker...'))
                else:
                    error_msg = resp.get('msg', 'Connection failed')
                    self._log(f"❌ Failed to connect to broker: {error_msg}", 'error')
                    messagebox.showerror("Error", f"Failed to connect to broker:\n\n{error_msg}")
            else:
                self._log("❌ Daemon not responding", 'error')
                messagebox.showerror("Error", 
                                   "Daemon not responding\n\n"
                                   "Possible causes:\n"
                                   "- Daemon not running (start from Daemon tab)\n"
                                   "- IPC connection issue (use 'Test IPC' button)")
            self._update_status()
        except Exception as e:
            self._log(f"❌ Failed to connect: {e}", 'error')
            messagebox.showerror("Error", f"Failed to connect: {e}")
    
    def _disconnect_broker(self):
        """Disconnect from broker via IPC"""
        try:
            resp = self.ipc.send_command('stop_broker')
            if resp:
                if resp.get('status') == 'ok':
                    messagebox.showinfo("Success", resp.get('msg', 'Disconnected from Mini-Broker'))
                else:
                    error_msg = resp.get('msg', 'Disconnect failed')
                    self._log(f"❌ {error_msg}", 'error')
                    messagebox.showerror("Error", error_msg)
            else:
                self._log("❌ Daemon not responding", 'error')
                messagebox.showerror("Error", "Daemon not responding")
            self._update_status()
        except Exception as e:
            self._log(f"❌ Failed to disconnect: {e}", 'error')
            messagebox.showerror("Error", f"Failed to disconnect: {e}")
    
    def _restart_broker(self):
        """Restart broker connection via IPC"""
        try:
            resp = self.ipc.send_command('restart_broker')
            if resp:
                if resp.get('status') == 'ok':
                    messagebox.showinfo("Success", resp.get('msg', 'Broker connection restarted'))
                else:
                    error_msg = resp.get('msg', 'Restart failed')
                    self._log(f"❌ {error_msg}", 'error')
                    messagebox.showerror("Error", error_msg)
            else:
                self._log("❌ Daemon not responding", 'error')
                messagebox.showerror("Error", "Daemon not responding")
            self._update_status()
        except Exception as e:
            self._log(f"❌ Failed to restart: {e}", 'error')
            messagebox.showerror("Error", f"Failed to restart: {e}")
    
    def _edit_config(self):
        """Open config editor dialog"""
        DaemonConfigEditorDialog(self, self.ipc, self.config_manager)
    
    def _view_config(self):
        """View full configuration in a read-only dialog"""
        ConfigViewDialog(self, self.ipc, self.config_manager)

    def _cleanup_existing_daemons_silent(self):
        """Kill existing usp_controller daemon processes before launching a new one."""
        try:
            if sys.platform != 'win32':
                return

            result = subprocess.run(
                ['wmic', 'process', 'where', 'CommandLine like "%usp_controller.py%--daemon%"', 'get', 'ProcessId'],
                capture_output=True,
                text=True,
                timeout=8
            )

            pids = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.isdigit():
                    pids.append(int(line))

            # Exclude current GUI-launched process object if already known and alive
            current_pid = self.daemon_process.pid if self.daemon_process else None
            killed = 0
            for pid in pids:
                if current_pid and pid == current_pid:
                    continue
                try:
                    kill_result = subprocess.run(
                        ['taskkill', '/F', '/PID', str(pid)],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if kill_result.returncode == 0:
                        killed += 1
                except Exception:
                    pass

            if killed > 0:
                self._log(f"🧹 Cleaned up {killed} existing daemon process(es)", 'info')
                # Give OS a short moment to release sockets/handles
                time.sleep(0.8)

        except Exception as e:
            self._log(f"⚠️ Pre-cleanup skipped: {e}", 'warning')
    
    def _start_daemon(self):
        """Start daemon process with output capture"""
        try:
            import subprocess
            import os

            # Prevent duplicate daemon instances and IPC port conflicts
            self._cleanup_existing_daemons_silent()
            
            # Get absolute path to usp_controller.py (same directory as this script)
            script_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(script_dir, 'usp_controller.py')
            
            if not os.path.exists(script_path):
                raise FileNotFoundError(f"usp_controller.py not found at: {script_path}")
            
            self._log(f"Starting daemon: {script_path}", 'info')
            
            # Start daemon with output pipes
            # Note: On Windows, we don't use CREATE_NEW_CONSOLE to capture output
            # The daemon runs in background and output is redirected to GUI
            self.daemon_process = subprocess.Popen(
                ['python', '-u', script_path, '--daemon', '--force'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',  # Replace invalid characters instead of failing
                bufsize=1,
                cwd=script_dir,  # Set working directory to script location
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            self._log("✅ Daemon process started (PID: {})".format(self.daemon_process.pid), 'success')
            self._log("Capturing daemon output...", 'info')
            
            # Start output reader thread
            self.output_reader_running = True
            self.output_reader = threading.Thread(target=self._output_reader_thread, daemon=True)
            self.output_reader.start()
            
            self.start_btn.config(state=tk.DISABLED)
            self.daemon_start_retry_count = 0
            
            # Wait for daemon to start and verify IPC
            self._log("⏳ Waiting for daemon initialization...", 'info')
            self.after(3000, self._verify_daemon_started)
        except FileNotFoundError as e:
            self._log(f"❌ {e}", 'error')
            messagebox.showerror("Error", str(e))
        except Exception as e:
            self._log(f"❌ Failed to start daemon: {e}", 'error')
            messagebox.showerror("Error", f"Failed to start daemon: {e}")
    
    def _verify_daemon_started(self):
        """Verify daemon started successfully and IPC is working"""
        try:
            resp = self.ipc.send_command('status')
            if resp and resp.get('status') == 'ok':
                self._log("✅ Daemon started successfully!", 'success')
                self._log(f"  - IPC Server: operational", 'success')
                self._log(f"  - Broker: {'connected' if resp.get('broker_connected') else 'not connected'}", 
                         'success' if resp.get('broker_connected') else 'warning')
                self._update_status()
                self.daemon_start_retry_count = 0
                return
        except:
            pass

        self.daemon_start_retry_count += 1

        if self.daemon_start_retry_count < self.daemon_start_max_retries:
            self._log(
                f"  Waiting for IPC server ({self.daemon_start_retry_count}/{self.daemon_start_max_retries})...",
                'info'
            )
            self.after(1000, self._verify_daemon_started)
        else:
            self._log("⚠️ Daemon started but IPC server not responding", 'warning')
            self._log("ℹ️ Check daemon console for errors", 'info')
            self._update_status()
            self.daemon_start_retry_count = 0
    
    def _stop_daemon(self):
        """Stop daemon process"""
        self._log("⏹️ Attempting to stop daemon...", 'info')
        
        # First try IPC shutdown command
        ipc_success = False
        try:
            resp = self.ipc.send_command('shutdown')
            if resp and resp.get('status') == 'ok':
                self._log("✅ Daemon shutdown command sent via IPC", 'success')
                ipc_success = True
                
                # Wait a moment for daemon to shutdown
                self.after(1000, self._verify_daemon_stopped)
                return
            else:
                self._log("⚠️ IPC shutdown returned unexpected response", 'warning')
        except ConnectionRefusedError:
            self._log("ℹ️ Daemon not responding (may already be stopped)", 'info')
        except Exception as e:
            self._log(f"⚠️ IPC shutdown failed: {e}", 'warning')
        
        # Fall back to process termination if daemon was started by GUI
        if self.daemon_process:
            try:
                # Stop output reader thread
                self.output_reader_running = False
                
                # Check if process is still running
                if self.daemon_process.poll() is None:
                    self._log("🔨 Terminating daemon process...", 'info')
                    self.daemon_process.terminate()
                    
                    # Wait for termination (with timeout)
                    try:
                        self.daemon_process.wait(timeout=5)
                        self._log("✅ Daemon process terminated", 'success')
                    except subprocess.TimeoutExpired:
                        self._log("⚠️ Daemon not responding, force killing...", 'warning')
                        self.daemon_process.kill()
                        self._log("✅ Daemon process killed", 'success')
                else:
                    self._log("ℹ️ Daemon process already exited", 'info')
                
                self.daemon_process = None
                self.force_stop_btn.config(state=tk.DISABLED)
                self.restart_btn.config(state=tk.DISABLED)
                self.start_btn.config(state=tk.NORMAL)
                self._update_status()
                
            except Exception as e:
                self._log(f"❌ Failed to stop daemon: {e}", 'error')
                messagebox.showerror("Error", f"Failed to stop daemon process: {e}")
        else:
            # Daemon not started by GUI - try to verify if it's really stopped
            self._log("ℹ️ Daemon was not started by GUI", 'info')
            self.after(1000, self._verify_daemon_stopped)
    
    def _force_stop_daemon(self):
        """Force stop daemon using PID file and taskkill"""
        self._log("🚫 Force stopping daemon...", 'warning')
        
        stopped = False
        
        # Method 1: Kill by PID file (same location as usp_controller.py uses)
        if sys.platform == 'win32':
            pid_file = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'usp_controller.pid')
        else:
            pid_file = '/tmp/usp_controller.pid'
        
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                self._log(f"📋 Found PID file: {pid}", 'info')
                
                if sys.platform == 'win32':
                    # Windows: use taskkill
                    result = subprocess.run(
                        ['taskkill', '/F', '/PID', str(pid)],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        self._log(f"✅ Process {pid} terminated", 'success')
                        stopped = True
                    else:
                        self._log(f"⚠️ taskkill failed: {result.stderr}", 'warning')
                else:
                    # Unix: use kill
                    import signal
                    try:
                        os.kill(pid, signal.SIGKILL)
                        self._log(f"✅ Process {pid} killed", 'success')
                        stopped = True
                    except ProcessLookupError:
                        self._log(f"ℹ️ Process {pid} not found", 'info')
                        stopped = True
                
                # Remove PID file
                try:
                    os.remove(pid_file)
                    self._log("🗑️ PID file removed", 'info')
                except Exception as e:
                    self._log(f"⚠️ Failed to remove PID file: {e}", 'warning')
                    
            except Exception as e:
                self._log(f"❌ Error reading PID file: {e}", 'error')
        else:
            self._log("ℹ️ No PID file found", 'info')
        
        # Method 2: Kill GUI-started process
        if self.daemon_process:
            try:
                self.output_reader_running = False
                
                if self.daemon_process.poll() is None:
                    self._log("🔨 Killing daemon process...", 'warning')
                    self.daemon_process.kill()
                    self.daemon_process.wait(timeout=3)
                    self._log("✅ Daemon process killed", 'success')
                    stopped = True
                    
                self.daemon_process = None
            except Exception as e:
                self._log(f"⚠️ Failed to kill process: {e}", 'warning')
        
        # Method 3: Kill all python processes running usp_controller.py (nuclear option)
        if not stopped and messagebox.askyesno(
            "Force Stop - Nuclear Option",
            "Kill all python processes running usp_controller.py?\n\n"
            "⚠️ This may affect other instances if running multiple controllers."
        ):
            try:
                if sys.platform == 'win32':
                    # Find and kill all usp_controller.py processes
                    result = subprocess.run(
                        ['wmic', 'process', 'where', 'CommandLine like "%usp_controller.py%"', 'get', 'ProcessId'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    pids = []
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and line.isdigit():
                            pids.append(line)
                    
                    if pids:
                        self._log(f"Found {len(pids)} usp_controller processes", 'info')
                        for pid in pids:
                            subprocess.run(['taskkill', '/F', '/PID', pid], capture_output=True, timeout=3)
                        self._log("✅ All processes terminated", 'success')
                        stopped = True
            except Exception as e:
                self._log(f"❌ Nuclear option failed: {e}", 'error')
        
        # Update UI
        self.daemon_process = None
        self.force_stop_btn.config(state=tk.DISABLED)
        self.restart_btn.config(state=tk.DISABLED)
        self.start_btn.config(state=tk.NORMAL)
        
        # Verify
        self.after(1500, self._verify_daemon_stopped)
        
        if stopped:
            self._log("✅ Daemon force stopped", 'success')
            messagebox.showinfo("Force Stop", "Daemon force stopped. Verify status in a moment.")
        else:
            self._log("❌ Force stop failed - requires manual intervention", 'error')
            messagebox.showwarning(
                "Force Stop Failed",
                "Could not force stop daemon.\n\n"
                "Please manually:\n"
                "1. Open Task Manager\n"
                "2. Find python.exe process running usp_controller.py\n"
                "3. End the process"
            )
    
    def _verify_daemon_stopped(self):
        """Verify daemon has stopped"""
        try:
            resp = self.ipc.send_command('status')
            if resp:
                self._log("⚠️ Daemon still running after stop attempt", 'warning')
                messagebox.showwarning(
                    "Daemon Still Running",
                    "Daemon is still responding.\n\n"
                    "Possible solutions:\n"
                    "1. If started externally: Close the daemon console window\n"
                    "2. Use Task Manager to end python process\n"
                    "3. Try '🚫 Force Stop' button"
                )
            else:
                self._log("✅ Daemon stopped successfully", 'success')
                self.daemon_process = None
                self.restart_btn.config(state=tk.DISABLED)
                self.start_btn.config(state=tk.NORMAL)
                self._update_status()
        except:
            self._log("✅ Daemon stopped (no IPC response)", 'success')
            self.daemon_process = None
            self.force_stop_btn.config(state=tk.DISABLED)
            self.restart_btn.config(state=tk.DISABLED)
            self.start_btn.config(state=tk.NORMAL)
            self._update_status()
    
    def _restart_daemon(self):
        """Restart daemon process (stop then start with proper verification)"""
        self._log("🔄 Restarting daemon...", 'info')
        
        # Disable restart button during operation
        self.restart_btn.config(state=tk.DISABLED)
        
        # Step 1: Stop daemon
        stop_success = False
        try:
            resp = self.ipc.send_command('shutdown')
            if resp and resp.get('status') == 'ok':
                self._log("⏹️ Daemon shutdown command sent via IPC", 'info')
                stop_success = True
        except:
            self._log("⚠️ IPC shutdown failed, trying process termination", 'warning')
        
        # If daemon was started by GUI process
        if self.daemon_process:
            try:
                self.output_reader_running = False
                self.daemon_process.terminate()
                self._log("⏹️ Daemon process terminated", 'info')
                stop_success = True
                self.daemon_process = None
            except Exception as e:
                self._log(f"⚠️ Error stopping daemon: {e}", 'warning')
        
        if not stop_success:
            self._log("❌ Failed to stop daemon", 'error')
            messagebox.showerror("Error", "Failed to stop daemon. Please stop it manually and try again.")
            self.restart_btn.config(state=tk.NORMAL)
            return
        
        # Step 2: Wait and verify daemon stopped
        self._log("⏳ Waiting for port release (3 seconds)...", 'info')
        self.after(3000, self._verify_and_start)
    
    def _verify_and_start(self):
        """Verify daemon stopped and start it again"""
        # Check if port is free
        import socket
        port_free = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((self.ipc.host, self.ipc.port))
                if result != 0:  # Connection failed = port is free
                    port_free = True
                    self._log("✅ Port is free, daemon stopped successfully", 'success')
        except:
            port_free = True
        
        if not port_free:
            self._log("⚠️ Port still occupied, waiting longer...", 'warning')
            # Wait another 2 seconds
            self.after(2000, self._verify_and_start)
            return
        
        # Port is free, start daemon
        try:
            self._start_daemon()
            self._log("✅ Daemon restarted successfully", 'success')
        except Exception as e:
            self._log(f"❌ Failed to restart daemon: {e}", 'error')
            messagebox.showerror("Error", f"Failed to restart daemon: {e}")
            self.restart_btn.config(state=tk.NORMAL)
    
    def _test_ipc(self):
        """Test IPC connection and display detailed results"""
        self._log("🔍 Testing IPC connection...", 'info')
        
        try:
            # Test 1: Port connectivity
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            
            try:
                s.connect((self.ipc.host, self.ipc.port))
                s.close()
                self._log(f"✅ Port {self.ipc.port} on {self.ipc.host} is reachable", 'success')
            except ConnectionRefusedError:
                self._log(f"❌ Port {self.ipc.port} connection refused - Daemon not running", 'error')
                messagebox.showerror("IPC Test Failed", 
                                   f"Cannot connect to {self.ipc.host}:{self.ipc.port}\n\n"
                                   "Daemon is not running or not listening on this port.")
                return
            except socket.timeout:
                self._log(f"❌ Connection timeout", 'error')
                messagebox.showerror("IPC Test Failed", "Connection timeout")
                return
            
            # Test 2: Status command
            resp = self.ipc.send_command('status')
            if resp:
                if resp.get('status') == 'ok':
                    self._log("✅ IPC communication successful", 'success')
                    self._log(f"  - Daemon running: {resp.get('daemon_running')}", 'info')
                    self._log(f"  - Broker connected: {resp.get('broker_connected')}", 'info')
                    self._log(f"  - Devices: {resp.get('devices_count', 0)}", 'info')
                    
                    messagebox.showinfo(
                        "IPC Test Successful",
                        f"✅ IPC connection working!\n\n"
                        f"Daemon: Running\n"
                        f"Broker: {'Connected' if resp.get('broker_connected') else 'Disconnected'}\n"
                        f"Devices: {resp.get('devices_count', 0)}\n"
                        f"Config: {'Valid' if resp.get('config_valid') else 'Invalid'}"
                    )
                else:
                    self._log(f"⚠️ IPC response error: {resp.get('msg')}", 'warning')
                    messagebox.showwarning("IPC Test Warning", 
                                         f"Daemon responded but with error:\n{resp.get('msg')}")
            else:
                self._log("❌ IPC returned no response", 'error')
                messagebox.showerror("IPC Test Failed", "Daemon returned no response")
                
        except Exception as e:
            self._log(f"❌ IPC test failed: {e}", 'error')
            messagebox.showerror("IPC Test Failed", f"Error: {e}")
    
    def _show_detailed_status(self):
        """Show detailed status information"""
        try:
            resp = self.ipc.send_command('status')
            if resp and resp.get('status') == 'ok':
                # Display detailed status in output
                self._log("=" * 60, 'info')
                self._log("📊 DAEMON STATUS REPORT", 'info')
                self._log("=" * 60, 'info')
                self._log(f"Daemon Running: ✅ Yes", 'success')
                self._log(f"Broker Connected: {'No' if not resp.get('broker_connected') else '✅ Yes'}", 
                         'error' if not resp.get('broker_connected') else 'success')
                self._log(f"Broker Address: {resp.get('broker_host')}:{resp.get('broker_port')}", 'info')
                self._log(f"Configuration: {'Invalid' if not resp.get('config_valid') else '✅ Valid'}", 
                         'error' if not resp.get('config_valid') else 'success')
                self._log(f"Devices Count: {resp.get('devices_count', 0)}", 'info')
                
                if resp.get('last_active'):
                    self._log(f"Last Active Device: {resp.get('last_active')}", 'info')
                
                if resp.get('subscriptions'):
                    self._log(f"Active Subscriptions:", 'info')
                    for sub in resp.get('subscriptions', []):
                        self._log(f"  - {sub}", 'info')
                
                self._log("=" * 60, 'info')
            else:
                self._log("❌ Cannot get daemon status - daemon not responding", 'error')
                messagebox.showerror("Error", "Cannot get daemon status - daemon not responding")
        except Exception as e:
            self._log(f"❌ Failed to get status: {e}", 'error')
            messagebox.showerror("Error", f"Failed to get status: {e}")
    
    def _output_reader_thread(self):
        """Thread to read daemon output continuously"""
        while self.output_reader_running and self.daemon_process:
            try:
                line = self.daemon_process.stdout.readline()
                if not line:  # Process ended
                    break
                # Schedule GUI update in main thread (avoid lambda closure issues)
                msg = line.rstrip()
                match = re.search(r"IPC Server listening on\s+([^:]+):(\d+)", msg)
                if match:
                    host = match.group(1).strip()
                    port = int(match.group(2))
                    self.after(0, self._apply_ipc_target, host, port)
                self.after(0, self._log_from_thread, msg, 'output')
            except UnicodeDecodeError as e:
                # Log encoding error but continue reading
                error_msg = f"⚠️ Encoding error in daemon output (character skipped)"
                self.after(0, self._log_from_thread, error_msg, 'warning')
                continue  # Continue reading instead of breaking
            except Exception as e:
                error_msg = f"❌ Output reader error: {e}"
                self.after(0, self._log_from_thread, error_msg, 'error')
                break
        
        # Process ended
        if self.daemon_process:
            exit_code = self.daemon_process.poll()
            if exit_code is not None:
                exit_msg = f"⚠️ Daemon process exited with code {exit_code}"
                self.after(0, self._log_from_thread, exit_msg, 'warning')
                self.after(0, lambda: self.start_btn.config(state=tk.NORMAL))
                self.after(0, lambda: self.force_stop_btn.config(state=tk.DISABLED))
    
    def _log_from_thread(self, message, level='output'):
        """Helper to log from background thread"""
        self._log(message, level)
    
    def _read_daemon_output(self):
        """Legacy method - now handled by _output_reader_thread"""
        pass
    
    def _clear_output(self):
        """Clear output display"""
        self.output_text.delete(1.0, tk.END)
        self._log("Output cleared", 'info')
    
    def _log(self, message, level='output'):
        """Log message to output text"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        colors = {
            'info': '#00a8ff',      # Blue
            'success': '#00ff00',   # Green
            'warning': '#ffcc00',   # Yellow
            'error': '#ff0000',     # Red
            'output': '#00ff00'     # Default green
        }
        
        color = colors.get(level, '#00ff00')
        
        self.output_text.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        self.output_text.insert(tk.END, f"{message}\n", level)
        self.output_text.see(tk.END)
        
        # Configure tags
        self.output_text.tag_config('timestamp', foreground='#888888')
        self.output_text.tag_config(level, foreground=color)
    
    def _display_config(self):
        """Refresh and display current configuration (called from main menu)"""
        try:
            # Force reload from daemon/file
            config = self.config_manager.get_config(self.ipc, force_reload=True)
            self._log("📋 Configuration reloaded", 'info')
            usp_cfg = config.get('usp_controller', {})
            
            # Display key configuration values
            endpoint_id = usp_cfg.get('controller_endpoint_id') or config.get('controller_endpoint_id', 'Not set')
            broker_host = usp_cfg.get('broker_host', config.get('broker_host', 'Not set'))
            broker_port = usp_cfg.get('broker_port', config.get('broker_port', 'Not set'))
            mini_broker = config.get('mini_broker', {})
            
            self._log("=" * 50, 'info')
            self._log(f"Controller Endpoint: {endpoint_id}", 'info')
            self._log(f"Broker Connection: {broker_host}:{broker_port}", 'info')
            self._log(f"Mini Broker: {mini_broker.get('host', '0.0.0.0')}:{mini_broker.get('port', 61613)}", 'info')
            self._log("=" * 50, 'info')
            
        except Exception as e:
            self._log(f"❌ Failed to load config: {e}", 'error')


class ConfigViewDialog(tk.Toplevel):
    """Read-only dialog to view full configuration"""
    
    def __init__(self, parent, ipc, config_manager):
        super().__init__(parent)
        self.ipc = ipc
        self.config_manager = config_manager
        self.title("Configuration Viewer")
        self.geometry("700x600")
        
        self._create_widgets()
        self._load_and_display()
    
    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(title_frame, text="Current Configuration", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        ttk.Button(title_frame, text="🔄 Refresh", command=self._load_and_display).pack(side=tk.RIGHT)
        
        # Config display
        config_frame = ttk.Frame(main_frame)
        config_frame.pack(fill=tk.BOTH, expand=True)
        
        self.config_text = scrolledtext.ScrolledText(
            config_frame,
            height=25,
            width=80,
            font=('Consolas', 10),
            wrap=tk.WORD,
            bg='#f5f5f5',
            fg='#000000'
        )
        self.config_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Edit Config", command=self._open_editor).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=self.destroy).pack(side=tk.LEFT, padx=5)
    
    def _load_and_display(self):
        """Load and display configuration"""
        try:
            config = self.config_manager.get_config(self.ipc, force_reload=True)
            usp_cfg = config.get('usp_controller', {})
            
            self.config_text.delete(1.0, tk.END)
            
            # Format and display config in a readable way
            self._insert_section("CONTROLLER SETTINGS")
            self._insert_item("Endpoint ID", usp_cfg.get('controller_endpoint_id') or config.get('controller_endpoint_id', 'Not set'))
            
            self._insert_section("\nBROKER CONNECTION")
            self._insert_item("Host", usp_cfg.get('broker_host', config.get('broker_host', 'Not set')))
            self._insert_item("Port", usp_cfg.get('broker_port', config.get('broker_port', 'Not set')))
            self._insert_item("Username", usp_cfg.get('username', config.get('username', 'Not set')))
            self._insert_item("Password", '****' if (usp_cfg.get('password') or config.get('password')) else 'Not set')
            
            self._insert_section("\nMINI BROKER SETTINGS")
            mini_broker = config.get('mini_broker', {})
            self._insert_item("Enabled", str(mini_broker.get('enable', False)))
            self._insert_item("Host", mini_broker.get('host', 'Not set'))
            self._insert_item("Port", str(mini_broker.get('port', 61613)))
            
            self._insert_section("\nRAW JSON")
            self.config_text.insert(tk.END, json.dumps(config, indent=2, ensure_ascii=False))
            
        except Exception as e:
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(tk.END, f"Error loading configuration: {e}")
    
    def _insert_section(self, title):
        """Insert section header"""
        self.config_text.insert(tk.END, f"{title}\n", 'section')
        self.config_text.insert(tk.END, "=" * 60 + "\n")
        self.config_text.tag_config('section', foreground='#0066cc', font=('Consolas', 11, 'bold'))
    
    def _insert_item(self, key, value):
        """Insert config item"""
        self.config_text.insert(tk.END, f"  {key:20s}: ", 'key')
        self.config_text.insert(tk.END, f"{value}\n", 'value')
        self.config_text.tag_config('key', foreground='#666666')
        self.config_text.tag_config('value', foreground='#000000', font=('Consolas', 10, 'bold'))
    
    def _open_editor(self):
        """Open config editor"""
        DaemonConfigEditorDialog(self, self.ipc, self.config_manager)
        # Refresh after editing
        self.after(500, self._load_and_display)


class DaemonConfigEditorDialog(tk.Toplevel):
    """Enhanced dialog for editing daemon configuration"""
    
    def __init__(self, parent, ipc, config_manager):
        super().__init__(parent)
        self.ipc = ipc
        self.config_manager = config_manager
        self.title("⚙️ Edit Daemon Configuration")
        self.geometry("650x500")
        
        # Load current config
        self.config = self.config_manager.get_config(ipc)
        
        self._create_widgets()
    
    def _create_widgets(self):
        # Main frame with scrollbar
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Daemon Configuration Editor", 
                 font=('Arial', 13, 'bold')).pack(pady=(0, 15))
        
        # Notebook for different config sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Tab 1: Controller Settings
        controller_tab = ttk.Frame(notebook, padding=15)
        notebook.add(controller_tab, text="Controller")
        self._create_controller_tab(controller_tab)
        
        # Tab 2: Broker Settings
        broker_tab = ttk.Frame(notebook, padding=15)
        notebook.add(broker_tab, text="Broker Connection")
        self._create_broker_tab(broker_tab)
        
        # Tab 3: Advanced Settings
        advanced_tab = ttk.Frame(notebook, padding=15)
        notebook.add(advanced_tab, text="Advanced")
        self._create_advanced_tab(advanced_tab)
        
        # Bottom buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="💾 Save & Reload", command=self._save_and_reload, 
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Save Only", command=self._save_only, 
                  width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.destroy, 
                  width=15).pack(side=tk.LEFT, padx=5)
    
    def _create_controller_tab(self, parent):
        """Create controller settings tab"""
        # Info
        info = ttk.Label(parent, text="💡 Controller identification settings", 
                        foreground='blue', font=('Arial', 9))
        info.pack(anchor=tk.W, pady=(0, 15))
        
        # Endpoint ID
        frame = ttk.LabelFrame(parent, text="Controller Endpoint ID", padding=10)
        frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(frame, text="Endpoint ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.endpoint_entry = ttk.Entry(frame, width=40)
        usp_cfg = self.config.get('usp_controller', {})
        self.endpoint_entry.insert(
            0,
            usp_cfg.get(
                'controller_endpoint_id',
                self.config.get('controller_endpoint_id', self.config.get('controller_id', ''))
            )
        )
        self.endpoint_entry.grid(row=0, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(frame, text="Example: proto::controller.my-laptop", 
                 foreground='gray', font=('Arial', 8)).grid(row=1, column=1, sticky=tk.W, padx=10)
        
        frame.columnconfigure(1, weight=1)
    
    def _create_broker_tab(self, parent):
        """Create broker connection settings tab"""
        # Info
        mini_broker_port = self.config.get('mini_broker', {}).get('port', 61613)
        info_text = f"💡 Daemon connects to Mini Broker (localhost:{mini_broker_port})\nThese settings are auto-configured based on Mini Broker settings."
        info = ttk.Label(parent, text=info_text, foreground='blue', font=('Arial', 9))
        info.pack(anchor=tk.W, pady=(0, 15))
        
        # Broker settings (read-only info)
        frame = ttk.LabelFrame(parent, text="Broker Connection (Auto-configured)", padding=10)
        frame.pack(fill=tk.X, pady=5)
        
        settings = [
            ("Host:", self.config.get('usp_controller', {}).get('broker_host', self.config.get('broker_host', '127.0.0.1'))),
            ("Port:", str(self.config.get('usp_controller', {}).get('broker_port', self.config.get('broker_port', mini_broker_port)))),
            ("Username:", self.config.get('usp_controller', {}).get('username', self.config.get('username', 'guest'))),
            ("Password:", '****' if (self.config.get('usp_controller', {}).get('password') or self.config.get('password')) else '')
        ]
        
        for i, (label, value) in enumerate(settings):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=3)
            value_label = ttk.Label(frame, text=value, foreground='#666', font=('Arial', 9, 'bold'))
            value_label.grid(row=i, column=1, sticky=tk.W, padx=10, pady=3)
        
        ttk.Label(frame, text="ℹ️ These are automatically set from Mini Broker configuration", 
                 foreground='gray', font=('Arial', 8)).grid(row=len(settings), column=0, 
                                                           columnspan=2, sticky=tk.W, pady=10)
    
    def _create_advanced_tab(self, parent):
        """Create advanced settings tab"""
        # Warning
        warning = ttk.Label(parent, text="⚠️ Advanced settings - modify with caution", 
                          foreground='#ff6600', font=('Arial', 9, 'bold'))
        warning.pack(anchor=tk.W, pady=(0, 15))
        
        # IPC Settings
        frame = ttk.LabelFrame(parent, text="IPC Settings", padding=10)
        frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(frame, text="IPC Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ipc_host_entry = ttk.Entry(frame, width=30)
        ipc_host = self.config.get('ipc', {}).get('host', '127.0.0.1')
        self.ipc_host_entry.insert(0, ipc_host)
        self.ipc_host_entry.grid(row=0, column=1, sticky=tk.EW, padx=10, pady=5)
        
        ttk.Label(frame, text="IPC Port:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ipc_port_entry = ttk.Entry(frame, width=30)
        ipc_port = self.config.get('ipc', {}).get('port', 6001)
        self.ipc_port_entry.insert(0, str(ipc_port))
        self.ipc_port_entry.grid(row=1, column=1, sticky=tk.EW, padx=10, pady=5)
        
        frame.columnconfigure(1, weight=1)
        
        ttk.Label(frame, text="ℹ️ Default: 127.0.0.1:6001", 
                 foreground='gray', font=('Arial', 8)).grid(row=2, column=1, sticky=tk.W, padx=10)
    
    def _validate_config(self):
        """Validate configuration before saving"""
        errors = []
        
        # Validate endpoint ID
        endpoint_id = self.endpoint_entry.get().strip()
        if not endpoint_id:
            errors.append("Controller Endpoint ID cannot be empty")
        
        # Validate IPC port
        try:
            ipc_port = int(self.ipc_port_entry.get())
            if not (1 <= ipc_port <= 65535):
                errors.append("IPC Port must be between 1 and 65535")
        except ValueError:
            errors.append("IPC Port must be a valid number")
        
        return errors
    
    def _save_only(self):
        """Save configuration without reloading daemon"""
        self._save_config(reload_daemon=False)
    
    def _save_and_reload(self):
        """Save configuration and reload daemon"""
        self._save_config(reload_daemon=True)
    
    def _save_config(self, reload_daemon=True):
        """Save configuration to file"""
        # Validate first
        errors = self._validate_config()
        if errors:
            error_msg = "\n".join(errors)
            print(f"[!] Config validation error: {error_msg}")
            messagebox.showerror("Validation Error", error_msg)
            return
        
        try:
            # Get absolute path to config.json
            script_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(script_dir, 'config.json')
            
            # Load current config from file
            from usp_core import load_config as load_config_file
            full_config = load_config_file(config_file)
            if not full_config:
                print("[!] Failed to load current configuration")
                messagebox.showerror("Error", "Failed to load current configuration")
                return
            
            # Update controller settings
            endpoint_id = self.endpoint_entry.get().strip()
            if 'usp_controller' not in full_config:
                full_config['usp_controller'] = {}
            full_config['usp_controller']['controller_endpoint_id'] = endpoint_id

            # Keep receive_topic in sync with controller id
            suffix = endpoint_id.split('::')[-1]
            full_config['usp_controller']['receive_topic'] = f'/queue/usp.controller.{suffix}'

            # Keep top-level mirror for backward compatibility
            full_config['controller_endpoint_id'] = endpoint_id
            
            # Update IPC settings
            if 'ipc' not in full_config:
                full_config['ipc'] = {}
            full_config['ipc']['host'] = self.ipc_host_entry.get().strip()
            full_config['ipc']['port'] = int(self.ipc_port_entry.get())
            
            # Auto-configure broker connection based on mini_broker settings
            mini_broker_config = full_config.get('mini_broker', {})
            broker_port = mini_broker_config.get('port', 61613)
            
            full_config['broker_host'] = '127.0.0.1'
            full_config['broker_port'] = broker_port
            full_config['username'] = 'guest'
            full_config['password'] = 'guest'
            full_config['usp_controller']['broker_host'] = '127.0.0.1'
            full_config['usp_controller']['broker_port'] = broker_port
            full_config['usp_controller']['username'] = 'guest'
            full_config['usp_controller']['password'] = 'guest'
            
            # Save config file
            from usp_core import save_config as save_config_file
            if not save_config_file(full_config, config_file):
                print("[!] Failed to save configuration file")
                messagebox.showerror("Error", "Failed to save configuration file")
                return
            
            # Invalidate cache
            self.config_manager.invalidate_cache()
            
            # Reload daemon if requested
            if reload_daemon:
                resp = self.ipc.send_command('reload_config')
                if resp and resp.get('status') == 'ok':
                    messagebox.showinfo("Success", 
                                      f"✅ Configuration saved and reloaded!\n\n"
                                      f"Controller Endpoint: {endpoint_id}\n"
                                      f"Broker: localhost:{broker_port}")
                    self.destroy()
                else:
                    messagebox.showwarning("Partial Success", 
                                         f"💾 Configuration saved to file\n\n"
                                         f"⚠️ Daemon reload failed or daemon not running.\n"
                                         f"Please restart daemon manually to apply changes.")
            else:
                messagebox.showinfo("Success", 
                                  f"💾 Configuration saved!\n\n"
                                  f"ℹ️ Restart daemon to apply changes.")
                self.destroy()
                
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"[!] Failed to save configuration: {e}")
            print(error_details)
            traceback.print_exc()
            messagebox.showerror("Error", f"Failed to save configuration: {e}")


class CLIPage(ttk.Frame):
    """CLI Page - Embedded command-line interface with history and quick commands"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.ipc = IPCClient()  # IPC client for command execution
        self.command_history = self._load_history()
        self.history_index = -1
        
        self._create_widgets()
        self._refresh_history_list()
        
        # Start background thread to check daemon and update devices
        self.polling = True
        self.poll_thread = threading.Thread(target=self._background_poller, daemon=True)
        self.poll_thread.start()
    
    def _background_poller(self):
        """Background thread to poll daemon status and update device list"""
        while self.polling:
            try:
                # Check daemon status and get devices
                resp = self.ipc.send_command('status')
                if resp and resp.get('status') == 'ok':
                    # Update connection indicator
                    pass
                
                # Get devices list
                resp = self.ipc.send_command('devices')
                if resp and resp.get('status') == 'ok':
                    devices = resp.get('devices', {})
                    endpoints = list(devices.keys())
                    # Update endpoint combo in main thread
                    self.after(0, lambda: self._update_endpoints(endpoints))
                
            except:
                pass
            
            # Poll every 3 seconds
            import time
            time.sleep(3)
    
    def _create_widgets(self):
        # Main layout: 3 columns
        self.columnconfigure(0, weight=3)  # Command center
        self.columnconfigure(1, weight=2)  # Quick commands  
        self.columnconfigure(2, weight=2)  # History
        self.rowconfigure(1, weight=1)     # Output area
        
        # Title Bar
        title_frame = ttk.Frame(self)
        title_frame.grid(row=0, column=0, columnspan=3, sticky=tk.EW, padx=10, pady=10)
        ttk.Label(title_frame, text="USP CLI - Command Center", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        ttk.Button(title_frame, text="Clear All", command=self._clear_output).pack(side=tk.RIGHT, padx=5)
        
        # === Column 1: Command Center ===
        cmd_frame = ttk.LabelFrame(self, text="Command Center", padding=10)
        cmd_frame.grid(row=1, column=0, sticky=tk.NSEW, padx=(10, 5), pady=5)
        cmd_frame.rowconfigure(1, weight=1)
        cmd_frame.columnconfigure(0, weight=1)
        
        # Command input area
        input_frame = ttk.Frame(cmd_frame)
        input_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(input_frame, text="Command:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.command_entry = ttk.Entry(input_frame, font=('Consolas', 10))
        self.command_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        self.command_entry.bind('<Return>', self._on_command)
        self.command_entry.bind('<Up>', self._history_up)
        self.command_entry.bind('<Down>', self._history_down)
        
        ttk.Button(input_frame, text="Execute", command=self._on_command, width=10).grid(row=0, column=2, padx=5)
        
        # Output terminal
        output_frame = ttk.Frame(cmd_frame)
        output_frame.grid(row=1, column=0, sticky=tk.NSEW)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            font=('Consolas', 10),
            bg='black',
            fg='#00ff00',
            insertbackground='white',
            wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Add context menu
        self._add_text_context_menu(self.output_text)
        
        # Configure text tags for colored output
        self.output_text.tag_config('command', foreground='#00ffff')  # Cyan
        self.output_text.tag_config('error', foreground='#ff0000')    # Red
        self.output_text.tag_config('warning', foreground='#ffff00')  # Yellow
        self.output_text.tag_config('info', foreground='#00ff00')     # Green
        self.output_text.tag_config('help', foreground='#ffffff')     # White
        
        # Welcome message
        self.output_text.insert(tk.END, "="*60 + "\n")
        self.output_text.insert(tk.END, f"  USP Controller CLI - Embedded Mode v{GUI_VERSION}\n")
        self.output_text.insert(tk.END, "="*60 + "\n\n")
        self.output_text.insert(tk.END, "Type 'help' for available commands\n")
        self.output_text.insert(tk.END, "Use arrow keys to navigate command history\n\n")
        self.output_text.insert(tk.END, ">>> ")
        
        self.command_entry.focus()
        
        # === Column 2: Quick Commands ===
        quick_frame = ttk.LabelFrame(self, text="Quick Commands", padding=10)
        quick_frame.grid(row=1, column=1, sticky=tk.NSEW, padx=5, pady=5)
        
        # Quick command buttons
        ttk.Label(quick_frame, text="USP Command Builder:", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        # Operation type selector
        ttk.Label(quick_frame, text="Operation:", font=('Arial', 8)).pack(anchor=tk.W, pady=(5, 2))
        self.operation_combo = ttk.Combobox(quick_frame, width=23, state='readonly')
        self.operation_combo['values'] = ['GET', 'SET', 'ADD', 'DELETE', 'GetInstances', 'GetSupportedDM', 'Operate']
        self.operation_combo.current(0)
        self.operation_combo.pack(fill=tk.X, pady=2)
        self.operation_combo.bind('<<ComboboxSelected>>', self._on_operation_change)
        
        # Endpoint selector
        ttk.Label(quick_frame, text="Endpoint:", font=('Arial', 8)).pack(anchor=tk.W, pady=(5, 2))
        self.endpoint_combo = ttk.Combobox(quick_frame, width=23, state='normal')
        self.endpoint_combo['values'] = ['proto::test-agent']  # Default test endpoint
        self.endpoint_combo.current(0)  # Select first item by default
        self.endpoint_combo.pack(fill=tk.X, pady=2)
        
        # Path/Object input
        ttk.Label(quick_frame, text="Path/Object:", font=('Arial', 8)).pack(anchor=tk.W, pady=(5, 2))
        self.cmd_path_entry = ttk.Entry(quick_frame, width=25)
        self.cmd_path_entry.pack(fill=tk.X, pady=2)
        self.cmd_path_entry.insert(0, "Device.DeviceInfo.SoftwareVersion")
        
        # Value input (for SET) - always visible, disabled when not SET
        ttk.Label(quick_frame, text="Value:", font=('Arial', 8)).pack(anchor=tk.W, pady=(5, 2))
        self.cmd_value_entry = ttk.Entry(quick_frame, width=25, state='disabled')
        self.cmd_value_entry.pack(fill=tk.X, pady=2)
        
        # Arguments frame (for Operate) - initially hidden
        self.args_frame = ttk.LabelFrame(quick_frame, text="Arguments (optional)", padding=5)
        
        # Arg 1
        arg_frame1 = ttk.Frame(self.args_frame)
        arg_frame1.pack(fill=tk.X, pady=2)
        self.arg1_key = ttk.Entry(arg_frame1, width=10)
        self.arg1_key.pack(side=tk.LEFT, padx=(0, 2))
        self.arg1_key.insert(0, "key1")
        ttk.Label(arg_frame1, text="=").pack(side=tk.LEFT)
        self.arg1_val = ttk.Entry(arg_frame1, width=10)
        self.arg1_val.pack(side=tk.LEFT, padx=(2, 0))
        self.arg1_val.insert(0, "value1")
        
        # Arg 2
        arg_frame2 = ttk.Frame(self.args_frame)
        arg_frame2.pack(fill=tk.X, pady=2)
        self.arg2_key = ttk.Entry(arg_frame2, width=10)
        self.arg2_key.pack(side=tk.LEFT, padx=(0, 2))
        self.arg2_key.insert(0, "key2")
        ttk.Label(arg_frame2, text="=").pack(side=tk.LEFT)
        self.arg2_val = ttk.Entry(arg_frame2, width=10)
        self.arg2_val.pack(side=tk.LEFT, padx=(2, 0))
        self.arg2_val.insert(0, "value2")
        
        # Generate button
        ttk.Button(quick_frame, text="🔧 Generate Command", command=self._generate_command, width=25).pack(fill=tk.X, pady=(10, 5))
        
        # Initialize form visibility based on selected operation
        self._on_operation_change(None)
        
        ttk.Separator(quick_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # System commands
        ttk.Label(quick_frame, text="System:", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=(5, 5))
        
        ttk.Button(quick_frame, text="Status", command=lambda: self._insert_cmd('status'), width=25).pack(fill=tk.X, pady=2)
        ttk.Button(quick_frame, text="Devices", command=lambda: self._insert_cmd('devices'), width=25).pack(fill=tk.X, pady=2)
        ttk.Button(quick_frame, text="Reconnect", command=lambda: self._insert_cmd('reconnect'), width=25).pack(fill=tk.X, pady=2)
        
        # === Column 3: Command History ===
        history_frame = ttk.LabelFrame(self, text="Command History", padding=10)
        history_frame.grid(row=1, column=2, sticky=tk.NSEW, padx=(5, 10), pady=5)
        history_frame.rowconfigure(0, weight=1)
        history_frame.columnconfigure(0, weight=1)
        
        # History listbox
        list_frame = ttk.Frame(history_frame)
        list_frame.grid(row=0, column=0, sticky=tk.NSEW, pady=(0, 10))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.grid(row=0, column=1, sticky=tk.NS)
        
        self.history_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            font=('Consolas', 9),
            selectmode=tk.SINGLE
        )
        self.history_listbox.grid(row=0, column=0, sticky=tk.NSEW)
        scrollbar.config(command=self.history_listbox.yview)
        
        # Bind events
        self.history_listbox.bind('<Double-Button-1>', self._history_double_click)
        self.history_listbox.bind('<Button-3>', self._history_right_click)
        self.history_listbox.bind('<Return>', self._history_execute)
        
        # History controls
        hist_btn_frame = ttk.Frame(history_frame)
        hist_btn_frame.grid(row=1, column=0, sticky=tk.EW)
        
        ttk.Button(hist_btn_frame, text="Load", command=self._history_load, width=10).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        ttk.Button(hist_btn_frame, text="Execute", command=self._history_execute, width=10).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        
        hist_btn_frame2 = ttk.Frame(history_frame)
        hist_btn_frame2.grid(row=2, column=0, sticky=tk.EW, pady=(5, 0))
        
        ttk.Button(hist_btn_frame2, text="Delete", command=self._history_delete, width=10).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        ttk.Button(hist_btn_frame2, text="Clear All", command=self._history_clear, width=10).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
    
    def _add_text_context_menu(self, text_widget):
        """Add right-click context menu to text widget"""
        menu = tk.Menu(text_widget, tearoff=0)
        menu.add_command(label="Copy", command=lambda: self._copy_text(text_widget))
        menu.add_command(label="Select All", command=lambda: text_widget.tag_add(tk.SEL, "1.0", tk.END))
        menu.add_separator()
        menu.add_command(label="Clear", command=self._clear_output)
        
        def show_menu(event):
            menu.post(event.x_root, event.y_root)
        
        text_widget.bind('<Button-3>', show_menu)
    
    def _copy_text(self, text_widget):
        """Copy selected text to clipboard"""
        try:
            text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:
            pass
    
    def _on_operation_change(self, event):
        """Handle operation type change - enable/disable relevant fields"""
        operation = self.operation_combo.get()
        
        # Hide arguments frame first
        self.args_frame.pack_forget()
        
        # Update path placeholder based on operation
        if operation in ['GET', 'SET']:
            self.cmd_path_entry.delete(0, tk.END)
            self.cmd_path_entry.insert(0, "Device.DeviceInfo.SoftwareVersion")
        elif operation in ['ADD', 'DELETE']:
            self.cmd_path_entry.delete(0, tk.END)
            self.cmd_path_entry.insert(0, "Device.WiFi.SSID.")
        elif operation in ['GetInstances', 'GetSupportedDM']:
            self.cmd_path_entry.delete(0, tk.END)
            self.cmd_path_entry.insert(0, "Device.WiFi.SSID.")
        elif operation == 'Operate':
            self.cmd_path_entry.delete(0, tk.END)
            self.cmd_path_entry.insert(0, "Device.Reboot()")
        
        # Enable/disable Value field based on operation
        if operation == 'SET':
            self.cmd_value_entry.config(state='normal')
            self.cmd_value_entry.delete(0, tk.END)
        else:
            self.cmd_value_entry.config(state='disabled')
            self.cmd_value_entry.delete(0, tk.END)
        
        # Show arguments frame for Operate
        if operation == 'Operate':
            # For Operate, Path/Object becomes the command
            # Show arguments frame
            self.args_frame.pack(fill=tk.X, pady=(5, 0))
    
    def _generate_command(self):
        """Generate USP command from form inputs"""
        operation = self.operation_combo.get()
        endpoint = self.endpoint_combo.get().strip()
        path = self.cmd_path_entry.get().strip()
        
        if not endpoint:
            messagebox.showwarning("Missing Endpoint", "Please select or enter a target endpoint")
            self.endpoint_combo.focus()
            return
        
        if not path:
            messagebox.showwarning("Missing Path", f"Please enter a path/object for {operation}")
            self.cmd_path_entry.focus()
            return
        
        # Build command based on operation type
        cmd = None
        
        if operation == 'GET':
            cmd = f"get {endpoint} {path}"
        
        elif operation == 'SET':
            value = self.cmd_value_entry.get().strip()
            if not value:
                messagebox.showwarning("Missing Value", "Please enter a value for SET operation")
                self.cmd_value_entry.focus()
                return
            cmd = f"set {endpoint} {path} {value}"
        
        elif operation == 'ADD':
            cmd = f"add {endpoint} {path}"
        
        elif operation == 'DELETE':
            cmd = f"delete {endpoint} {path}"
        
        elif operation == 'GetInstances':
            cmd = f"get_instances {endpoint} {path}"
        
        elif operation == 'GetSupportedDM':
            cmd = f"get_supported {endpoint} {path}"
        
        elif operation == 'Operate':
            # For operate, path IS the command
            cmd_parts = [f"operate {endpoint} {path}"]
            
            # Add arguments if provided
            args = []
            
            # Arg 1
            key1 = self.arg1_key.get().strip()
            val1 = self.arg1_val.get().strip()
            if key1 and val1 and key1 not in ['key1', ''] and val1 not in ['value1', '']:
                args.append(f"{key1}={val1}")
            
            # Arg 2
            key2 = self.arg2_key.get().strip()
            val2 = self.arg2_val.get().strip()
            if key2 and val2 and key2 not in ['key2', ''] and val2 not in ['value2', '']:
                args.append(f"{key2}={val2}")
            
            # Combine
            if args:
                cmd = f"{cmd_parts[0]} {' '.join(args)}"
            else:
                cmd = cmd_parts[0]
        
        if cmd:
            # Insert into command entry (don't auto-execute)
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, cmd)
            self.command_entry.focus()
            
            # Flash the command entry to draw attention
            original_bg = self.command_entry.cget('background')
            self.command_entry.configure(background='#ffffcc')
            self.after(200, lambda: self.command_entry.configure(background=original_bg))
    
    def _insert_cmd(self, cmd):
        """Insert command into entry"""
        self.command_entry.delete(0, tk.END)
        self.command_entry.insert(0, cmd)
        self.command_entry.focus()
    
    def _on_command(self, event=None):
        """Execute command from entry"""
        command = self.command_entry.get().strip()
        if not command:
            return 'break'
        
        self._execute_command(command)
        self.command_entry.delete(0, tk.END)
        return 'break'
    
    def _execute_command(self, command):
        """Execute a command and display output"""
        # Add to history (avoid duplicates)
        if not self.command_history or self.command_history[-1] != command:
            self.command_history.append(command)
            if len(self.command_history) > MAX_HISTORY:
                self.command_history.pop(0)
            self._save_history()
            self._refresh_history_list()
        
        self.history_index = len(self.command_history)
        
        # Display command in terminal
        self.output_text.insert(tk.END, f"{command}\n", 'command')
        self.output_text.see(tk.END)  # Scroll to show command
        self.output_text.update_idletasks()  # Force update display
        
        # Handle LOCAL commands (no daemon needed)
        if command == 'help':
            self._show_help()
            self.output_text.insert(tk.END, "\n>>> ")
            self.output_text.see(tk.END)
            self.output_text.update_idletasks()  # Force update display
            return
        elif command == 'clear':
            self._clear_output()
            return
        elif command == 'version':
            self.output_text.insert(tk.END, f"USP Controller GUI V{GUI_VERSION}\n", 'info')
            self.output_text.insert(tk.END, f"Build Version: {FULL_VERSION}\n", 'info')
            self.output_text.insert(tk.END, "Multi-Page Embedded Architecture\n", 'info')
            self.output_text.insert(tk.END, "\n>>> ")
            self.output_text.see(tk.END)
            self.output_text.update_idletasks()
            return
        elif command == 'exit' or command == 'quit':
            self.output_text.insert(tk.END, "💡 Use File > Exit to close application\n", 'info')
            self.output_text.insert(tk.END, "\n>>> ")
            self.output_text.see(tk.END)
            self.output_text.update_idletasks()
            return
        
        # All other commands require daemon - send via IPC
        try:
            is_usp_payload = self._is_usp_payload_command(command)

            # Execute command via IPC in background thread
            def execute_in_background():
                if is_usp_payload:
                    status_resp = self.ipc.send_command('status')

                    if status_resp is None or status_resp.get('status') != 'ok':
                        self.after(0, lambda: self._display_route_blocked(
                            "Daemon not running. Start daemon first so CLI commands follow GUI -> Daemon -> Broker -> Agent."
                        ))
                        return

                    if not status_resp.get('broker_connected', False):
                        broker_host = status_resp.get('broker_host', '127.0.0.1')
                        broker_port = status_resp.get('broker_port', 61613)
                        self.after(0, lambda: self._display_route_blocked(
                            f"Daemon is running but broker is not connected ({broker_host}:{broker_port}). "
                            "Connect broker from Daemon tab first."
                        ))
                        return

                    self.after(0, self._display_route_info)

                response = self.ipc.send_command(command)
                # Update UI in main thread
                self.after(0, lambda: self._display_response(command, response))
            
            threading.Thread(target=execute_in_background, daemon=True).start()
            
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n", 'error')
            self.output_text.insert(tk.END, "\n>>> ")
            self.output_text.see(tk.END)

    def _is_usp_payload_command(self, command):
        """Return True if command is a USP payload command that must pass full architecture path."""
        if not command:
            return False
        cmd = command.strip().split()[0].lower()
        return cmd in {'get', 'set', 'add', 'delete', 'get_instances', 'get_supported', 'operate'}

    def _display_route_info(self):
        """Display architecture route for USP payload commands."""
        self.output_text.insert(
            tk.END,
            "🔁 Route: CLI -> Daemon(IPC) -> Broker(STOMP) -> Agent\n",
            'info'
        )
        self.output_text.see(tk.END)

    def _display_route_blocked(self, reason):
        """Display why USP command was blocked before dispatch."""
        self.output_text.insert(tk.END, f"❌ Route guard blocked command: {reason}\n", 'error')
        self.output_text.insert(tk.END, "\n>>> ")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
    
    def _display_response(self, command, response):
        """Display command response in terminal"""
        if response is None:
            # Distinguish between truly-down daemon and command-level no-response
            status_probe = self.ipc.send_command('status')

            self.output_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'error')
            if status_probe and status_probe.get('status') == 'ok':
                self.output_text.insert(tk.END, "❌ Command returned no response\n\n", 'error')
                self.output_text.insert(tk.END, "Daemon is reachable, but this command did not return a payload.\n", 'warning')
                self.output_text.insert(tk.END, "Possible causes:\n", 'warning')
                self.output_text.insert(tk.END, "  - Agent did not respond in time\n", 'warning')
                self.output_text.insert(tk.END, "  - Broker route/session issue\n", 'warning')
                self.output_text.insert(tk.END, "  - Command processing failed in daemon\n", 'warning')
            else:
                self.output_text.insert(tk.END, "❌ Daemon Not Running\n\n", 'error')
                self.output_text.insert(tk.END, "This command requires the USP daemon to be running.\n\n", 'info')
                self.output_text.insert(tk.END, "To start daemon:\n", 'info')
                self.output_text.insert(tk.END, "  1. Switch to 'Daemon' tab\n", 'info')
                self.output_text.insert(tk.END, "  2. Click 'Start Daemon'\n\n", 'info')
                self.output_text.insert(tk.END, "Or run manually in terminal:\n", 'info')
                self.output_text.insert(tk.END, "  python usp_controller.py --daemon\n", 'command')

            self.output_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'error')
        elif response.get('status') == 'ok':
            # Success - format output based on command type
            if command == 'status':
                self._display_status_response(response)
            elif command == 'devices':
                self._display_devices_response(response)
            elif command.startswith('get ') or command.startswith('get_'):
                self._display_get_response(response)
            else:
                # Generic success
                self.output_text.insert(tk.END, f"✅ {response.get('msg', 'Command executed successfully')}\n", 'info')
                # Show additional data if present
                for key, value in response.items():
                    if key not in ['status', 'msg']:
                        self.output_text.insert(tk.END, f"   {key}: {value}\n", 'info')
        elif response.get('status') == 'timeout' and response.get('sent_to_broker'):
            self.output_text.insert(tk.END, f"⏱️ {response.get('msg', 'No agent response')}\n", 'warning')
            endpoint = response.get('endpoint')
            path = response.get('path')
            if endpoint or path:
                self.output_text.insert(tk.END, f"   endpoint: {endpoint}\n", 'warning')
                self.output_text.insert(tk.END, f"   path: {path}\n", 'warning')
            self.output_text.insert(tk.END, "   daemon: reachable\n", 'warning')
            self.output_text.insert(tk.END, "   route: CLI -> Daemon -> Broker (sent) -> Agent (no response)\n", 'warning')
        else:
            # Error response
            self.output_text.insert(tk.END, f"❌ Error: {response.get('msg', 'Unknown error')}\n", 'error')
        
        self.output_text.insert(tk.END, "\n>>> ")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
    
    def _display_status_response(self, response):
        """Display status command response"""
        self.output_text.insert(tk.END, "Connection Status:\n", 'info')
        self.output_text.insert(tk.END, f"  Connected: {response.get('broker_connected', False)}\n", 'info')
        self.output_text.insert(tk.END, f"  Devices: {response.get('devices_count', 0)}\n", 'info')
        if response.get('last_active'):
            self.output_text.insert(tk.END, f"  Last Active: {response.get('last_active')}\n", 'info')
    
    def _display_devices_response(self, response):
        """Display devices list"""
        devices = response.get('devices', {})
        if not devices:
            self.output_text.insert(tk.END, "No devices discovered yet\n", 'warning')
        else:
            self.output_text.insert(tk.END, f"Discovered Devices ({len(devices)}):\n", 'info')
            for endpoint, info in devices.items():
                status = info.get('status', 'unknown')
                status_icon = '🟢' if status == 'online' else '🔴' if status == 'offline' else '⚪'
                self.output_text.insert(tk.END, f"  {status_icon} {endpoint}\n", 'info')
                if 'last_seen' in info:
                    self.output_text.insert(tk.END, f"      Last seen: {info['last_seen']}\n", 'info')
    
    def _display_get_response(self, response):
        """Display GET command response"""
        if 'params' in response:
            # GetParameterValues response
            params = response['params']
            if not params:
                self.output_text.insert(tk.END, "No parameters returned\n", 'warning')
            else:
                self.output_text.insert(tk.END, f"Parameters ({len(params)}):\n", 'info')
                for path, value in params.items():
                    self.output_text.insert(tk.END, f"  {path} = {value}\n", 'info')
        elif 'instances' in response:
            # GetInstances response
            instances = response['instances']
            if not instances:
                self.output_text.insert(tk.END, "No instances found\n", 'warning')
            else:
                self.output_text.insert(tk.END, f"Instances ({len(instances)}):\n", 'info')
                for inst in instances:
                    self.output_text.insert(tk.END, f"  {inst}\n", 'info')
        else:
            # Generic response
            self.output_text.insert(tk.END, f"✅ {response.get('msg', 'Success')}\n", 'info')
    
    def _show_help(self):
        """Show help message"""
        help_text = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USP Controller CLI - Command Reference
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LOCAL COMMANDS (No daemon needed):
  help              - Show this help message
  clear             - Clear terminal output
  version           - Show version information
  exit / quit       - Exit instructions

USP COMMANDS (Require daemon):
  status            - Show connection status
  devices           - List discovered devices
  reconnect         - Reconnect to broker
  
  get <endpoint> <path>           - Get parameter value
  set <endpoint> <path> <value>   - Set parameter value
  add <endpoint> <object>         - Add object instance
  delete <endpoint> <object>      - Delete object
  get_instances <endpoint> <path> - Get object instances
  get_supported <endpoint> <path> - Get supported data model

DISCOVERY COMMANDS (Require daemon):
  discover          - Discover devices via mDNS
  scan              - Active mDNS scan

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 TIPS:
  • Local commands (help, clear, version) work without daemon
    • USP payload commands are enforced to run via: CLI -> Daemon -> Broker -> Agent
    • If daemon/broker is not ready, CLI will block USP payload commands before send
  • Start daemon from 'Daemon' tab or run: python usp_controller.py --daemon
  • Use ↑↓ arrow keys to navigate command history
  • Double-click history items to load
  • Use Quick Commands panel for common operations
  • Check daemon status in status bar at bottom

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        self.output_text.insert(tk.END, help_text, 'help')
    
    def _update_endpoints(self, endpoints):
        """Update endpoint combobox with discovered devices"""
        current = self.endpoint_combo.get()
        self.endpoint_combo['values'] = endpoints
        # Restore selection if still valid
        if current in endpoints:
            self.endpoint_combo.set(current)
        elif endpoints:
            self.endpoint_combo.current(0)
    
    def _history_up(self, event):
        """Navigate history up"""
        if self.history_index > 0:
            self.history_index -= 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        return 'break'
    
    def _history_down(self, event):
        """Navigate history down"""
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, self.command_history[self.history_index])
        elif self.history_index == len(self.command_history) - 1:
            self.history_index = len(self.command_history)
            self.command_entry.delete(0, tk.END)
        return 'break'
    
    def _history_double_click(self, event):
        """Double-click to load history item"""
        self._history_load()
    
    def _history_right_click(self, event):
        """Right-click menu for history"""
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Load to Entry", command=self._history_load)
        menu.add_command(label="Execute", command=self._history_execute)
        menu.add_separator()
        menu.add_command(label="Delete", command=self._history_delete)
        menu.post(event.x_root, event.y_root)
    
    def _history_load(self):
        """Load selected history item to entry"""
        selection = self.history_listbox.curselection()
        if selection:
            cmd = self.history_listbox.get(selection[0])
            self.command_entry.delete(0, tk.END)
            self.command_entry.insert(0, cmd)
            self.command_entry.focus()
    
    def _history_execute(self, event=None):
        """Execute selected history item"""
        selection = self.history_listbox.curselection()
        if selection:
            cmd = self.history_listbox.get(selection[0])
            self._execute_command(cmd)
    
    def _history_delete(self):
        """Delete selected history item"""
        selection = self.history_listbox.curselection()
        if selection:
            idx = selection[0]
            if messagebox.askyesno("Delete", "Delete this command from history?"):
                self.command_history.pop(idx)
                self._save_history()
                self._refresh_history_list()
    
    def _history_clear(self):
        """Clear all history"""
        if messagebox.askyesno("Clear History", "Clear all command history?"):
            self.command_history.clear()
            self._save_history()
            self._refresh_history_list()
    
    def _refresh_history_list(self):
        """Refresh history listbox"""
        self.history_listbox.delete(0, tk.END)
        for cmd in self.command_history:
            self.history_listbox.insert(tk.END, cmd)
    
    def _clear_output(self):
        """Clear output terminal"""
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, ">>> ")
        self.output_text.update_idletasks()
    
    def _load_history(self):
        """Load command history from file"""
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Handle different formats
                    if isinstance(data, list):
                        if not data:
                            return []
                        
                        # Check if it's new format (list of strings) or old format (list of objects)
                        first_item = data[0]
                        if isinstance(first_item, str):
                            # New format - return as is
                            return data
                        elif isinstance(first_item, dict):
                            # Old format - convert objects to command strings
                            commands = []
                            for item in data:
                                cmd = self._convert_old_command_format(item)
                                if cmd:
                                    commands.append(cmd)
                            return commands
                    elif isinstance(data, dict):
                        # Another old format {history: [...]}
                        history = data.get('history', [])
                        commands = []
                        for item in history:
                            if isinstance(item, dict):
                                cmd = self._convert_old_command_format(item)
                                if cmd:
                                    commands.append(cmd)
                            elif isinstance(item, str):
                                commands.append(item)
                        return commands
        except Exception as e:
            print(f"[Warning] Failed to load history: {e}")
        return []
    
    def _convert_old_command_format(self, item):
        """Convert old command format to command string"""
        try:
            # Check if it has the old structure
            if 'command' in item:
                return item['command']
            
            # Convert action-based format to command string
            action = item.get('action', '').upper()
            endpoint = item.get('endpoint', '')
            path = item.get('path', '')
            value = item.get('value', '')
            
            if action == 'GET' and endpoint and path:
                return f"get {endpoint} {path}"
            elif action == 'SET' and endpoint and path and value:
                return f"set {endpoint} {path} {value}"
            elif action == 'GET_INSTANCES' and endpoint and path:
                return f"get_instances {endpoint} {path}"
            elif action == 'GET_SUPPORTED' and endpoint and path:
                return f"get_supported {endpoint} {path}"
            elif action == 'ADD' and endpoint and path:
                return f"add {endpoint} {path}"
            elif action == 'DELETE' and endpoint and path:
                return f"delete {endpoint} {path}"
        except:
            pass
        return None
    
    def _save_history(self):
        """Save command history to file"""
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                # Save as simple list of command strings
                json.dump(self.command_history, f, indent=2, ensure_ascii=False)
        except:
            pass
    
    def update_endpoints(self, endpoints):
        """Update endpoint combobox with available devices"""
        # Always include test endpoint at the beginning
        test_endpoint = 'proto::test-agent'
        endpoint_list = [test_endpoint]
        
        # Add discovered endpoints
        if endpoints:
            for ep in endpoints:
                if ep != test_endpoint:  # Avoid duplicates
                    endpoint_list.append(ep)
        
        # Update combobox values
        current_value = self.endpoint_combo.get()
        self.endpoint_combo['values'] = endpoint_list
        
        # Restore previous selection if still valid, otherwise select first
        if current_value in endpoint_list:
            self.endpoint_combo.set(current_value)
        elif endpoint_list:
            self.endpoint_combo.current(0)
    
    def on_close(self):
        """Cleanup when page is closed"""
        self.polling = False


class USPControllerGUI:
    """Main GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title(f"USP Controller V{GUI_VERSION} - Multi-Page")
        self.root.geometry("1200x800")
        
        # Create menu
        self._create_menu()
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create pages (CLI first as default)
        self.cli_page = CLIPage(self.notebook, self)
        self.broker_page = BrokerPage(self.notebook, self)
        self.daemon_page = DaemonPage(self.notebook, self)
        
        # Add pages to notebook (CLI is first/default)
        self.notebook.add(self.cli_page, text="💻 CLI Terminal")
        self.notebook.add(self.daemon_page, text="⚙️ Daemon")
        self.notebook.add(self.broker_page, text="🔧 Mini Broker")
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready - Daemon: Not checked", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Auto startup sequence when GUI opens: mini-broker -> daemon
        self.root.after(300, self._auto_start_sequence)
        
        # Check daemon status after GUI loads
        self.root.after(500, self._check_daemon_status)

    def _auto_start_sequence(self):
        """Auto startup sequence: mini-broker first, then daemon."""
        self._auto_start_mini_broker()
        self.root.after(1200, lambda: self._auto_start_daemon_after_broker(retries=8))

    def _auto_start_mini_broker(self):
        """Auto-start mini-broker on GUI startup."""
        try:
            if getattr(self.broker_page, 'broker_running', False):
                return

            self.broker_page._log("[AUTO] Starting Mini-Broker on GUI startup...")
            self.broker_page._start_broker()
        except Exception as e:
            try:
                self.broker_page._log(f"[AUTO] Failed to start Mini-Broker: {e}")
            except Exception:
                pass

    def _auto_start_daemon_after_broker(self, retries=8):
        """Auto-start daemon after broker startup sequence (if daemon not already running)."""
        try:
            if self._is_daemon_running():
                try:
                    self.daemon_page._log("[AUTO] Daemon already running, skip auto-start", 'info')
                except Exception:
                    pass
                return

            # Wait until broker is running before starting daemon
            if not getattr(self.broker_page, 'broker_running', False):
                if retries > 0:
                    self.root.after(700, lambda: self._auto_start_daemon_after_broker(retries=retries - 1))
                else:
                    try:
                        self.daemon_page._log("[AUTO] Mini-Broker not ready, skip daemon auto-start", 'warning')
                    except Exception:
                        pass
                return

            try:
                self.daemon_page._log("[AUTO] Starting Daemon after Mini-Broker...", 'info')
            except Exception:
                pass
            self.daemon_page._start_daemon()
        except Exception as e:
            try:
                self.daemon_page._log(f"[AUTO] Failed to auto-start daemon: {e}", 'error')
            except Exception:
                pass

    def _is_daemon_running(self):
        """Check daemon runtime status via daemon page IPC client."""
        try:
            resp = self.daemon_page.ipc.send_command('status')
            return bool(resp and resp.get('status') == 'ok' and resp.get('daemon_running'))
        except Exception:
            return False
    
    def _check_daemon_status(self):
        """Check daemon status and update status bar"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((IPC_HOST, IPC_PORT))
                self.status_bar.config(text="Ready - Daemon: ✅ Running")
        except:
            self.status_bar.config(text="Ready - Daemon: ⚠️ Not running (start from Daemon tab if needed)")
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Reload Config", command=self._reload_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _reload_config(self):
        """Reload configuration"""
        # Invalidate cache and reload
        config_manager = ConfigManager()
        config_manager.invalidate_cache()
        
        self.daemon_page._display_config()
        # Reload broker config
        try:
            self.broker_page.config = config_manager.get_config(force_reload=True)
            # Update broker UI fields
            broker_config = self.broker_page.config.get('mini_broker', {})
            self.broker_page.host_entry.delete(0, tk.END)
            self.broker_page.host_entry.insert(0, broker_config.get('host', '0.0.0.0'))
            self.broker_page.port_entry.delete(0, tk.END)
            self.broker_page.port_entry.insert(0, str(broker_config.get('port', 61613)))
        except Exception as e:
            print(f"Error reloading broker config: {e}")
        messagebox.showinfo("Success", "Configuration reloaded from config.json")
    
    def _show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            f"USP Controller V{GUI_VERSION}\n"
            f"Build: {FULL_VERSION}\n\n"
            "Multi-Page Embedded Architecture\n"
            "- Broker Management\n"
            "- Daemon Control\n"
            "- CLI Interface\n\n"
            "© 2026"
        )

    def on_close(self):
        """Graceful GUI shutdown: stop polling, daemon and mini-broker."""
        try:
            self.status_bar.config(text="Shutting down services...")
        except Exception:
            pass

        # Stop CLI background polling first
        try:
            self.cli_page.on_close()
        except Exception:
            pass

        # Stop daemon via IPC first, then force-stop fallback
        try:
            resp = self.daemon_page.ipc.send_command('shutdown')
            if not (resp and resp.get('status') == 'ok'):
                self.daemon_page._force_stop_daemon()
            else:
                # Give daemon a short moment to exit cleanly
                time.sleep(0.4)
        except Exception:
            try:
                self.daemon_page._force_stop_daemon()
            except Exception:
                pass

        # Stop embedded mini-broker (if running in GUI process)
        try:
            if getattr(self.broker_page, 'broker_running', False) and getattr(self.broker_page, 'broker', None):
                self.broker_page._stop_broker()
        except Exception:
            pass

        try:
            self.root.destroy()
        except Exception:
            pass


def main():
    root = tk.Tk()
    app = USPControllerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
