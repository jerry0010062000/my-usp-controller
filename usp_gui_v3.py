#!/usr/bin/env python3
"""
USP Controller GUI V3.0 - Multi-Page Architecture
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
from pathlib import Path
from datetime import datetime

# Constants
HISTORY_FILE = 'command_history.json'
MAX_HISTORY = 50
IPC_HOST = '127.0.0.1'
IPC_PORT = 6001


class IPCClient:
    """IPC Client for communicating with daemon"""
    def __init__(self, host=IPC_HOST, port=IPC_PORT):
        self.host = host
        self.port = port
    
    def send_command(self, cmd):
        """Send command string and return JSON response. Blocking call."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(30.0)  # Extended timeout for GET/GetInstances (30s)
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
                
                if not data_chunks:
                    return None
                    
                data = b''.join(data_chunks).decode('utf-8')
                return json.loads(data)
        except socket.timeout:
            return {"status": "error", "msg": "Connection timeout (30s) - daemon may be busy"}
        except ConnectionRefusedError:
            return None
        except ConnectionResetError:
            return {"status": "error", "msg": "Connection reset by daemon"}
        except json.JSONDecodeError as e:
            return {"status": "error", "msg": f"Invalid response from daemon: {e}"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

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
    """Broker Management Page - Mini-Broker control and connection status"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.broker = None
        self.broker_thread = None
        self.broker_running = False
        
        self._create_widgets()
        self._load_config()
    
    def _create_widgets(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(title_frame, text="Broker Management", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        
        # Configuration Frame
        config_frame = ttk.LabelFrame(self, text="Broker Configuration", padding=10)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Mini-Broker Enable
        self.mini_broker_var = tk.BooleanVar()
        ttk.Checkbutton(
            config_frame,
            text="Enable Mini-Broker (Embedded STOMP 1.2)",
            variable=self.mini_broker_var,
            command=self._on_mini_broker_toggle
        ).grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Host
        ttk.Label(config_frame, text="Host:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.host_entry = ttk.Entry(config_frame, width=30)
        self.host_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Port
        ttk.Label(config_frame, text="Port:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_entry = ttk.Entry(config_frame, width=30)
        self.port_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # External Broker (shown when mini-broker disabled)
        ttk.Label(config_frame, text="External Broker:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.external_host_entry = ttk.Entry(config_frame, width=20)
        self.external_host_entry.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(config_frame, text="External Port:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.external_port_entry = ttk.Entry(config_frame, width=20)
        self.external_port_entry.grid(row=4, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(config_frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Broker", command=self._start_broker)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop Broker", command=self._stop_broker, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Save Config", command=self._save_config).pack(side=tk.LEFT, padx=5)
        
        # Status Frame
        status_frame = ttk.LabelFrame(self, text="Broker Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=15, state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True)
        
        self._log("Broker page initialized")
    
    def _load_config(self):
        """Load broker configuration"""
        config = load_config()
        if config:
            # Mini-broker config
            mini_broker = config.get('mini_broker', {})
            self.mini_broker_var.set(mini_broker.get('enable', False))
            self.host_entry.insert(0, mini_broker.get('host', '0.0.0.0'))
            self.port_entry.insert(0, str(mini_broker.get('port', 61613)))
            
            # External broker config
            usp_config = config.get('usp_controller', {})
            self.external_host_entry.insert(0, usp_config.get('broker_host', '127.0.0.1'))
            self.external_port_entry.insert(0, str(usp_config.get('broker_port', 61613)))
            
            self._on_mini_broker_toggle()
    
    def _on_mini_broker_toggle(self):
        """Toggle between mini-broker and external broker config"""
        enabled = self.mini_broker_var.get()
        state = tk.NORMAL if enabled else tk.DISABLED
        self.host_entry.config(state=state)
        self.port_entry.config(state=state)
        
        ext_state = tk.DISABLED if enabled else tk.NORMAL
        self.external_host_entry.config(state=ext_state)
        self.external_port_entry.config(state=ext_state)
    
    def _start_broker(self):
        """Start mini-broker"""
        if not BROKER_AVAILABLE:
            messagebox.showerror("Error", "Mini-Broker module not available")
            return
        
        if not self.mini_broker_var.get():
            messagebox.showwarning("Warning", "Mini-Broker is disabled in config")
            return
        
        if self.broker_running:
            messagebox.showinfo("Info", "Broker is already running")
            return
        
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            self._log(f"Starting Mini-Broker on {host}:{port}...")
            
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
            messagebox.showerror("Error", "Invalid port number")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start broker: {e}")
    
    def _check_broker_started(self):
        """Check if broker started successfully"""
        if self.broker_running:
            self._log("✅ Mini-Broker started successfully")
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
        else:
            self._log("❌ Mini-Broker failed to start")
    
    def _stop_broker(self):
        """Stop mini-broker"""
        if self.broker:
            self._log("Stopping Mini-Broker...")
            try:
                self.broker.stop()
                self.broker_running = False
                self._log("✅ Mini-Broker stopped")
                self.start_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
            except Exception as e:
                self._log(f"ERROR: {e}")
    
    def _save_config(self):
        """Save broker configuration"""
        try:
            config = load_config() or {"usp_controller": {}, "mini_broker": {}}
            
            # Update mini-broker config
            config['mini_broker'] = {
                'enable': self.mini_broker_var.get(),
                'host': self.host_entry.get(),
                'port': int(self.port_entry.get())
            }
            
            # Update external broker config
            if not self.mini_broker_var.get():
                config['usp_controller']['broker_host'] = self.external_host_entry.get()
                config['usp_controller']['broker_port'] = int(self.external_port_entry.get())
            
            if save_config(config):
                self._log("✅ Configuration saved")
                messagebox.showinfo("Success", "Configuration saved to config.json")
            else:
                self._log("❌ Failed to save configuration")
                messagebox.showerror("Error", "Failed to save configuration")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")
    
    def _log(self, message):
        """Log message to status text"""
        self.status_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)


class DaemonPage(ttk.Frame):
    """Daemon Management Page - Connection status and device management"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        
        self._create_widgets()
    
    def _create_widgets(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(title_frame, text="Daemon & Connection", font=('Arial', 14, 'bold')).pack(side=tk.LEFT)
        
        # Configuration Display
        config_frame = ttk.LabelFrame(self, text="Current Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.config_text = tk.Text(config_frame, height=8, state=tk.DISABLED, bg='#f0f0f0')
        self.config_text.pack(fill=tk.BOTH, expand=True)
        
        # Connection Control
        conn_frame = ttk.LabelFrame(self, text="Connection Control", padding=10)
        conn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="Connect", command=self._connect).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Disconnect", command=self._disconnect).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reconnect", command=self._reconnect).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reload Config", command=self._reload_config).pack(side=tk.LEFT, padx=5)
        
        # Status Indicator
        self.status_label = ttk.Label(conn_frame, text="Status: Disconnected", foreground='red')
        self.status_label.pack(pady=5)
        
        # Device List
        device_frame = ttk.LabelFrame(self, text="Discovered Devices", padding=10)
        device_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Device tree
        columns = ('endpoint', 'status', 'last_seen')
        self.device_tree = ttk.Treeview(device_frame, columns=columns, show='headings', height=10)
        self.device_tree.heading('endpoint', text='Endpoint ID')
        self.device_tree.heading('status', text='Status')
        self.device_tree.heading('last_seen', text='Last Seen')
        
        scrollbar = ttk.Scrollbar(device_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscroll=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load configuration
        self._display_config()
    
    def _display_config(self):
        """Display current configuration"""
        config = load_config()
        if config:
            self.config_text.config(state=tk.NORMAL)
            self.config_text.delete(1.0, tk.END)
            self.config_text.insert(1.0, json.dumps(config, indent=2))
            self.config_text.config(state=tk.DISABLED)
    
    def _connect(self):
        """Connect to broker"""
        messagebox.showinfo("Info", "Embedded connection will be implemented")
        # TODO: Implement embedded STOMP connection
    
    def _disconnect(self):
        """Disconnect from broker"""
        messagebox.showinfo("Info", "Disconnect will be implemented")
    
    def _reconnect(self):
        """Reconnect to broker"""
        self._disconnect()
        self._connect()
    
    def _reload_config(self):
        """Reload configuration"""
        self._display_config()
        messagebox.showinfo("Success", "Configuration reloaded")


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
        self.output_text.insert(tk.END, "  USP Controller CLI - Embedded Mode v3.0\n")
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
            self.output_text.insert(tk.END, "USP Controller GUI V3.0\n", 'info')
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
            # Execute command via IPC in background thread
            def execute_in_background():
                response = self.ipc.send_command(command)
                # Update UI in main thread
                self.after(0, lambda: self._display_response(command, response))
            
            threading.Thread(target=execute_in_background, daemon=True).start()
            
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n", 'error')
            self.output_text.insert(tk.END, "\n>>> ")
            self.output_text.see(tk.END)
    
    def _display_response(self, command, response):
        """Display command response in terminal"""
        if response is None:
            # Daemon not running - provide clear instructions
            self.output_text.insert(tk.END, "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n", 'error')
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
        else:
            # Error response
            self.output_text.insert(tk.END, f"❌ Error: {response.get('msg', 'Unknown error')}\n", 'error')
        
        self.output_text.insert(tk.END, "\n>>> ")
        self.output_text.see(tk.END)
        self.output_text.update_idletasks()
    
    def _display_status_response(self, response):
        """Display status command response"""
        self.output_text.insert(tk.END, "Connection Status:\n", 'info')
        self.output_text.insert(tk.END, f"  Connected: {response.get('connected', False)}\n", 'info')
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
  • USP commands require daemon to be running
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
        self.root.title("USP Controller V3.0 - Multi-Page")
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
        self.notebook.add(self.broker_page, text="🌐 Broker")
        self.notebook.add(self.daemon_page, text="⚙️ Daemon")
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready - Daemon: Not checked", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Check daemon status after GUI loads
        self.root.after(500, self._check_daemon_status)
    
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
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _reload_config(self):
        """Reload configuration"""
        self.daemon_page._display_config()
        self.broker_page._load_config()
        messagebox.showinfo("Success", "Configuration reloaded from config.json")
    
    def _show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            "USP Controller V3.0\n\n"
            "Multi-Page Embedded Architecture\n"
            "- Broker Management\n"
            "- Daemon Control\n"
            "- CLI Interface\n\n"
            "© 2026"
        )


def main():
    root = tk.Tk()
    app = USPControllerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
