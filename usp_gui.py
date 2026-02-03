#!/usr/bin/env python3
"""
USP Controller Windows UI (Tkinter)
Connects to 'usp_controller.py --daemon' via IPC (port 6001)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import json
import threading
import time
import queue
import os
import sys
from datetime import datetime

# Hide console window on Windows
if sys.platform == 'win32':
    import ctypes
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001
HISTORY_FILE = 'command_history.json'
MAX_HISTORY = 50

class IPCClient:
    def __init__(self, host=IPC_HOST, port=IPC_PORT):
        self.host = host
        self.port = port
    
    def send_command(self, cmd):
        """Send command string and return JSON response. Blocking call."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(20.0)  # Extended timeout for GET/GetInstances (15s) + buffer
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
            return {"status": "error", "msg": "Connection timeout (20s) - daemon may be busy"}
        except ConnectionRefusedError:
            return None
        except ConnectionResetError:
            return {"status": "error", "msg": "Connection reset by daemon"}
        except json.JSONDecodeError as e:
            return {"status": "error", "msg": f"Invalid response from daemon: {e}"}
        except Exception as e:
            return {"status": "error", "msg": str(e)}

class USPControllerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USP Controller GUI V2.0")
        self.root.geometry("1000x700")
        
        self.ipc = IPCClient()
        self.last_log_id = -1
        self.selected_device = None
        self.polling = True
        
        # Queues for thread processing
        self.log_queue = queue.Queue()
        self.status_queue = queue.Queue()
        
        # Command history
        self.command_history = self._load_history()
        
        self._setup_ui()
        
        # Start background polling thread
        self.poll_thread = threading.Thread(target=self._background_poller, daemon=True)
        self.poll_thread.start()
        
        # Start checking queues in main thread
        self.root.after(100, self._process_queues)

    def _setup_ui(self):
        # Configure grid weight
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # --- Top Bar: Connection Status ---
        top_frame = ttk.Frame(self.root, padding="5")
        top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        self.lbl_status = ttk.Label(top_frame, text="Checking daemon...", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side="left")
        
        btn_reconnect = ttk.Button(top_frame, text="Force Refresh", command=self._force_refresh)
        btn_reconnect.pack(side="right")
        
        # --- Left Panel: Devices ---
        left_panel = ttk.LabelFrame(self.root, text="Devices", padding="5")
        left_panel.grid(row=1, column=0, sticky="ns", padx=5, pady=5)
        
        # Device list with status indicators
        tree_frame = ttk.Frame(left_panel)
        tree_frame.pack(fill="both", expand=True)
        
        self.tree_devices = ttk.Treeview(tree_frame, columns=("Status",), show="tree", height=15)
        self.tree_devices.column("#0", width=200)
        self.tree_devices.column("Status", width=60, anchor="center")
        self.tree_devices.heading("#0", text="Endpoint ID")
        self.tree_devices.heading("Status", text="Status")
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_devices.yview)
        self.tree_devices.configure(yscrollcommand=scrollbar.set)
        
        self.tree_devices.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.tree_devices.bind('<<TreeviewSelect>>', self._on_device_select)
        
        # Device control buttons
        dev_btn_frame = ttk.Frame(left_panel)
        dev_btn_frame.pack(fill="x", pady=2)
        
        ttk.Button(dev_btn_frame, text="Refresh", command=self._refresh_devices).pack(side="left", fill="x", expand=True, padx=(0, 2))
        ttk.Button(dev_btn_frame, text="Delete", command=self._delete_device).pack(side="left", fill="x", expand=True, padx=(2, 0))

        # --- Right Panel: Controls & Logs ---
        right_panel = ttk.Frame(self.root, padding="5")
        right_panel.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        right_panel.rowconfigure(0, weight=1)
        right_panel.columnconfigure(0, weight=1)

        # Tabs
        self.tabs = ttk.Notebook(right_panel)
        self.tabs.grid(row=0, column=0, sticky="nsew")

        # Tab 1: Operations
        tab_ops = ttk.Frame(self.tabs, padding=5)
        self.tabs.add(tab_ops, text="Operations")
        
        # Grid for Tab 1
        tab_ops.columnconfigure(0, weight=3)
        tab_ops.columnconfigure(1, weight=1)
        tab_ops.rowconfigure(1, weight=1)

        # 1. Command Controls (Left side)
        cmd_frame = ttk.LabelFrame(tab_ops, text="Command Center", padding="10")
        cmd_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10), padx=(0, 5))
        
        # Row 1: Endpoint
        ttk.Label(cmd_frame, text="Target Endpoint:").grid(row=0, column=0, sticky="w")
        ep_row = ttk.Frame(cmd_frame)
        ep_row.grid(row=0, column=1, columnspan=2, sticky="ew", pady=2)
        self.cb_endpoint = ttk.Combobox(ep_row, width=37, state="readonly")
        self.cb_endpoint.pack(side="left", fill="x", expand=True)
        ttk.Button(ep_row, text="↻", width=3, command=self._refresh_devices).pack(side="left", padx=(2, 0))
        
        # Row 2: Operation
        ttk.Label(cmd_frame, text="Action:").grid(row=1, column=0, sticky="w")
        self.cb_action = ttk.Combobox(cmd_frame, values=["GET", "SET", "ADD", "DELETE", "OPERATE", "GetSupportedDM", "GetInstances"], state="readonly", width=15)
        self.cb_action.current(0)
        self.cb_action.grid(row=1, column=1, sticky="w", pady=2)
        self.cb_action.bind("<<ComboboxSelected>>", self._on_action_change)
        
        # Row 3: Path
        ttk.Label(cmd_frame, text="Path / Obj:").grid(row=2, column=0, sticky="w")
        self.ent_path = ttk.Entry(cmd_frame, width=50)
        self.ent_path.grid(row=2, column=1, columnspan=2, sticky="ew", pady=2)
        self.ent_path.bind("<Return>", lambda e: self._send_command())
        
        # Row 4: Value (Dynamic)
        self.lbl_value = ttk.Label(cmd_frame, text="Value:")
        self.lbl_value.grid(row=3, column=0, sticky="w")
        self.ent_value = ttk.Entry(cmd_frame)
        self.ent_value.grid(row=3, column=1, columnspan=2, sticky="ew", pady=2)
        self.ent_value.bind("<Return>", lambda e: self._send_command())
        
        # Row 5: Send Button
        self.btn_send = ttk.Button(cmd_frame, text="Execute Command", command=self._send_command)
        self.btn_send.grid(row=4, column=1, sticky="e", pady=5)
        
        # 1.5. Command History (Right side)
        history_frame = ttk.LabelFrame(tab_ops, text="Command History", padding="5")
        history_frame.grid(row=0, column=1, rowspan=1, sticky="nsew", pady=(0, 10))
        
        # History list
        hist_scroll_frame = ttk.Frame(history_frame)
        hist_scroll_frame.pack(fill="both", expand=True)
        
        hist_scrollbar = ttk.Scrollbar(hist_scroll_frame, orient="vertical")
        self.lst_history = tk.Listbox(hist_scroll_frame, yscrollcommand=hist_scrollbar.set, font=("Consolas", 8))
        hist_scrollbar.config(command=self.lst_history.yview)
        
        self.lst_history.pack(side="left", fill="both", expand=True)
        hist_scrollbar.pack(side="right", fill="y")
        
        # Bind events
        self.lst_history.bind('<Double-Button-1>', self._history_double_click)
        self.lst_history.bind('<Button-3>', self._history_right_click)
        
        # History controls
        hist_btn_frame = ttk.Frame(history_frame)
        hist_btn_frame.pack(fill="x", pady=(5, 0))
        
        ttk.Button(hist_btn_frame, text="Load", command=self._history_load, width=7).pack(side="left", padx=2)
        ttk.Button(hist_btn_frame, text="Execute", command=self._history_execute, width=7).pack(side="left", padx=2)
        ttk.Button(hist_btn_frame, text="Delete", command=self._history_delete_selected, width=7).pack(side="left", padx=2)
        ttk.Button(hist_btn_frame, text="Clear", command=self._history_clear, width=7).pack(side="left", padx=2)
        
        # Load history into listbox
        self._refresh_history_list()
        
        # 2. Log Area (Inside Tab 1)
        log_frame = ttk.LabelFrame(tab_ops, text="Controller Logs & Responses", padding="5")
        log_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        
        # Log Controls (at top of log frame)
        log_ctrl_frame = ttk.Frame(log_frame)
        log_ctrl_frame.pack(fill="x", side="top", pady=(0, 5))
        
        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_ctrl_frame, text="Auto-scroll", variable=self.var_autoscroll).pack(side="left")
        ttk.Button(log_ctrl_frame, text="Clear Logs", command=self._clear_logs).pack(side="left", padx=5)
        
        # Text widget
        self.txt_log = scrolledtext.ScrolledText(log_frame, state='disabled', font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, side="bottom")
        self._add_text_context_menu(self.txt_log)


        # Tab 2: Settings & Debug
        tab_settings = ttk.Frame(self.tabs, padding=20)
        self.tabs.add(tab_settings, text="Settings & Debug")
        
        # Tab 3: mDNS Debug
        tab_mdns = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab_mdns, text="mDNS Debug")
        
        # Tab 4: Test Scripts
        tab_scripts = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab_scripts, text="Test Scripts")
        
        # Test Scripts Tab Layout
        tab_scripts.columnconfigure(0, weight=1)
        tab_scripts.rowconfigure(1, weight=1)
        
        # Script Controls
        script_ctrl_frame = ttk.LabelFrame(tab_scripts, text="Test Script Runner", padding=10)
        script_ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Script selection
        script_select_frame = ttk.Frame(script_ctrl_frame)
        script_select_frame.pack(fill="x", pady=(0, 5))
        
        ttk.Label(script_select_frame, text="Select Script:").pack(side="left", padx=(0, 5))
        self.cb_script = ttk.Combobox(script_select_frame, state="readonly", width=40)
        self.cb_script.pack(side="left", padx=(0, 5))
        ttk.Button(script_select_frame, text="🔄 Refresh", command=self._refresh_script_list).pack(side="left")
        
        # Target endpoint selection
        endpoint_select_frame = ttk.Frame(script_ctrl_frame)
        endpoint_select_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(endpoint_select_frame, text="Target Device:").pack(side="left", padx=(0, 5))
        self.cb_script_endpoint = ttk.Combobox(endpoint_select_frame, state="readonly", width=40)
        self.cb_script_endpoint.pack(side="left", padx=(0, 5))
        ttk.Button(endpoint_select_frame, text="🔄 Refresh", command=self._refresh_devices).pack(side="left")
        
        # Script controls
        script_btn_frame = ttk.Frame(script_ctrl_frame)
        script_btn_frame.pack(fill="x", pady=(0, 10))
        
        self.btn_run_script = ttk.Button(script_btn_frame, text="▶ Run Script", command=self._run_script, width=15)
        self.btn_run_script.pack(side="left", padx=2)
        
        self.btn_stop_script = ttk.Button(script_btn_frame, text="■ Stop", command=self._stop_script, width=15, state='disabled')
        self.btn_stop_script.pack(side="left", padx=2)
        
        ttk.Button(script_btn_frame, text="📂 Open Folder", command=self._open_script_folder, width=15).pack(side="left", padx=2)
        ttk.Button(script_btn_frame, text="🗑 Clear Log", command=self._clear_script_log, width=15).pack(side="left", padx=2)
        
        # Progress bar
        self.script_progress = ttk.Progressbar(script_ctrl_frame, mode='indeterminate')
        self.script_progress.pack(fill="x", pady=(0, 5))
        
        # Status label
        self.lbl_script_status = ttk.Label(script_ctrl_frame, text="Ready", font=("Segoe UI", 9))
        self.lbl_script_status.pack(anchor="w")
        
        # Script output log
        log_frame = ttk.LabelFrame(tab_scripts, text="Script Output", padding=5)
        log_frame.grid(row=1, column=0, sticky="nsew")
        
        self.txt_script_log = scrolledtext.ScrolledText(log_frame, state='disabled', font=("Consolas", 9), height=20)
        self.txt_script_log.pack(fill="both", expand=True)
        self._add_text_context_menu(self.txt_script_log)
        
        # Configure log tags
        self.txt_script_log.tag_config('success', foreground='green')
        self.txt_script_log.tag_config('error', foreground='red', font=("Consolas", 9, "bold"))
        self.txt_script_log.tag_config('command', foreground='blue')
        self.txt_script_log.tag_config('comment', foreground='gray')
        self.txt_script_log.tag_config('info', foreground='black')
        
        # Script runner state
        self.script_running = False
        self.script_thread = None
        self.script_variables = {}  # Store variables for substitution
        
        # mDNS Debug Tab Layout
        tab_mdns.columnconfigure(0, weight=1)
        tab_mdns.rowconfigure(2, weight=1)
        
        # Status and Controls
        mdns_ctrl_frame = ttk.LabelFrame(tab_mdns, text="mDNS Discovery Control", padding=10)
        mdns_ctrl_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        self.lbl_mdns_status_debug = ttk.Label(mdns_ctrl_frame, text="Status: Checking...", font=("Segoe UI", 10, "bold"))
        self.lbl_mdns_status_debug.pack(anchor="w", pady=(0, 10))
        
        mdns_debug_btn_frame = ttk.Frame(mdns_ctrl_frame)
        mdns_debug_btn_frame.pack(fill="x")
        
        self.btn_mdns_start_debug = ttk.Button(mdns_debug_btn_frame, text="▶ Start Listener", command=self._mdns_start, width=15)
        self.btn_mdns_start_debug.pack(side="left", padx=2)
        
        self.btn_mdns_stop_debug = ttk.Button(mdns_debug_btn_frame, text="■ Stop Listener", command=self._mdns_stop, width=15)
        self.btn_mdns_stop_debug.pack(side="left", padx=2)
        
        self.btn_mdns_scan_debug = ttk.Button(mdns_debug_btn_frame, text="🔍 Scan Now", command=self._mdns_scan_debug, width=15)
        self.btn_mdns_scan_debug.pack(side="left", padx=2)
        
        self.btn_mdns_refresh_debug = ttk.Button(mdns_debug_btn_frame, text="🔄 Refresh Status", command=self._mdns_refresh_debug, width=15)
        self.btn_mdns_refresh_debug.pack(side="left", padx=2)
        
        ttk.Button(mdns_debug_btn_frame, text="🗑 Clear Logs", command=self._mdns_clear_logs, width=15).pack(side="left", padx=2)
        
        # Discovered Services Table
        services_frame = ttk.LabelFrame(tab_mdns, text="Discovered Services", padding=5)
        services_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        # Treeview for services
        services_tree_frame = ttk.Frame(services_frame)
        services_tree_frame.pack(fill="both", expand=True)
        
        self.tree_mdns_services = ttk.Treeview(services_tree_frame, 
                                                columns=("Address", "Port", "Path", "Status"), 
                                                show="tree headings", height=6)
        self.tree_mdns_services.column("#0", width=250)
        self.tree_mdns_services.column("Address", width=120, anchor="center")
        self.tree_mdns_services.column("Port", width=60, anchor="center")
        self.tree_mdns_services.column("Path", width=80, anchor="center")
        self.tree_mdns_services.column("Status", width=80, anchor="center")
        
        self.tree_mdns_services.heading("#0", text="Endpoint ID")
        self.tree_mdns_services.heading("Address", text="Address")
        self.tree_mdns_services.heading("Port", text="Port")
        self.tree_mdns_services.heading("Path", text="Path")
        self.tree_mdns_services.heading("Status", text="Status")
        
        services_scrollbar = ttk.Scrollbar(services_tree_frame, orient="vertical", command=self.tree_mdns_services.yview)
        self.tree_mdns_services.configure(yscrollcommand=services_scrollbar.set)
        
        self.tree_mdns_services.pack(side="left", fill="both", expand=True)
        services_scrollbar.pack(side="right", fill="y")
        
        # Bind selection to show details
        self.tree_mdns_services.bind('<<TreeviewSelect>>', self._mdns_service_selected)
        
        # Discovery Logs
        logs_frame = ttk.LabelFrame(tab_mdns, text="Discovery Logs & Events", padding=5)
        logs_frame.grid(row=2, column=0, sticky="nsew")
        
        # Log controls
        log_ctrl = ttk.Frame(logs_frame)
        log_ctrl.pack(fill="x", pady=(0, 5))
        
        self.var_mdns_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_ctrl, text="Auto-scroll", variable=self.var_mdns_autoscroll).pack(side="left")
        
        ttk.Label(log_ctrl, text="Filter:").pack(side="left", padx=(20, 5))
        self.cb_mdns_filter = ttk.Combobox(log_ctrl, values=["All", "Discovered", "Updated", "Removed", "Errors"], 
                                           state="readonly", width=12)
        self.cb_mdns_filter.current(0)
        self.cb_mdns_filter.pack(side="left")
        
        # Log text widget
        self.txt_mdns_log = scrolledtext.ScrolledText(logs_frame, state='disabled', font=("Consolas", 9), height=12)
        self.txt_mdns_log.pack(fill="both", expand=True)
        self._add_text_context_menu(self.txt_mdns_log)
        
        # Configure log tags
        self.txt_mdns_log.tag_config('discovered', foreground='green')
        self.txt_mdns_log.tag_config('updated', foreground='blue')
        self.txt_mdns_log.tag_config('removed', foreground='red')
        self.txt_mdns_log.tag_config('error', foreground='red', font=("Consolas", 9, "bold"))
        self.txt_mdns_log.tag_config('info', foreground='black')
        self.txt_mdns_log.tag_config('timestamp', foreground='gray')
        
        # Make tab_settings scrollable
        canvas = tk.Canvas(tab_settings)
        scrollbar_settings = ttk.Scrollbar(tab_settings, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar_settings.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar_settings.pack(side="right", fill="y")
        
        # Config Editor (Editable)
        conf_frame = ttk.LabelFrame(scrollable_frame, text="Configuration Editor", padding=10)
        conf_frame.pack(fill="x", pady=10)
        
        # Subscription Status (Read-only, above config editor)
        sub_frame = ttk.LabelFrame(scrollable_frame, text="Active STOMP Subscriptions", padding=10)
        sub_frame.pack(fill="x", pady=(0, 10))
        
        sub_info = ttk.Frame(sub_frame)
        sub_info.pack(fill="x")
        
        ttk.Label(sub_info, text="Subscribed Queues:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.lbl_subscriptions = ttk.Label(sub_info, text="Loading...", font=("Consolas", 9), foreground="blue")
        self.lbl_subscriptions.pack(anchor="w", pady=(5, 0))
        
        ttk.Button(sub_info, text="🔄 Refresh Subscriptions", command=self._refresh_subscriptions).pack(anchor="w", pady=(5, 0))
        
        # Inner frame for grid layout
        conf_grid = ttk.Frame(conf_frame)
        conf_grid.pack(fill="x", expand=True)
        
        ttk.Label(conf_grid, text="⚠ Changes require daemon restart to take effect", foreground="orange").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        
        # Broker Host
        row = 1
        ttk.Label(conf_grid, text="Broker Host:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_broker_host = ttk.Entry(conf_grid, width=30)
        self.ent_broker_host.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # Broker Port
        row += 1
        ttk.Label(conf_grid, text="Broker Port:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_broker_port = ttk.Entry(conf_grid, width=30)
        self.ent_broker_port.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # Username
        row += 1
        ttk.Label(conf_grid, text="Username:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_username = ttk.Entry(conf_grid, width=30)
        self.ent_username.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # Password
        row += 1
        ttk.Label(conf_grid, text="Password:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_password = ttk.Entry(conf_grid, width=30, show="*")
        self.ent_password.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # Controller ID
        row += 1
        ttk.Label(conf_grid, text="Controller ID:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_ctrl_id = ttk.Entry(conf_grid, width=30)
        self.ent_ctrl_id.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # Receive Topic
        row += 1
        ttk.Label(conf_grid, text="Receive Topic:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_topic = ttk.Entry(conf_grid, width=30)
        self.ent_topic.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        # IPC Port
        row += 1
        ttk.Label(conf_grid, text="IPC Port:").grid(row=row, column=0, sticky="w", pady=5)
        self.ent_ipc_port = ttk.Entry(conf_grid, width=30)
        self.ent_ipc_port.grid(row=row, column=1, sticky="ew", pady=5, padx=5)
        
        conf_grid.columnconfigure(1, weight=1)
        
        # Buttons
        btn_frame = ttk.Frame(conf_frame)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Load from Daemon", command=self._refresh_config).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Save Configuration", command=self._save_config).pack(side="left", padx=5)

        # Broker Status Section
        broker_status_frame = ttk.LabelFrame(scrollable_frame, text="STOMP Broker Status", padding=10)
        broker_status_frame.pack(fill="x", pady=10)
        
        self.lbl_broker_conn = ttk.Label(broker_status_frame, text="Connection: Checking...", font=("Segoe UI", 9))
        self.lbl_broker_conn.pack(anchor="w", pady=2)
        
        self.lbl_broker_addr = ttk.Label(broker_status_frame, text="Address: N/A", font=("Segoe UI", 9))
        self.lbl_broker_addr.pack(anchor="w", pady=2)
        
        self.lbl_broker_user = ttk.Label(broker_status_frame, text="Username: N/A", font=("Segoe UI", 9))
        self.lbl_broker_user.pack(anchor="w", pady=2)
        
        self.txt_broker_log = tk.Text(broker_status_frame, height=4, state='disabled', font=("Consolas", 8), bg="#f0f0f0")
        self.txt_broker_log.pack(fill="x", pady=(5, 0))
        
        ttk.Label(broker_status_frame, text="Recent connection messages", font=("Segoe UI", 8), foreground="gray").pack(anchor="w")

        # Debug Control
        dbg_frame = ttk.LabelFrame(scrollable_frame, text="Runtime Debug Control", padding=10)
        dbg_frame.pack(fill="x", pady=10)
        
        ttk.Label(dbg_frame, text="Debug Level:").pack(anchor="w")
        self.var_debug = tk.IntVar(value=-1)
        
        ttk.Radiobutton(dbg_frame, text="Level 0: Agent Response Only (Quiet)", variable=self.var_debug, value=0, command=self._set_debug_level).pack(anchor="w", padx=20)
        ttk.Radiobutton(dbg_frame, text="Level 1: USP Messages (Standard)", variable=self.var_debug, value=1, command=self._set_debug_level).pack(anchor="w", padx=20)
        ttk.Radiobutton(dbg_frame, text="Level 2: Full STOMP Frames (Verbose)", variable=self.var_debug, value=2, command=self._set_debug_level).pack(anchor="w", padx=20)
        
        # Connection Control
        conn_frame = ttk.LabelFrame(scrollable_frame, text="Connection Management", padding=10)
        conn_frame.pack(fill="x", pady=10)
        
        ttk.Label(conn_frame, text="If broker connection is lost, you can attempt reconnection here:").pack(anchor="w")
        ttk.Button(conn_frame, text="Reconnect to STOMP Broker", command=self._reconnect_stomp).pack(anchor="w", pady=5)
        
        # mDNS Discovery Control
        mdns_frame = ttk.LabelFrame(scrollable_frame, text="mDNS Agent Discovery", padding=10)
        mdns_frame.pack(fill="x", pady=10)
        
        ttk.Label(mdns_frame, text="Automatically discover USP agents on the local network using mDNS/Zeroconf").pack(anchor="w", pady=(0, 5))
        
        self.lbl_mdns_status = ttk.Label(mdns_frame, text="Status: Checking...", font=("Segoe UI", 9))
        self.lbl_mdns_status.pack(anchor="w", pady=2)
        
        mdns_btn_frame = ttk.Frame(mdns_frame)
        mdns_btn_frame.pack(anchor="w", pady=5)
        
        ttk.Button(mdns_btn_frame, text="Start Discovery", command=self._mdns_start).pack(side="left", padx=(0, 5))
        ttk.Button(mdns_btn_frame, text="Stop Discovery", command=self._mdns_stop).pack(side="left", padx=5)
        ttk.Button(mdns_btn_frame, text="Scan Now", command=self._mdns_scan).pack(side="left", padx=5)
        ttk.Button(mdns_btn_frame, text="Check Status", command=self._mdns_check_status).pack(side="left", padx=5)
        
        # Scan results display
        ttk.Label(mdns_frame, text="Last scan results:", font=("Segoe UI", 8)).pack(anchor="w", pady=(10, 2))
        self.txt_mdns_results = tk.Text(mdns_frame, height=4, state='disabled', font=("Consolas", 8), bg="#f0f0f0")
        self.txt_mdns_results.pack(fill="x")
        self._add_text_context_menu(self.txt_mdns_results)

        # Initial config load
        self.root.after(2000, self._refresh_config)
        self.root.after(3000, self._mdns_check_status)
        self.root.after(1000, self._refresh_script_list)
        self.root.after(500, self._refresh_devices)
        self.root.after(600, self._sync_script_endpoint)

    def _refresh_devices(self):
        """Refresh list of available devices from devices.json"""
        devices_file = os.path.join(os.path.dirname(__file__), 'devices.json')
        if not os.path.exists(devices_file):
            self.cb_endpoint['values'] = []
            if hasattr(self, 'cb_script_endpoint'):
                self.cb_script_endpoint['values'] = []
            return
        
        try:
            with open(devices_file, 'r', encoding='utf-8') as f:
                devices = json.load(f)
            
            device_list = list(devices.keys())
            self.cb_endpoint['values'] = device_list
            if hasattr(self, 'cb_script_endpoint'):
                self.cb_script_endpoint['values'] = device_list
            
            # Auto-select first device if nothing is selected
            if device_list and not self.cb_endpoint.get():
                self.cb_endpoint.current(0)
            if hasattr(self, 'cb_script_endpoint') and device_list and not self.cb_script_endpoint.get():
                self.cb_script_endpoint.current(0)
        except Exception as e:
            self.cb_endpoint['values'] = []
            if hasattr(self, 'cb_script_endpoint'):
                self.cb_script_endpoint['values'] = []
    
    def _sync_script_endpoint(self):
        """Sync script endpoint with main endpoint selector"""
        if hasattr(self, 'cb_script_endpoint') and self.cb_endpoint.get() and not self.cb_script_endpoint.get():
            endpoint = self.cb_endpoint.get()
            if endpoint in self.cb_script_endpoint['values']:
                self.cb_script_endpoint.set(endpoint)
    
    def _refresh_script_list(self):
        """Refresh list of available test scripts"""
        import os
        script_dir = os.path.join(os.path.dirname(__file__), 'scripts')
        if not os.path.exists(script_dir):
            return
        
        try:
            scripts = [f for f in os.listdir(script_dir) if f.endswith('.txt')]
            self.cb_script['values'] = scripts
            if scripts and not self.cb_script.get():
                self.cb_script.current(0)
        except Exception as e:
            pass
    
    def _open_script_folder(self):
        """Open scripts folder in file explorer"""
        import os
        import subprocess
        script_dir = os.path.join(os.path.dirname(__file__), 'scripts')
        if os.path.exists(script_dir):
            if sys.platform == 'win32':
                os.startfile(script_dir)
            else:
                subprocess.run(['xdg-open', script_dir])
    
    def _clear_script_log(self):
        """Clear script output log"""
        self.txt_script_log.configure(state='normal')
        self.txt_script_log.delete(1.0, tk.END)
        self.txt_script_log.configure(state='disabled')
    
    def _run_script(self):
        """Run selected test script"""
        script_name = self.cb_script.get()
        if not script_name:
            messagebox.showwarning("No Script", "Please select a script to run")
            return
        
        endpoint = self.cb_script_endpoint.get()
        if not endpoint:
            messagebox.showwarning("No Device", "Please select a target device")
            return
        
        if self.script_running:
            messagebox.showinfo("Script Running", "A script is already running")
            return
        
        self.script_running = True
        self.btn_run_script.configure(state='disabled')
        self.btn_stop_script.configure(state='normal')
        self.script_progress.start(10)
        
        self._clear_script_log()
        self._script_log(f"Starting script: {script_name}\n", 'info')
        self._script_log(f"Target device: {endpoint}\n\n", 'info')
        
        # Reset script variables
        self.script_variables = {}
        
        self.script_thread = threading.Thread(target=self._run_script_thread, args=(script_name, endpoint), daemon=True)
        self.script_thread.start()
    
    def _stop_script(self):
        """Stop running script"""
        self.script_running = False
        self._script_log("\n[STOPPED] Script execution stopped by user\n", 'error')
    
    def _run_script_thread(self, script_name, endpoint):
        """Execute script in background thread"""
        import os
        script_path = os.path.join(os.path.dirname(__file__), 'scripts', script_name)
        
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            executed = 0
            failed = 0
            
            for i, line in enumerate(lines, 1):
                if not self.script_running:
                    break
                
                line = line.strip()
                
                # Print comments
                if line.startswith('#'):
                    self._script_log(f"{line}\n", 'comment')
                    continue
                
                # Skip empty lines
                if not line:
                    continue
                
                # Replace endpoint variable
                line = line.replace('{ENDPOINT}', endpoint)
                
                # Replace other variables
                for var_name, var_value in self.script_variables.items():
                    line = line.replace(f'{{{var_name}}}', str(var_value))
                
                # Parse and execute command
                result = self._parse_script_line(line)
                if not result:
                    continue
                
                # Unpack command and expected value
                if isinstance(result, tuple):
                    cmd, expected_value = result
                else:
                    cmd = result
                    expected_value = None
                
                self._script_log(f"[{i}] {cmd}\n", 'command')
                if expected_value:
                    self._script_log(f"    Expected: {expected_value}\n", 'info')
                self.lbl_script_status.config(text=f"Executing command {i}...")
                
                try:
                    resp = self.ipc.send_command(cmd)
                    
                    # Handle connection errors
                    if resp is None:
                        self._script_log(f"    ✗ CONNECTION ERROR: Cannot connect to daemon\n", 'error')
                        failed += 1
                        # Give daemon a moment to recover
                        time.sleep(1.0)
                        continue
                    
                    # Handle duplicate request errors (skip to next command)
                    if resp.get('status') == 'error' and 'Duplicate request' in resp.get('msg', ''):
                        self._script_log(f"    ⚠ SKIPPED: {resp.get('msg')}\n", 'error')
                        time.sleep(0.5)
                        continue
                    
                    if resp and resp.get('status') == 'ok':
                        actual_value = resp.get('msg', 'OK')
                        self._script_log(f"    ✓ SUCCESS: {actual_value}\n", 'success')
                        
                        # Try to extract instance number for ADD or GetInstances commands
                        if 'add' in cmd.lower() or 'get_instances' in cmd.lower():
                            # Try to extract from response dict first
                            instance_num = self._extract_instance_number(resp, cmd)
                            if instance_num:
                                self.script_variables['INSTANCE'] = instance_num
                                self._script_log(f"    → Saved INSTANCE={instance_num}\n", 'info')
                        
                        # Check expected value if specified
                        if expected_value:
                            actual_str = str(actual_value).strip()
                            expected_str = expected_value.strip()
                            
                            if expected_str.lower() in actual_str.lower():
                                self._script_log(f"    ✓ ASSERTION PASSED\n", 'success')
                                executed += 1
                            else:
                                self._script_log(f"    ✗ ASSERTION FAILED\n", 'error')
                                self._script_log(f"      Expected: {expected_str}\n", 'error')
                                self._script_log(f"      Got: {actual_str}\n", 'error')
                                failed += 1
                        else:
                            executed += 1
                    else:
                        error_msg = resp.get('msg', 'Unknown error') if resp else 'No response'
                        self._script_log(f"    ✗ FAILED: {error_msg}\n", 'error')
                        failed += 1
                except Exception as e:
                    self._script_log(f"    ✗ ERROR: {e}\n", 'error')
                    failed += 1
                
                time.sleep(0.5)  # Delay between commands
            
            # Summary
            self._script_log(f"\n{'='*60}\n", 'info')
            self._script_log(f"[SUMMARY]\n", 'info')
            self._script_log(f"  Executed: {executed}\n", 'success')
            self._script_log(f"  Failed:   {failed}\n", 'error' if failed > 0 else 'info')
            self._script_log(f"{'='*60}\n", 'info')
            
            self.lbl_script_status.config(text=f"Completed: {executed} success, {failed} failed")
            
        except Exception as e:
            self._script_log(f"\n[ERROR] Failed to run script: {e}\n", 'error')
            self.lbl_script_status.config(text="Error occurred")
        finally:
            self.script_running = False
            self.btn_run_script.configure(state='normal')
            self.btn_stop_script.configure(state='disabled')
            self.script_progress.stop()
    
    def _extract_instance_number(self, response, cmd):
        """Extract instance number from add/get_instances response"""
        import re
        
        # For response dict with 'instances' key (from GetInstances)
        if isinstance(response, dict) and 'instances' in response:
            instances = response.get('instances', [])
            if instances:
                # Return the last instance (usually the most recently created)
                return instances[-1]
        
        # For response text
        response_msg = response.get('msg', '') if isinstance(response, dict) else str(response)
        
        # For ADD responses, look for "created instance X"
        if 'instance' in response_msg.lower():
            match = re.search(r'instance[:\s]+(\d+)', response_msg, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Extract path from command to look for instance numbers
        cmd_parts = cmd.split()
        if len(cmd_parts) >= 3:
            path = cmd_parts[2]
            # For GetInstances, try to find instance number in response
            # Look for pattern like "Pool.2." in the response
            if path.endswith('.'):
                base_obj = path.rstrip('.')
                pattern = re.escape(base_obj) + r'\.(\d+)\.'
                match = re.search(pattern, response_msg)
                if match:
                    return match.group(1)
        
        return None
    
    def _parse_script_line(self, line):
        """Parse script line into IPC command"""
        # Check for expected value assertion
        expected_value = None
        if '# expect:' in line or '# EXPECT:' in line:
            parts_split = line.split('#')
            line = parts_split[0].strip()
            expect_part = parts_split[1].strip()
            if expect_part.lower().startswith('expect:'):
                expected_value = expect_part[7:].strip()
        
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            return None
        
        cmd = parts[0].lower()
        endpoint = parts[1]
        path = parts[2]
        value = parts[3] if len(parts) > 3 else ""
        
        if cmd in ['get', 'get_supported', 'get_instances', 'add', 'delete']:
            return (f"{cmd} {endpoint} {path}", expected_value)
        elif cmd == 'set':
            # SET command requires a value
            if len(parts) < 4 or not value.strip():
                self._script_log(f"    [WARNING] SET command missing value\n", 'error')
                return None
            return (f"{cmd} {endpoint} {path} {value}", expected_value)
        else:
            self._script_log(f"    [WARNING] Unknown command: {cmd}\n", 'error')
            return None
    
    def _script_log(self, text, tag='info'):
        """Append text to script log with tag"""
        self.txt_script_log.configure(state='normal')
        self.txt_script_log.insert(tk.END, text, tag)
        self.txt_script_log.see(tk.END)
        self.txt_script_log.configure(state='disabled')

    def _get_tag_for_type(self, log_type):
        """Return color tag for log type"""
        if log_type == 'error' or log_type == 'critical': return 'error'
        if log_type == 'usp': return 'usp'
        if log_type == 'data': return 'data'
        if log_type == 'success': return 'success'
        if log_type == 'detail': return 'detail'
        return 'info'

    def _setup_log_tags(self):
        self.txt_log.tag_config('error', foreground='red')
        self.txt_log.tag_config('usp', foreground='blue')
        self.txt_log.tag_config('data', foreground='darkgreen')
        self.txt_log.tag_config('success', foreground='green')
        self.txt_log.tag_config('detail', foreground='gray')
        self.txt_log.tag_config('info', foreground='black')

    def _append_log(self, time_str, log_type, msg):
        self.txt_log.configure(state='normal')
        tag = self._get_tag_for_type(log_type)
        self.txt_log.insert(tk.END, f"[{time_str}] ", 'info')
        self.txt_log.insert(tk.END, f"{msg}\n", tag)
        if self.var_autoscroll.get():
            self.txt_log.see(tk.END)
        self.txt_log.configure(state='disabled')
        
        # Also update broker log if it's broker-related message
        if 'broker' in msg.lower() or 'stomp' in msg.lower() or 'connect' in msg.lower():
            try:
                self.txt_broker_log.configure(state='normal')
                self.txt_broker_log.insert(tk.END, f"[{time_str}] {msg}\n")
                # Keep only last 4 lines
                line_count = int(self.txt_broker_log.index('end-1c').split('.')[0])
                if line_count > 4:
                    self.txt_broker_log.delete('1.0', f'{line_count-4}.0')
                self.txt_broker_log.see(tk.END)
                self.txt_broker_log.configure(state='disabled')
            except:
                pass

    def _clear_logs(self):
        self.txt_log.configure(state='normal')
        self.txt_log.delete(1.0, tk.END)
        self.txt_log.configure(state='disabled')

    def _on_action_change(self, event):
        action = self.cb_action.get()
        if action in ["GET", "ADD", "DELETE", "GetSupportedDM", "GetInstances"]:
            self.ent_value.configure(state='disabled')
        else:
            self.ent_value.configure(state='normal')

    def _on_device_select(self, event):
        selection = self.tree_devices.selection()
        if selection:
            item_id = selection[0]
            # Get the endpoint ID from the item
            ep_id = self.tree_devices.item(item_id, "text")
            # Set endpoint from device list
            if ep_id in self.cb_endpoint['values']:
                self.cb_endpoint.set(ep_id)
            else:
                # If not in list, refresh and try again
                self._refresh_devices()
                if ep_id in self.cb_endpoint['values']:
                    self.cb_endpoint.set(ep_id)

    def _poll_status_loop(self):
        # Legacy: handled by background thread now
        pass

    def _poll_logs_loop(self):
        # Legacy: handled by background thread now
        pass
    
    def _background_poller(self):
        """Thread that handles all network IO"""
        last_status_time = 0
        
        while self.polling:
            now = time.time()
            
            # 1. Poll Status every 5 seconds
            if now - last_status_time > 5:
                try:
                    resp = self.ipc.send_command("status")
                    if resp and resp.get("status") == "ok":
                        # Also fetch devices if connected
                        dev_resp = self.ipc.send_command("devices")
                        if dev_resp and dev_resp.get("status") == "ok":
                            resp['devices'] = dev_resp.get('devices')
                    self.status_queue.put(resp)
                except Exception as e:
                    self.status_queue.put(None)
                last_status_time = now
            
            # 2. Poll Logs every 0.5 seconds
            try:
                resp = self.ipc.send_command(f"poll_logs {self.last_log_id}")
                if resp and resp.get("status") == "ok":
                    self.log_queue.put(resp)
            except:
                pass
                
            time.sleep(0.5)

    def _process_queues(self):
        """Main thread function to update UI from queues"""
        
        # Handle Logs (limit processing per cycle to keep UI responsive)
        logs_processed = 0
        max_logs_per_cycle = 50  # Process max 50 logs per cycle
        try:
            while logs_processed < max_logs_per_cycle:
                # Get all available log updates without blocking
                log_data = self.log_queue.get_nowait()
                logs = log_data.get("logs", [])
                last_id = log_data.get("last_id", -1)
                
                if logs:
                    self._setup_log_tags()
                    for log in logs:
                        self._append_log(log['time'], log['type'], log['msg'])
                        if log['id'] > self.last_log_id:
                            self.last_log_id = log['id']
                        logs_processed += 1
                        if logs_processed >= max_logs_per_cycle:
                            break
                elif last_id > self.last_log_id:
                    self.last_log_id = last_id
        except queue.Empty:
            pass
            
        # Handle Status
        try:
            status_data = self.status_queue.get_nowait()
            self._update_status_ui(status_data)
        except queue.Empty:
            pass
            
        # Schedule next check
        self.root.after(100, self._process_queues)

    def _update_status_ui(self, resp):
        if resp and resp.get("status") == "ok":
            connected = resp.get("connected", False)
            cnt = resp.get("devices_count", 0)
            status_text = f"Connected to Daemon | Broker: {'UP' if connected else 'DOWN'} | Devices: {cnt}"
            self.lbl_status.config(text=status_text, foreground="green")
            
            # Update subscriptions display
            subscriptions = resp.get("subscriptions", [])
            if subscriptions:
                subs_text = "\n".join(f"  • {sub}" for sub in subscriptions)
                self.lbl_subscriptions.config(text=subs_text)
            else:
                self.lbl_subscriptions.config(text="  (No active subscriptions)", foreground="gray")
            
            # Update broker status labels
            broker_status = "🟢 Connected" if connected else "🔴 Disconnected"
            self.lbl_broker_conn.config(text=f"Connection: {broker_status}", 
                                       foreground="green" if connected else "red")
            
            # Update device list with status
            devices = resp.get("devices", {})
            
            # Get current items
            current_items = {self.tree_devices.item(item, "text"): item for item in self.tree_devices.get_children()}
            
            # Save current selection
            selected = None
            cur_sel = self.tree_devices.selection()
            if cur_sel:
                selected = self.tree_devices.item(cur_sel[0], "text")
            
            # Update or add devices
            for ep_id, info in devices.items():
                status = info.get('status', 'unknown')
                status_text = status.upper()
                
                if ep_id in current_items:
                    # Update existing item
                    item_id = current_items[ep_id]
                    self.tree_devices.item(item_id, values=(status_text,))
                else:
                    # Add new item
                    self.tree_devices.insert("", "end", text=ep_id, values=(status_text,))
            
            # Remove devices that no longer exist
            for ep_id, item_id in current_items.items():
                if ep_id not in devices:
                    self.tree_devices.delete(item_id)
            
            # Restore selection if still exists
            if selected:
                for item in self.tree_devices.get_children():
                    if self.tree_devices.item(item, "text") == selected:
                        self.tree_devices.selection_set(item)
                        break
        else:
            self.lbl_status.config(text="Daemon Disconnected (Is it running?)", foreground="red")
    
    def _force_refresh(self):
        # Only triggers an immediate status poll in the next thread loop
        # For now, just a placeholder as the thread loops automatically
        pass

    def _refresh_status(self):
        # Legacy method kept for compatibility bound to buttons
        pass

    def _refresh_subscriptions(self):
        """Manually refresh subscription status"""
        threading.Thread(target=self._refresh_subscriptions_thread, daemon=True).start()
    
    def _refresh_subscriptions_thread(self):
        """Thread to refresh subscription status via IPC"""
        try:
            resp = self.ipc.send_command("status")
            if resp and resp.get("status") == "ok":
                subscriptions = resp.get("subscriptions", [])
                if subscriptions:
                    subs_text = "\n".join(f"  • {sub}" for sub in subscriptions)
                    self.lbl_subscriptions.config(text=subs_text, foreground="blue")
                else:
                    self.lbl_subscriptions.config(text="  (No active subscriptions)", foreground="gray")
                self._append_log(datetime.now().strftime('%H:%M:%S'), 'info', 
                                f"Subscriptions refreshed: {len(subscriptions)} active")
            else:
                self.lbl_subscriptions.config(text="  (Failed to retrieve)", foreground="red")
        except Exception as e:
            self.lbl_subscriptions.config(text=f"  Error: {e}", foreground="red")
    
    def _delete_device(self):
        """Delete selected device from list"""
        selection = self.tree_devices.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to delete")
            return
        
        item_id = selection[0]
        endpoint = self.tree_devices.item(item_id, "text")
        
        if messagebox.askyesno("Confirm Delete", f"Delete device '{endpoint}' from list?\n\nThis will remove it from devices.json."):
            threading.Thread(target=self._delete_device_thread, args=(endpoint,)).start()
    
    def _delete_device_thread(self, endpoint):
        """Thread to delete device via IPC"""
        try:
            resp = self.ipc.send_command(f"remove_device {endpoint}")
            if resp and resp.get("status") == "ok":
                self.log_queue.put({"logs": [{"id": -1, "time": datetime.now().strftime("%H:%M:%S"), "type": "success", "msg": f"Device '{endpoint}' deleted"}], "last_id": -1})
                # Trigger immediate refresh
                time.sleep(0.5)
                self.ipc.send_command("devices")
            else:
                msg = resp.get("msg", "Unknown error") if resp else "No response"
                self.log_queue.put({"logs": [{"id": -1, "time": datetime.now().strftime("%H:%M:%S"), "type": "error", "msg": f"Delete failed: {msg}"}], "last_id": -1})
        except Exception as e:
            self.log_queue.put({"logs": [{"id": -1, "time": datetime.now().strftime("%H:%M:%S"), "type": "error", "msg": f"Delete error: {e}"}], "last_id": -1})

    def _send_command(self):
        ep = self.cb_endpoint.get().strip()
        path = self.ent_path.get().strip()
        action = self.cb_action.get().lower()
        val = self.ent_value.get().strip()
        
        if not ep:
            messagebox.showwarning("Input Error", "Target Endpoint is required")
            return
        
        cmd_str = ""
        if action == "get":
            cmd_str = f"get {ep} {path}"
            history_action = "GET"
        elif action == "set":
            cmd_str = f"set {ep} {path} {val}"
            history_action = "SET"
        elif action == "add":
            cmd_str = f"add {ep} {path}"
            history_action = "ADD"
        elif action == "delete":
            cmd_str = f"delete {ep} {path}"
            history_action = "DELETE"
        elif action == "operate":
            cmd_str = f"operate {ep} {path} {val}"
            history_action = "OPERATE"
        elif action == "getsupporteddm":
            cmd_str = f"get_supported {ep} {path}"
            history_action = "GetSupportedDM"
        elif action == "getinstances":
            cmd_str = f"get_instances {ep} {path}"
            history_action = "GetInstances"
        
        # Add to history
        self._add_to_history(history_action, ep, path, val)
            
        # Send in a separate thread to avoid freezing UI
        threading.Thread(target=self._send_command_thread, args=(cmd_str,)).start()
        
    def _send_command_thread(self, cmd_str):
        resp = self.ipc.send_command(cmd_str)
        
        # Update history status
        success = resp and resp.get("status") == "ok"
        if self.command_history:
            self.command_history[-1]['status'] = 'success' if success else 'error'
            self._save_history()
            # Schedule UI refresh in main thread
            self.root.after(0, self._refresh_history_list)
        
        # Schedule UI update in main thread
        self.root.after(0, lambda: self._handle_command_response(resp, cmd_str))
        
    def _handle_command_response(self, resp, cmd_str):
        if resp:
            if resp.get("status") == "ok":
                # Log successful command locally as well
                pass 
            else:
                 messagebox.showerror("Error", resp.get("msg", "Unknown error"))
        else:
            messagebox.showerror("Connection Error", "Could not talk to daemon")

    def _refresh_config(self):
        threading.Thread(target=self._refresh_config_thread).start()

    def _refresh_config_thread(self):
        resp = self.ipc.send_command("get_config")
        if resp and resp.get("status") == "ok":
            cfg = resp.get("config", {})
            
            # Update entry widgets in main thread
            self.root.after(0, lambda: self.ent_broker_host.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_broker_host.insert(0, cfg.get('broker_host', '')))
            
            self.root.after(0, lambda: self.ent_broker_port.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_broker_port.insert(0, str(cfg.get('broker_port', ''))))
            
            self.root.after(0, lambda: self.ent_username.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_username.insert(0, cfg.get('username', '')))
            
            self.root.after(0, lambda: self.ent_ctrl_id.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_ctrl_id.insert(0, cfg.get('controller_id', '')))
            
            self.root.after(0, lambda: self.ent_topic.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_topic.insert(0, cfg.get('receive_topic', '')))
            
            self.root.after(0, lambda: self.ent_ipc_port.delete(0, tk.END))
            self.root.after(0, lambda: self.ent_ipc_port.insert(0, str(cfg.get('ipc_port', ''))))
            
            # Update Debug Level Radio
            lvl = cfg.get("debug_level", 1)
            self.root.after(0, lambda: self.var_debug.set(lvl))
            
            # Update broker status display
            broker_addr = f"{cfg.get('broker_host', 'N/A')}:{cfg.get('broker_port', 'N/A')}"
            self.root.after(0, lambda: self.lbl_broker_addr.config(text=f"Address: {broker_addr}"))
            self.root.after(0, lambda: self.lbl_broker_user.config(text=f"Username: {cfg.get('username', 'N/A')}"))
    
    def _save_config(self):
        if not messagebox.askyesno("Confirm", "Save configuration changes?\n\nNote: Daemon must be restarted for changes to take effect."):
            return
        
        threading.Thread(target=self._save_config_thread).start()
    
    def _save_config_thread(self):
        fields = {
            'broker_host': self.ent_broker_host.get(),
            'broker_port': self.ent_broker_port.get(),
            'username': self.ent_username.get(),
            'password': self.ent_password.get(),
            'controller_id': self.ent_ctrl_id.get(),
            'receive_topic': self.ent_topic.get(),
            'ipc_port': self.ent_ipc_port.get()
        }
        
        errors = []
        for field, value in fields.items():
            if not value and field != 'password':  # password can be empty
                continue
            
            resp = self.ipc.send_command(f"update_config {field} {value}")
            if resp and resp.get("status") != "ok":
                errors.append(f"{field}: {resp.get('msg', 'Unknown error')}")
        
        if errors:
            msg = "Some updates failed:\n" + "\n".join(errors)
            self.root.after(0, lambda: messagebox.showerror("Save Failed", msg))
        else:
            self.root.after(0, lambda: messagebox.showinfo("Success", "Configuration saved successfully!\n\nRestart the daemon to apply changes."))

        
    def _set_debug_level(self):
        lvl = self.var_debug.get()
        threading.Thread(target=self._set_debug_level_thread, args=(lvl,), daemon=True).start()
    
    def _set_debug_level_thread(self, level):
        """Background thread to set debug level"""
        try:
            resp = self.ipc.send_command(f"set_debug {level}")
            if resp and resp.get("status") == "ok":
                def show_success():
                    messagebox.showinfo("Success", f"Debug level set to {level}")
                self.root.after(0, show_success)
            else:
                msg = resp.get("msg", "Unknown error") if resp else "No response from daemon"
                def show_error():
                    messagebox.showerror("Error", f"Failed to set debug level: {msg}")
                self.root.after(0, show_error)
        except Exception as e:
            def show_error():
                messagebox.showerror("Error", f"Failed to set debug level: {str(e)}")
            self.root.after(0, show_error)

    def _reconnect_stomp(self):
        if messagebox.askyesno("Confirm", "Attempt reconnection to Broker?"):
             threading.Thread(target=self._reconnect_stomp_thread).start()

    def _reconnect_stomp_thread(self):
        resp = self.ipc.send_command("reconnect")
        if resp:
            msg = resp.get("msg", "")
            if resp.get("status") == "ok":
                self.root.after(0, lambda: messagebox.showinfo("Success", msg))
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", msg))

    def _mdns_check_status(self):
        """Check mDNS discovery status"""
        threading.Thread(target=self._mdns_check_status_thread).start()
    
    def _mdns_check_status_thread(self):
        resp = self.ipc.send_command("mdns_status")
        if resp and resp.get("status") == "ok":
            available = resp.get("mdns_available", False)
            running = resp.get("mdns_running", False)
            enabled = resp.get("enabled", False)
            
            if not available:
                status_text = "Status: ❌ Not Available (zeroconf not installed)"
                color = "red"
            elif running:
                status_text = "Status: 🟢 Running (Listening for agents)"
                color = "green"
            elif enabled:
                status_text = "Status: ⚪ Enabled but not started"
                color = "orange"
            else:
                status_text = "Status: ⚪ Disabled in config"
                color = "gray"
            
            self.root.after(0, lambda: self.lbl_mdns_status.config(text=status_text, foreground=color))
        else:
            self.root.after(0, lambda: self.lbl_mdns_status.config(text="Status: ❓ Unknown", foreground="gray"))
    
    def _mdns_start(self):
        """Start mDNS discovery"""
        threading.Thread(target=self._mdns_start_thread).start()
    
    def _mdns_start_thread(self):
        resp = self.ipc.send_command("mdns_start")
        if resp:
            msg = resp.get("msg", "")
            if resp.get("status") == "ok":
                self.root.after(0, lambda: messagebox.showinfo("Success", msg))
                self.root.after(500, self._mdns_check_status)
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", msg))
    
    def _mdns_stop(self):
        """Stop mDNS discovery"""
        threading.Thread(target=self._mdns_stop_thread).start()
    
    def _mdns_stop_thread(self):
        resp = self.ipc.send_command("mdns_stop")
        if resp:
            msg = resp.get("msg", "")
            self.root.after(0, lambda: messagebox.showinfo("Info", msg))
            self.root.after(500, self._mdns_check_status)
    
    def _mdns_scan(self):
        """Perform active mDNS scan"""
        # Update status
        self.root.after(0, lambda: self.txt_mdns_results.config(state='normal'))
        self.root.after(0, lambda: self.txt_mdns_results.delete(1.0, tk.END))
        self.root.after(0, lambda: self.txt_mdns_results.insert(tk.END, "Scanning... (3 seconds)\n"))
        self.root.after(0, lambda: self.txt_mdns_results.config(state='disabled'))
        
        threading.Thread(target=self._mdns_scan_thread).start()
    
    def _mdns_scan_thread(self):
        resp = self.ipc.send_command("mdns_scan 3")
        
        if resp and resp.get("status") == "ok":
            count = resp.get("count", 0)
            agents = resp.get("agents", [])
            
            # Build result text
            result_text = f"Found {count} agent(s):\n"
            if agents:
                for agent in agents:
                    ep_id = agent.get('endpoint_id', 'unknown')
                    addr = agent.get('address', 'N/A')
                    result_text += f"  • {ep_id} @ {addr}\n"
            else:
                result_text += "  (No agents found)\n"
            
            # Update UI
            def update_results():
                self.txt_mdns_results.config(state='normal')
                self.txt_mdns_results.delete(1.0, tk.END)
                self.txt_mdns_results.insert(tk.END, result_text)
                self.txt_mdns_results.config(state='disabled')
            
            self.root.after(0, update_results)
            
            if count > 0:
                self.root.after(0, lambda: messagebox.showinfo("Scan Complete", f"Found {count} agent(s). Check device list."))
        else:
            msg = resp.get("msg", "Unknown error") if resp else "No response"
            
            def update_error():
                self.txt_mdns_results.config(state='normal')
                self.txt_mdns_results.delete(1.0, tk.END)
                self.txt_mdns_results.insert(tk.END, f"Scan failed: {msg}\n")
                self.txt_mdns_results.config(state='disabled')
            
            self.root.after(0, update_error)
            self.root.after(0, lambda: messagebox.showerror("Scan Error", msg))
    
    def _mdns_log(self, log_type, message):
        """Add message to mDNS debug log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        def add_log():
            self.txt_mdns_log.configure(state='normal')
            self.txt_mdns_log.insert(tk.END, f"[{timestamp}] ", 'timestamp')
            self.txt_mdns_log.insert(tk.END, f"{message}\n", log_type)
            
            if self.var_mdns_autoscroll.get():
                self.txt_mdns_log.see(tk.END)
            
            self.txt_mdns_log.configure(state='disabled')
        
        self.root.after(0, add_log)
    
    def _add_text_context_menu(self, text_widget):
        """Add right-click context menu with copy functionality to a text widget"""
        context_menu = tk.Menu(text_widget, tearoff=0)
        context_menu.add_command(label="Copy", command=lambda: self._copy_selection(text_widget))
        context_menu.add_command(label="Select All", command=lambda: self._select_all(text_widget))
        context_menu.add_separator()
        context_menu.add_command(label="Clear", command=lambda: self._clear_text_widget(text_widget))
        
        def show_context_menu(event):
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
        
        text_widget.bind("<Button-3>", show_context_menu)
    
    def _copy_selection(self, text_widget):
        """Copy selected text to clipboard"""
        try:
            selected_text = text_widget.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected_text)
        except tk.TclError:
            # No selection, copy all
            text = text_widget.get(1.0, tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
    
    def _select_all(self, text_widget):
        """Select all text in widget"""
        text_widget.tag_add(tk.SEL, "1.0", tk.END)
        text_widget.mark_set(tk.INSERT, "1.0")
        text_widget.see(tk.INSERT)
    
    def _clear_text_widget(self, text_widget):
        """Clear text widget content"""
        text_widget.configure(state='normal')
        text_widget.delete(1.0, tk.END)
        text_widget.configure(state='disabled')
    
    def _mdns_service_selected(self, event):
        """Show detailed info when a service is selected"""
        selection = self.tree_mdns_services.selection()
        if selection:
            item = selection[0]
            endpoint = self.tree_mdns_services.item(item, "text")
            values = self.tree_mdns_services.item(item, "values")
            
            info = f"Service Details:\n"
            info += f"  Endpoint: {endpoint}\n"
            info += f"  Address: {values[0]}\n"
            info += f"  Port: {values[1]}\n"
            info += f"  Path: {values[2]}\n"
            info += f"  Status: {values[3]}"
            
            self._mdns_log("info", f"Selected: {endpoint}")

    def _mdns_scan_debug(self):
        """Trigger mDNS scan from debug tab"""
        self._mdns_log("info", "Initiating mDNS scan...")
        self.btn_mdns_scan_debug.config(state='disabled')
        threading.Thread(target=self._mdns_scan_debug_thread, daemon=True).start()
    
    def _mdns_scan_debug_thread(self):
        """Background thread for mDNS scanning"""
        try:
            timeout = 5.0
            resp = self.ipc.send_command(f"mdns_scan {timeout}")
            
            if resp and resp.get("status") == "ok":
                count = resp.get("count", 0)
                agents = resp.get("agents", [])
                
                self._mdns_log("info", f"Scan complete - found {count} agent(s)")
                
                # Clear and update services table
                def clear_table():
                    self.tree_mdns_services.delete(*self.tree_mdns_services.get_children())
                self.root.after(0, clear_table)
                
                for agent in agents:
                    endpoint = agent.get('endpoint_id', 'N/A')
                    address = agent.get('host', 'N/A')
                    port = agent.get('port', 'N/A')
                    path = agent.get('path', '/usp')
                    
                    self._mdns_log("discovered", f"Found: {endpoint} at {address}:{port}")
                    
                    # Add to table
                    def add_to_table(ep=endpoint, addr=address, p=port, pth=path):
                        self.tree_mdns_services.insert("", "end", text=ep, values=(addr, p, pth, "Discovered"))
                    self.root.after(0, add_to_table)
                
                if count == 0:
                    self._mdns_log("info", "No agents found on the network")
            else:
                msg = resp.get("msg", "Unknown error") if resp else "No response from daemon"
                self._mdns_log("error", f"Scan failed: {msg}")
        except Exception as e:
            self._mdns_log("error", f"Scan error: {str(e)}")
        finally:
            def enable_button():
                self.btn_mdns_scan_debug.config(state='normal')
            self.root.after(0, enable_button)
    
    def _mdns_refresh_debug(self):
        """Refresh mDNS status in debug tab"""
        self.btn_mdns_refresh_debug.config(state='disabled')
        threading.Thread(target=self._mdns_refresh_debug_thread, daemon=True).start()
    
    def _mdns_refresh_debug_thread(self):
        """Background thread for refreshing mDNS status"""
        try:
            resp = self.ipc.send_command("mdns_status")
            if resp and resp.get("status") == "ok":
                available = resp.get("mdns_available", False)
                running = resp.get("mdns_running", False)
                enabled = resp.get("enabled", False)
                
                if not available:
                    status_text = "Status: ❌ Not Available (zeroconf not installed)"
                    color = "red"
                    self._mdns_log("error", "mDNS not available - install zeroconf package")
                elif running:
                    status_text = "Status: 🟢 Listener Active"
                    color = "green"
                    self._mdns_log("info", "mDNS listener is running")
                elif enabled:
                    status_text = "Status: ⚪ Enabled but not started"
                    color = "orange"
                else:
                    status_text = "Status: ⚪ Disabled in configuration"
                    color = "gray"
                
                def update_status():
                    self.lbl_mdns_status_debug.config(text=status_text, foreground=color)
                self.root.after(0, update_status)
            else:
                msg = resp.get("msg", "Unknown error") if resp else "No response from daemon"
                self._mdns_log("error", f"Status check failed: {msg}")
        except Exception as e:
            self._mdns_log("error", f"Refresh error: {str(e)}")
        finally:
            def enable_button():
                self.btn_mdns_refresh_debug.config(state='normal')
            self.root.after(0, enable_button)
    
    def _mdns_clear_logs(self):
        """Clear mDNS debug logs"""
        def clear():
            self.txt_mdns_log.configure(state='normal')
            self.txt_mdns_log.delete(1.0, tk.END)
            self.txt_mdns_log.configure(state='disabled')
        self.root.after(0, clear)
        self._mdns_log("info", "Logs cleared")


    def _load_history(self):
        """Load command history from file"""
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_history(self):
        """Save command history to file"""
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.command_history, f, indent=2)
        except Exception as e:
            print(f"Failed to save history: {e}")
    
    def _add_to_history(self, action, endpoint, path, value):
        """Add command to history"""
        # Check if identical command already exists (ignore timestamp and status)
        for existing in self.command_history:
            if (existing['action'] == action and 
                existing['endpoint'] == endpoint and 
                existing['path'] == path and 
                existing.get('value') == value):
                # Update timestamp and status of existing entry
                existing['timestamp'] = datetime.now().isoformat()
                existing['status'] = 'pending'
                self._save_history()
                self._refresh_history_list()
                return
        
        # Add new entry if not found
        entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'endpoint': endpoint,
            'path': path,
            'value': value,
            'status': 'pending'  # Will be updated after execution
        }
        
        self.command_history.append(entry)
        
        # Limit history size
        if len(self.command_history) > MAX_HISTORY:
            self.command_history = self.command_history[-MAX_HISTORY:]
        
        self._save_history()
        self._refresh_history_list()
    
    def _refresh_history_list(self):
        """Refresh history listbox"""
        self.lst_history.delete(0, tk.END)
        for entry in reversed(self.command_history):  # Show newest first
            display = f"{entry['action']}: {entry['endpoint']} {entry['path']}"
            if entry.get('value'):
                display += f" = {entry['value']}"
            
            # Add status indicator
            status = entry.get('status', 'success')
            if status == 'error':
                display += " (✗)"
            
            idx = self.lst_history.size()
            self.lst_history.insert(tk.END, display)
            
            # Color failed commands in red
            if status == 'error':
                self.lst_history.itemconfig(idx, fg='red')
    
    def _history_double_click(self, event):
        """Double-click to execute"""
        self._history_execute()
    
    def _history_right_click(self, event):
        """Right-click menu"""
        selection = self.lst_history.curselection()
        if not selection:
            return
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Load to Form", command=self._history_load)
        menu.add_command(label="Execute Now", command=self._history_execute)
        menu.add_separator()
        menu.add_command(label="Delete This Entry", command=self._history_delete_selected)
        menu.post(event.x_root, event.y_root)
    
    def _history_load(self):
        """Load selected history to input fields"""
        selection = self.lst_history.curselection()
        if not selection:
            return
        
        idx = len(self.command_history) - 1 - selection[0]  # Reverse index
        entry = self.command_history[idx]
        
        # Set action
        action_map = {"GET": 0, "SET": 1, "ADD": 2, "DELETE": 3, "OPERATE": 4, "GetSupportedDM": 5, "GetInstances": 6}
        action_idx = action_map.get(entry['action'], 0)
        self.cb_action.current(action_idx)
        
        # Set endpoint
        # Set endpoint from history
        endpoint = entry['endpoint']
        if endpoint in self.cb_endpoint['values']:
            self.cb_endpoint.set(endpoint)
        else:
            # If not in list, refresh devices first
            self._refresh_devices()
            if endpoint in self.cb_endpoint['values']:
                self.cb_endpoint.set(endpoint)
        
        # Set path
        self.ent_path.delete(0, tk.END)
        self.ent_path.insert(0, entry['path'])
        
        # Set value
        self.ent_value.delete(0, tk.END)
        if entry.get('value'):
            self.ent_value.insert(0, entry['value'])
        
        # Trigger action change to update UI
        self._on_action_change(None)
    
    def _history_execute(self):
        """Execute selected history command"""
        self._history_load()
        self._send_command()
    
    def _history_delete_selected(self):
        """Delete selected history entry"""
        selection = self.lst_history.curselection()
        if not selection:
            return
        
        idx = len(self.command_history) - 1 - selection[0]
        del self.command_history[idx]
        self._save_history()
        self._refresh_history_list()
    
    def _history_clear(self):
        """Clear all history"""
        if messagebox.askyesno("Confirm", "Clear all command history?"):
            self.command_history = []
            self._save_history()
            self._refresh_history_list()

from datetime import datetime

if __name__ == "__main__":
    root = tk.Tk()
    # Set icon if available (skip for now)
    app = USPControllerGUI(root)
    root.mainloop()
