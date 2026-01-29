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

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

class IPCClient:
    def __init__(self, host=IPC_HOST, port=IPC_PORT):
        self.host = host
        self.port = port
    
    def send_command(self, cmd):
        """Send command string and return JSON response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((self.host, self.port))
                s.sendall(cmd.encode('utf-8'))
                data = s.recv(16384).decode('utf-8')
                if not data: return None
                return json.loads(data)
        except ConnectionRefusedError:
            return None
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
        
        self._setup_ui()
        
        # Start background polling
        self.root.after(1000, self._poll_status_loop)
        self.root.after(500, self._poll_logs_loop)

    def _setup_ui(self):
        # Configure grid weight
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # --- Top Bar: Connection Status ---
        top_frame = ttk.Frame(self.root, padding="5")
        top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        self.lbl_status = ttk.Label(top_frame, text="Checking daemon...", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side="left")
        
        btn_reconnect = ttk.Button(top_frame, text="Reconnect", command=self._refresh_status)
        btn_reconnect.pack(side="right")
        
        # --- Left Panel: Devices ---
        left_panel = ttk.LabelFrame(self.root, text="Devices", padding="5")
        left_panel.grid(row=1, column=0, sticky="ns", padx=5, pady=5)
        
        self.lst_devices = tk.Listbox(left_panel, width=30)
        self.lst_devices.pack(fill="both", expand=True)
        self.lst_devices.bind('<<ListboxSelect>>', self._on_device_select)
        
        btn_refresh_dev = ttk.Button(left_panel, text="Refresh List", command=self._refresh_devices)
        btn_refresh_dev.pack(fill="x", pady=2)

        # --- Right Panel: Controls & Logs ---
        right_panel = ttk.Frame(self.root, padding="5")
        right_panel.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        right_panel.rowconfigure(2, weight=1) # Log area expands
        right_panel.columnconfigure(0, weight=1)

        # 1. Command Controls
        cmd_frame = ttk.LabelFrame(right_panel, text="Command Center", padding="10")
        cmd_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Row 1: Endpoint
        ttk.Label(cmd_frame, text="Target Endpoint:").grid(row=0, column=0, sticky="w")
        self.ent_target = ttk.Entry(cmd_frame, width=40)
        self.ent_target.grid(row=0, column=1, columnspan=2, sticky="ew", pady=2)
        
        # Row 2: Operation
        ttk.Label(cmd_frame, text="Action:").grid(row=1, column=0, sticky="w")
        self.cb_action = ttk.Combobox(cmd_frame, values=["GET", "SET", "ADD", "DELETE", "OPERATE", "DISCOVER"], state="readonly", width=10)
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
        
        # 2. Log Area
        log_frame = ttk.LabelFrame(right_panel, text="Controller Logs & Responses", padding="5")
        log_frame.grid(row=2, column=0, sticky="nsew")
        
        self.txt_log = scrolledtext.ScrolledText(log_frame, state='disabled', font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True)
        
        # Log Controls
        log_ctrl_frame = ttk.Frame(log_frame)
        log_ctrl_frame.pack(fill="x")
        
        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(log_ctrl_frame, text="Auto-scroll", variable=self.var_autoscroll).pack(side="right")
        ttk.Button(log_ctrl_frame, text="Clear Logs", command=self._clear_logs).pack(side="right", padx=5)

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

    def _clear_logs(self):
        self.txt_log.configure(state='normal')
        self.txt_log.delete(1.0, tk.END)
        self.txt_log.configure(state='disabled')

    def _on_action_change(self, event):
        action = self.cb_action.get()
        if action in ["GET", "ADD", "DELETE", "DISCOVER"]:
            self.ent_value.configure(state='disabled')
        else:
            self.ent_value.configure(state='normal')

    def _on_device_select(self, event):
        selection = self.lst_devices.curselection()
        if selection:
            idx = selection[0]
            dev_str = self.lst_devices.get(idx)
            # Typically "endpoint_id (Details...)" or just endpoint_id
            # Assuming list contains just endpoint IDs for now
            self.ent_target.delete(0, tk.END)
            self.ent_target.insert(0, dev_str)

    def _poll_status_loop(self):
        if not self.polling: return
        self._refresh_status()
        self.root.after(5000, self._poll_status_loop)

    def _poll_logs_loop(self):
        if not self.polling: return
        
        # Poll logs
        resp = self.ipc.send_command(f"poll_logs {self.last_log_id}")
        if resp and resp.get("status") == "ok":
            logs = resp.get("logs", [])
            last_id = resp.get("last_id", -1)
            
            # If we received logs
            if logs:
                self._setup_log_tags() # Ensure tags exist
                for log in logs:
                    self._append_log(log['time'], log['type'], log['msg'])
                    if log['id'] > self.last_log_id:
                        self.last_log_id = log['id']
            elif last_id > self.last_log_id:
                # Catch up if we missed something (though logs list covers it usually)
                self.last_log_id = last_id
                
        self.root.after(1000, self._poll_logs_loop)

    def _refresh_status(self):
        resp = self.ipc.send_command("status")
        if resp and resp.get("status") == "ok":
            connected = resp.get("connected", False)
            cnt = resp.get("devices_count", 0)
            status_text = f"Connected to Daemon | Broker: {'UP' if connected else 'DOWN'} | Devices: {cnt}"
            self.lbl_status.config(text=status_text, foreground="green")
            
            # Also refresh device list if it's empty
            if self.lst_devices.size() == 0 and cnt > 0:
                self._refresh_devices()
        else:
            self.lbl_status.config(text="Daemon Disconnected (Is it running?)", foreground="red")

    def _refresh_devices(self):
        resp = self.ipc.send_command("devices")
        if resp and resp.get("status") == "ok":
            devices = resp.get("devices", {})
            self.lst_devices.delete(0, tk.END)
            for ep in devices.keys():
                self.lst_devices.insert(tk.END, ep)

    def _send_command(self):
        ep = self.ent_target.get().strip()
        path = self.ent_path.get().strip()
        action = self.cb_action.get().lower()
        val = self.ent_value.get().strip()
        
        if not ep:
            messagebox.showwarning("Input Error", "Target Endpoint is required")
            return
        
        cmd_str = ""
        if action == "get":
            cmd_str = f"get {ep} {path}"
        elif action == "set":
            cmd_str = f"set {ep} {path} {val}"
        elif action == "add":
            cmd_str = f"add {ep} {path}"
        elif action == "delete":
            cmd_str = f"delete {ep} {path}"
        elif action == "operate":
            cmd_str = f"operate {ep} {path} {val}"
        elif action == "discover":
            cmd_str = f"get_supported {ep} {path}"
            
        # Send
        resp = self.ipc.send_command(cmd_str)
        if resp:
            if resp.get("status") == "ok":
                self._append_log(datetime.now().strftime("%H:%M:%S"), "info", f"Command SENT: {cmd_str}")
            else:
                 messagebox.showerror("Error", resp.get("msg", "Unknown error"))
        else:
            messagebox.showerror("Connection Error", "Could not talk to daemon")

from datetime import datetime

if __name__ == "__main__":
    root = tk.Tk()
    # Set icon if available (skip for now)
    app = USPControllerGUI(root)
    root.mainloop()
