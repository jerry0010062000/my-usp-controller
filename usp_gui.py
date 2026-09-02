#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TR-369 USP Controller - Professional GUI Control Deck & Server/Port Monitor
Engineered with WindowsACS-inspired split-panel layout, parameter explorer,
quick action cards, CDRouter script runner, and live STOMP/USP protocol monitor.
"""

import sys
import os
import json
import time
import socket
import threading
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from usp_controller.ipc import IPCClient, check_port_listening


def show_selectable_dialog(parent, title: str, message: str, dialog_type: str = "info"):
    """
    Open a modern modal dialog where the text is fully selectable, highlightable,
    and copyable with keyboard shortcuts and a dedicated 'Copy' button.
    dialog_type: 'error', 'warning', 'info', or 'success'
    """
    top = tk.Toplevel(parent)
    top.title(title)
    top.geometry("580x360")
    top.minsize(440, 250)
    top.configure(bg="#f8fafc")
    top.transient(parent)

    # Position relative to parent
    try:
        x = parent.winfo_rootx() + (parent.winfo_width() // 2) - 290
        y = parent.winfo_rooty() + (parent.winfo_height() // 2) - 180
        top.geometry(f"+{max(50, x)}+{max(50, y)}")
    except Exception:
        pass

    # Colors & Icons based on type
    if dialog_type == "error":
        header_bg = "#fef2f2"
        badge_fg = "#dc2626"
        icon_str = "❌ 錯誤訊息"
    elif dialog_type == "warning":
        header_bg = "#fffbeb"
        badge_fg = "#d97706"
        icon_str = "⚠️ 警告提示"
    elif dialog_type == "success":
        header_bg = "#f0fdf4"
        badge_fg = "#059669"
        icon_str = "✅ 執行成功"
    else:
        header_bg = "#f0f9ff"
        badge_fg = "#0284c7"
        icon_str = "ℹ️ 系統提示"

    # Header Bar
    hdr = tk.Frame(top, bg=header_bg, padx=14, pady=10)
    hdr.pack(fill=tk.X)
    tk.Label(hdr, text=icon_str, font=("Segoe UI", 11, "bold"), fg=badge_fg, bg=header_bg).pack(side=tk.LEFT)
    tk.Label(hdr, text=title, font=("Segoe UI", 10), fg="#475569", bg=header_bg).pack(side=tk.LEFT, padx=(10, 0))

    # Body with ScrolledText (Selectable / Copyable)
    body_frame = ttk.Frame(top, padding=12)
    body_frame.pack(fill=tk.BOTH, expand=True)

    txt = scrolledtext.ScrolledText(
        body_frame,
        wrap=tk.WORD,
        font=("Consolas", 10),
        bg="#ffffff",
        fg="#0f172a",
        padx=10,
        pady=8,
        relief="solid",
        bd=1,
        selectbackground="#0284c7",
        selectforeground="#ffffff"
    )
    txt.pack(fill=tk.BOTH, expand=True)
    txt.insert("1.0", str(message))

    # Ctrl+A select all
    def select_all(event=None):
        txt.tag_add(tk.SEL, "1.0", tk.END)
        txt.mark_set(tk.INSERT, "1.0")
        txt.see(tk.INSERT)
        return "break"

    txt.bind("<Control-a>", select_all)
    txt.bind("<Control-A>", select_all)

    # Bottom Actions Bar
    btn_bar = ttk.Frame(top, padding=(12, 10))
    btn_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def copy_to_clipboard():
        try:
            if txt.tag_ranges(tk.SEL):
                selected_text = txt.get(tk.SEL_FIRST, tk.SEL_LAST)
            else:
                selected_text = txt.get("1.0", tk.END).strip()
            top.clipboard_clear()
            top.clipboard_append(selected_text)
            btn_copy.config(text="✓ 已複製至剪貼簿！")
            top.after(1500, lambda: btn_copy.config(text="📋 複製內容 (Copy)"))
        except Exception:
            pass

    btn_copy = ttk.Button(btn_bar, text="📋 複製內容 (Copy)", command=copy_to_clipboard)
    btn_copy.pack(side=tk.LEFT)

    btn_ok = ttk.Button(btn_bar, text="確定 (OK)", style="Primary.TButton", command=top.destroy)
    btn_ok.pack(side=tk.RIGHT)

    top.bind("<Escape>", lambda e: top.destroy())

    top.grab_set()
    txt.focus_set()
    top.wait_window()


class USPGuiApp:
    """
    TR-369 USP Controller GUI Application
    Modeled after the WindowsACS layout:
    - Top Dark Header Bar with live Daemon/Broker status and connection controls
    - Sub-header with Port status, Broker IP/Port, and quick network utilities
    - Main Paned Split Window:
        - Left Panel: Agent Devices Explorer with search/filter and status indicators
        - Right Panel: Selected Device Summary + Tabbed Workspace:
            1. Parameter Explorer (Get/Set/Add/Delete/DM/Instances Treeview)
            2. Quick Actions & Direct Command Deck
            3. CDRouter Test Script Runner
            4. Server & Port Monitor Dashboard
            5. Live Protocol & Packet Logs
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("TR-369 USP Controller 管理主控台")
        self.root.geometry("1240x820")
        self.root.minsize(1020, 680)

        # IPC Client & State
        self.ipc_url_var = tk.StringVar(value="127.0.0.1:6001")
        self.ipc_client = IPCClient(host="127.0.0.1", port=6001, timeout=5.0)

        self.internal_broker = None
        self.selected_device_id: Optional[str] = None
        self.active_device_id: Optional[str] = None
        self.cached_devices = []
        self.cached_params: Dict[str, Dict[str, Any]] = {}
        self.last_log_id = -1
        self.auto_refresh_logs = tk.BooleanVar(value=True)
        self.polling_running = True
        self.command_history = []
        self.history_index = -1

        # Configuration Management Variables
        self.cfg_broker_host_var = tk.StringVar(value="127.0.0.1")
        self.cfg_broker_port_var = tk.StringVar(value="61614")
        self.cfg_broker_user_var = tk.StringVar(value="guest")
        self.cfg_broker_pass_var = tk.StringVar(value="guest")
        self.cfg_controller_id_var = tk.StringVar(value="proto::controller.default")
        self.cfg_rx_topic_var = tk.StringVar(value="/queue/usp.controller.default")
        self.cfg_ipc_port_var = tk.StringVar(value="6001")
        self.cfg_debug_level_var = tk.StringVar(value="1 - 雙向 Payload (標準)")
        self.cfg_auto_register_var = tk.BooleanVar(value=True)
        self.cfg_mdns_var = tk.BooleanVar(value=True)
        self._load_config_to_vars()

        # Request Lock & Action Buttons State (Race Condition & Freeze Prevention)
        self._cmd_lock = threading.Lock()
        self._is_busy = False
        self._action_buttons: List[ttk.Button] = []

        self._setup_styles()
        self._build_ui()

        # Clean shutdown handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_close_window)

        # Start periodic polling
        self.poll_thread = threading.Thread(target=self._periodic_daemon_polling, daemon=True)
        self.poll_thread.start()

    def _register_action_button(self, btn: ttk.Button) -> ttk.Button:
        """Register an action button so its state is auto-disabled during in-flight requests."""
        if btn not in self._action_buttons:
            self._action_buttons.append(btn)
        return btn

    def _acquire_request_lock(self, action_name: str = "操作") -> bool:
        """Try to acquire request lock (non-blocking). Returns True if acquired, False if already busy."""
        if not self._cmd_lock.acquire(blocking=False):
            self.status_bar.config(text="⚠️ 前一項操作仍在執行中，請稍候再試...")
            return False
        self._is_busy = True
        self._set_ui_busy_state(True, action_name)
        return True

    def _release_request_lock(self):
        """Release request lock and restore UI state."""
        self._is_busy = False
        self._set_ui_busy_state(False)
        try:
            self._cmd_lock.release()
        except RuntimeError:
            pass

    def _set_ui_busy_state(self, is_busy: bool, action_name: str = ""):
        """Update cursor and button states during in-flight requests safely on main thread."""
        def apply():
            cursor = "wait" if is_busy else ""
            try:
                self.root.configure(cursor=cursor)
            except Exception:
                pass
            btn_state = "disabled" if is_busy else "normal"
            for btn in self._action_buttons:
                try:
                    btn.configure(state=btn_state)
                except Exception:
                    pass
            if is_busy and action_name:
                self.status_bar.config(text=f"⏳ 正在執行: {action_name} ... (請稍候)")

        if threading.current_thread() is threading.main_thread():
            apply()
        else:
            self.root.after(0, apply)

    def show_error(self, title: str, message: str):
        show_selectable_dialog(self.root, title, message, dialog_type="error")

    def show_warning(self, title: str, message: str):
        show_selectable_dialog(self.root, title, message, dialog_type="warning")

    def show_info(self, title: str, message: str):
        show_selectable_dialog(self.root, title, message, dialog_type="info")

    def show_success(self, title: str, message: str):
        show_selectable_dialog(self.root, title, message, dialog_type="success")

    def _setup_styles(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # WindowsACS Signature Palette
        bg_dark = "#0f172a"      # Navy / Dark Slate Header
        accent_cyan = "#38bdf8"  # Title Cyan
        accent_blue = "#0284c7"  # Primary Action Blue
        text_muted = "#94a3b8"   # Subtitle Muted

        self.root.configure(bg="#f1f5f9")
        self.style.configure(".", font=("Segoe UI", 9))

        # Header Styles
        self.style.configure("Header.TFrame", background=bg_dark)
        self.style.configure("HeaderTitle.TLabel", background=bg_dark, foreground=accent_cyan, font=("Segoe UI", 13, "bold"))
        self.style.configure("HeaderStatus.TLabel", background=bg_dark, foreground=text_muted, font=("Segoe UI", 9))
        self.style.configure("HeaderBadge.TLabel", background="#1e293b", foreground="#38bdf8", font=("Consolas", 9, "bold"), padding=[6, 2])

        # Treeview Styles
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#e2e8f0", foreground="#0f172a")
        self.style.configure("Treeview", rowheight=26, background="#ffffff", fieldbackground="#ffffff", foreground="#0f172a")
        self.style.map("Treeview", 
            background=[("selected", "#0284c7"), ("!focus", "#e0f2fe")], 
            foreground=[("selected", "#ffffff"), ("!focus", "#0f172a")]
        )

        # Button Styles
        self.style.configure("Action.TButton", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        self.style.configure("Primary.TButton", background=accent_blue, foreground="white", font=("Segoe UI", 9, "bold"), padding=[12, 6])
        self.style.map("Primary.TButton", background=[("active", "#0369a1"), ("pressed", "#075985")])

        self.style.configure("Launch.TButton", background="#059669", foreground="white", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        self.style.map("Launch.TButton", background=[("active", "#047857"), ("pressed", "#065f46")])

        self.style.configure("Danger.TButton", background="#dc2626", foreground="white", font=("Segoe UI", 9, "bold"), padding=[10, 5])
        self.style.map("Danger.TButton", background=[("active", "#b91c1c"), ("pressed", "#991b1b")])


    def _build_ui(self):
        # 1. Top Header Bar (WindowsACS Header style)
        self._build_top_header()

        # 1.5 Sub-header: Network, Broker & Port Monitor Bar
        self._build_network_sub_bar()

        # 2. Main Paned Window Layout (Left: Device Explorer, Right: Notebook Workspace)
        self.main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6, 10))

        # Left Panel: Device Explorer
        self._build_device_panel()

        # Right Panel: Main Workspace Notebook
        self._build_notebook_panel()

        # Bottom Status Bar
        self.status_bar = tk.Label(
            self.root,
            text="系統就緒。正在連接 USP Controller 後台守護進程 (127.0.0.1:6001)...",
            bg="#e2e8f0",
            fg="#475569",
            anchor="w",
            font=("Segoe UI", 9),
            padx=12,
            pady=4
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # ==========================================
    # 1. Top Header & Network Sub-Bar
    # ==========================================

    def _build_top_header(self):
        top_bar = ttk.Frame(self.root, style="Header.TFrame", padding=(16, 10))
        top_bar.pack(side=tk.TOP, fill=tk.X)

        # Title & Status
        title_frame = ttk.Frame(top_bar, style="Header.TFrame")
        title_frame.pack(side=tk.LEFT, fill=tk.Y)

        title_lbl = ttk.Label(title_frame, text="TR-369 USP Controller 控制主控台", style="HeaderTitle.TLabel")
        title_lbl.pack(anchor=tk.W)

        self.lbl_header_status = ttk.Label(
            title_frame,
            text="Daemon: 檢查中... | STOMP Broker: 127.0.0.1:61614 | IPC: 127.0.0.1:6001",
            style="HeaderStatus.TLabel"
        )
        self.lbl_header_status.pack(anchor=tk.W, pady=(2, 0))

        # Top Right Controls
        ctrl_frame = ttk.Frame(top_bar, style="Header.TFrame")
        ctrl_frame.pack(side=tk.RIGHT, fill=tk.Y)

        ttk.Label(ctrl_frame, text="IPC 位址:", style="HeaderStatus.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        ipc_entry = ttk.Entry(ctrl_frame, textvariable=self.ipc_url_var, width=16)
        ipc_entry.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_refresh_connect = ttk.Button(ctrl_frame, text="連線 / 刷新", command=self.on_refresh_connect_clicked)
        self.btn_refresh_connect.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_broker_toggle = ttk.Button(
            ctrl_frame,
            text="啟動 Broker 黑窗",
            style="Launch.TButton",
            command=self.launch_broker_black_window
        )
        self.btn_broker_toggle.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_daemon_toggle = ttk.Button(
            ctrl_frame,
            text="啟動 Controller 黑窗",
            style="Launch.TButton",
            command=self.launch_daemon_black_window
        )
        self.btn_daemon_toggle.pack(side=tk.LEFT)


    def _build_network_sub_bar(self):
        sub_bar = ttk.Frame(self.root, padding=(16, 6))
        sub_bar.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(sub_bar, text="STOMP Broker:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.lbl_sub_broker_port = ttk.Label(sub_bar, text="61614 (CLOSED)", foreground="#dc2626", font=("Segoe UI", 9, "bold"))
        self.lbl_sub_broker_port.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(sub_bar, text="Controller Daemon:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.lbl_sub_ipc = ttk.Label(sub_bar, text="6001 (OFFLINE)", foreground="#dc2626", font=("Segoe UI", 9, "bold"))
        self.lbl_sub_ipc.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(sub_bar, text="Controller <-> Broker:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.lbl_sub_broker_conn = ttk.Label(sub_bar, text="OFFLINE", foreground="#94a3b8", font=("Segoe UI", 9, "bold"))
        self.lbl_sub_broker_conn.pack(side=tk.LEFT, padx=(0, 14))

        ttk.Label(sub_bar, text="當前目標:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.lbl_sub_target = ttk.Label(sub_bar, text="(未選擇)", foreground="#d97706", font=("Segoe UI", 9, "bold"))
        self.lbl_sub_target.pack(side=tk.LEFT, padx=(0, 14))


        # Quick utility buttons on the right
        btn_box = ttk.Frame(sub_bar)
        btn_box.pack(side=tk.RIGHT)

        ttk.Button(btn_box, text="💡 DUT 設定指南", command=self.on_show_dut_guide_clicked).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_box, text="🔍 掃描 mDNS Agent", command=lambda: self.send_ipc_cmd_async("scan")).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_box, text="⚡ Ping 伺服器", command=self.on_ping_clicked).pack(side=tk.LEFT, padx=3)



    # ==========================================
    # 2. Left Panel: Device Explorer
    # ==========================================

    def _build_device_panel(self):
        left_frame = ttk.LabelFrame(self.main_paned, text=" USP Agent 設備清單 ", padding=8)
        self.main_paned.add(left_frame, weight=1)

        # Search / Filter
        filter_frame = ttk.Frame(left_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(filter_frame, text="搜尋:").pack(side=tk.LEFT, padx=(0, 4))
        self.dev_filter_var = tk.StringVar()
        self.dev_filter_var.trace_add("write", lambda *args: self._filter_devices())
        dev_search_entry = ttk.Entry(filter_frame, textvariable=self.dev_filter_var)
        dev_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Auto-refresh notice / count
        info_row = ttk.Frame(left_frame)
        info_row.pack(fill=tk.X, pady=(0, 6))
        self.lbl_dev_count = ttk.Label(info_row, text="已發現 0 個設備 (自動刷新中)", foreground="#64748b", font=("Segoe UI", 8))
        self.lbl_dev_count.pack(side=tk.LEFT)

        # Bottom Buttons (Packed first at bottom to reserve space)
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0))
        btn_target = ttk.Button(btn_frame, text="設為操作目標", style="Primary.TButton", command=self.on_set_active_target)
        btn_target.pack(side=tk.TOP, fill=tk.X, expand=True, pady=(0, 4))
        self._register_action_button(btn_target)

        btn_probe = ttk.Button(btn_frame, text="探測 / 連線", command=self.on_probe_agent_clicked)
        btn_probe.pack(side=tk.TOP, fill=tk.X, expand=True, pady=(0, 4))
        self._register_action_button(btn_probe)

        del_frame = ttk.Frame(btn_frame)
        del_frame.pack(side=tk.TOP, fill=tk.X, expand=True)
        btn_clear = ttk.Button(del_frame, text="清除離線", command=self.on_clear_offline_clicked)
        btn_clear.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        self._register_action_button(btn_clear)

        btn_rm = ttk.Button(del_frame, text="移除選中", command=self.on_remove_selected_device_clicked)
        btn_rm.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
        self._register_action_button(btn_rm)

        # Device Treeview Container (Packed between top filter and bottom buttons)
        tree_container = ttk.Frame(left_frame)
        tree_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        cols = ("status", "endpoint", "ip", "proto")
        self.dev_tree = ttk.Treeview(tree_container, columns=cols, show="headings", selectmode="browse")
        self.dev_tree.heading("status", text="狀態")
        self.dev_tree.heading("endpoint", text="Agent Endpoint ID")
        self.dev_tree.heading("ip", text="IP / 通道")
        self.dev_tree.heading("proto", text="協議")

        self.dev_tree.column("status", width=70, anchor=tk.CENTER)
        self.dev_tree.column("endpoint", width=180, anchor=tk.W)
        self.dev_tree.column("ip", width=95, anchor=tk.W)
        self.dev_tree.column("proto", width=65, anchor=tk.CENTER)

        dev_scroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=dev_scroll.set)

        self.dev_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dev_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.dev_tree.tag_configure("online", foreground="#059669")
        self.dev_tree.tag_configure("offline", foreground="#64748b")

        self.dev_tree.bind("<<TreeviewSelect>>", self.on_device_selected)





    # ==========================================
    # 3. Right Panel: Workspace Notebook Tabs
    # ==========================================

    def _build_notebook_panel(self):
        right_frame = ttk.Frame(self.main_paned)
        self.main_paned.add(right_frame, weight=3)

        # Selected Device Summary Header (WindowsACS style)
        self.dev_summary_frame = ttk.Frame(right_frame, padding=(6, 4))
        self.dev_summary_frame.pack(fill=tk.X)

        self.lbl_selected_title = ttk.Label(
            self.dev_summary_frame,
            text="請由左側選擇 USP Agent 設備",
            font=("Segoe UI", 11, "bold"),
            foreground="#0369a1"
        )
        self.lbl_selected_title.pack(anchor=tk.W)

        self.lbl_selected_detail = ttk.Label(
            self.dev_summary_frame,
            text="狀態: - | 通訊協議: STOMP | 回應佇列: /queue/usp-agent-response",
            foreground="#64748b"
        )
        self.lbl_selected_detail.pack(anchor=tk.W)

        # Main Notebook
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        # Tab 1: Parameter Data Model Explorer
        self.tab_params = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_params, text=" 參數檢視與修改 (Parameters) ")
        self._build_param_tab()

        # Tab 2: Quick Actions & Command Deck
        self.tab_actions = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_actions, text=" 快捷控制與指令台 (Actions & CMD) ")
        self._build_actions_tab()

        # Tab 3: CDRouter Test Scripts (暫時隱藏)
        # self.tab_scripts = ttk.Frame(self.notebook, padding=8)
        # self.notebook.add(self.tab_scripts, text=" CDRouter 測試腳本 (Test Scripts) ")
        # self._build_scripts_tab()

        # Tab 4: Server & Port Monitor Dashboard
        self.tab_monitor = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_monitor, text=" 伺服器與通訊埠監控 (Port Monitor) ")
        self._build_monitor_tab()

        # Tab 5: Live Protocol & STOMP Logs
        self.tab_logs = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_logs, text=" 即時日誌與封包檢視 (Live Logs) ")
        self._build_logs_tab()

        # Tab 6: System & Network Configuration
        self.tab_config = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab_config, text=" 系統與連線設定 (Settings) ")
        self._build_config_tab()


    # ------------------------------------------
    # Tab 1: Parameter Data Model Explorer
    # ------------------------------------------

    def _build_param_tab(self):
        # Row 1: Parameter Path Entry (Full Width Standalone Row)
        p_path_row = ttk.Frame(self.tab_params)
        p_path_row.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(p_path_row, text="參數路徑:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.param_path_var = tk.StringVar(value="Device.DeviceInfo.")
        p_entry = ttk.Entry(p_path_row, textvariable=self.param_path_var)
        p_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Row 2: Action Buttons Row (Standalone Row)
        p_btn_row = ttk.Frame(self.tab_params)
        p_btn_row.pack(fill=tk.X, pady=(0, 6))

        b_get = ttk.Button(p_btn_row, text="查詢 (Get)", style="Primary.TButton", command=self.on_param_get_clicked)
        b_get.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_get)

        b_set = ttk.Button(p_btn_row, text="修改 (Set)", command=self.on_param_set_clicked)
        b_set.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_set)

        b_add = ttk.Button(p_btn_row, text="新增實例 (Add)", command=self.on_param_add_clicked)
        b_add.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_add)

        b_del = ttk.Button(p_btn_row, text="刪除實例 (Del)", command=self.on_param_delete_clicked)
        b_del.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_del)

        b_dm = ttk.Button(p_btn_row, text="查詢架構 (GetDM)", command=self.on_param_get_dm_clicked)
        b_dm.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_dm)

        b_inst = ttk.Button(p_btn_row, text="實例清單 (GetInst)", command=self.on_param_get_inst_clicked)
        b_inst.pack(side=tk.LEFT, padx=(0, 4))
        self._register_action_button(b_inst)

        b_clr = ttk.Button(p_btn_row, text="清空清單", command=self.on_clear_param_tree_clicked)
        b_clr.pack(side=tk.RIGHT)
        self._register_action_button(b_clr)

        # Row 3: Parameter Filter & Search Bar (Real-time Filter)
        p_filter_row = ttk.Frame(self.tab_params)
        p_filter_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(p_filter_row, text="過濾條件:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.param_filter_var = tk.StringVar()
        self.param_filter_var.trace_add("write", lambda *args: self._filter_params())
        p_filter_entry = ttk.Entry(p_filter_row, textvariable=self.param_filter_var)
        p_filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))

        self.lbl_param_count = ttk.Label(p_filter_row, text="顯示: 0 / 0 筆", foreground="#64748b", font=("Segoe UI", 9))
        self.lbl_param_count.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(p_filter_row, text="清除過濾 (X)", command=self._clear_param_filter).pack(side=tk.RIGHT)

        # Param Treeview Table
        p_cols = ("path", "value", "type", "access", "updated")
        self.param_tree = ttk.Treeview(self.tab_params, columns=p_cols, show="headings")
        self.param_tree.heading("path", text="參數路徑 (Parameter Path)")
        self.param_tree.heading("value", text="參數值 (Value)")
        self.param_tree.heading("type", text="型別 (Type)")
        self.param_tree.heading("access", text="權限 (Access)")
        self.param_tree.heading("updated", text="最後更新時間")

        self.param_tree.column("path", width=360, anchor=tk.W)
        self.param_tree.column("value", width=200, anchor=tk.W)
        self.param_tree.column("type", width=90, anchor=tk.CENTER)
        self.param_tree.column("access", width=95, anchor=tk.CENTER)
        self.param_tree.column("updated", width=110, anchor=tk.CENTER)

        p_scroll_y = ttk.Scrollbar(self.tab_params, orient=tk.VERTICAL, command=self.param_tree.yview)
        self.param_tree.configure(yscrollcommand=p_scroll_y.set)

        self.param_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        self.param_tree.bind("<<TreeviewSelect>>", self._on_param_row_clicked)
        self.param_tree.bind("<Double-1>", self._on_param_double_clicked)




    # ------------------------------------------
    # Tab 2: Quick Actions & Command Deck
    # ------------------------------------------
    def _build_actions_tab(self):
        grid_frame = ttk.Frame(self.tab_actions)
        grid_frame.pack(fill=tk.BOTH, expand=True)

        # Card 1: Device Information Query
        c1 = ttk.LabelFrame(grid_frame, text=" ℹ️ 系統與設備資訊 (DeviceInfo) ", padding=12)
        c1.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        ttk.Label(c1, text="查詢 Agent 軟體版本、序號、製造商、運行時間等基礎系統資訊。", wraplength=260).pack(anchor=tk.W, pady=(0, 10))
        btn_c1 = ttk.Button(c1, text="查詢 DeviceInfo", style="Primary.TButton", command=lambda: self.send_ipc_cmd_async("get Device.DeviceInfo."))
        btn_c1.pack(anchor=tk.W)
        self._register_action_button(btn_c1)

        # Card 2: WiFi & Network Radios
        c2 = ttk.LabelFrame(grid_frame, text=" 📶 WiFi 無線網路管理 (WiFi.Radio) ", padding=12)
        c2.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        ttk.Label(c2, text="檢視 2.4G / 5G / 6G Radio 頻段狀態、SSID 與頻道設定。", wraplength=260).pack(anchor=tk.W, pady=(0, 10))
        btn_c2 = ttk.Button(c2, text="查詢 WiFi Radios", style="Action.TButton", command=lambda: self.send_ipc_cmd_async("get Device.WiFi.Radio."))
        btn_c2.pack(anchor=tk.W)
        self._register_action_button(btn_c2)

        # Card 3: DHCP Server & Pools
        c3 = ttk.LabelFrame(grid_frame, text=" 🌐 DHCP 伺服器與位址池 (DHCPv4) ", padding=12)
        c3.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        ttk.Label(c3, text="管理 DHCPv4 Server Pool 配置，新增/刪除位址發放範圍。", wraplength=260).pack(anchor=tk.W, pady=(0, 10))
        btn_c3 = ttk.Button(c3, text="查詢 DHCP Pools", style="Action.TButton", command=lambda: self.send_ipc_cmd_async("get Device.DHCPv4.Server.Pool."))
        btn_c3.pack(anchor=tk.W)
        self._register_action_button(btn_c3)

        # Card 4: IP Diagnostics / Ping RPC
        c4 = ttk.LabelFrame(grid_frame, text=" ⚡ 遠端診斷與 RPC 操作 (Operate) ", padding=12)
        c4.grid(row=1, column=1, sticky="nsew", padx=8, pady=8)
        ttk.Label(c4, text="發送遠端 RPC 指令或觸發 IPPing 診斷流程。", wraplength=260).pack(anchor=tk.W, pady=(0, 10))
        btn_c4 = ttk.Button(c4, text="查詢 IP.Interface", style="Action.TButton", command=lambda: self.send_ipc_cmd_async("get Device.IP.Interface."))
        btn_c4.pack(anchor=tk.W)
        self._register_action_button(btn_c4)

        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

        # Bottom Direct CMD Input Bar
        cmd_box = ttk.LabelFrame(self.tab_actions, text=" 💻 直接指令發送列 (Direct CMD Execution) ", padding=10)
        cmd_box.pack(fill=tk.X, pady=(12, 0))

        c_inner = ttk.Frame(cmd_box)
        c_inner.pack(fill=tk.X)

        ttk.Label(c_inner, text="usp >", font=("Consolas", 11, "bold"), foreground="#0284c7").pack(side=tk.LEFT, padx=(0, 6))
        self.action_cmd_entry = tk.Entry(c_inner, font=("Consolas", 11), bg="#ffffff", fg="#0f172a", relief="solid", bd=1)
        self.action_cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)
        self.action_cmd_entry.bind("<Return>", lambda e: self.on_action_cmd_enter())

        btn_send = ttk.Button(c_inner, text="發送指令 (Enter)", style="Primary.TButton", command=self.on_action_cmd_enter)
        btn_send.pack(side=tk.LEFT)
        self._register_action_button(btn_send)

    # ------------------------------------------
    # Tab 3: CDRouter Test Scripts
    # ------------------------------------------
    def _build_scripts_tab(self):
        s_top = ttk.Frame(self.tab_scripts)
        s_top.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(s_top, text="測試腳本:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.combo_scripts = ttk.Combobox(s_top, width=38, state="readonly")
        self.combo_scripts.pack(side=tk.LEFT, padx=(0, 8))
        self._reload_scripts_dropdown()

        ttk.Button(s_top, text="🔄 重新載入", command=self._reload_scripts_dropdown).pack(side=tk.LEFT, padx=3)
        self.btn_run_script = ttk.Button(s_top, text="▶ 執行測試腳本", style="Primary.TButton", command=self.on_run_script_clicked)
        self.btn_run_script.pack(side=tk.LEFT, padx=8)

        # Metrics Banner
        self.lbl_script_metrics = ttk.Label(
            self.tab_scripts,
            text="尚未執行腳本。請由上方下拉選單選擇測試腳本並點擊「執行測試腳本」。",
            font=("Segoe UI", 9, "bold"),
            foreground="#64748b"
        )
        self.lbl_script_metrics.pack(anchor=tk.W, pady=(0, 8))

        # Progress Table
        cols = ("line", "cmd", "path", "status", "elapsed", "details")
        self.script_tree = ttk.Treeview(self.tab_scripts, columns=cols, show="headings")
        self.script_tree.heading("line", text="行號")
        self.script_tree.heading("cmd", text="指令")
        self.script_tree.heading("path", text="參數路徑 / 內容")
        self.script_tree.heading("status", text="狀態")
        self.script_tree.heading("elapsed", text="耗時")
        self.script_tree.heading("details", text="斷言與執行結果")

        self.script_tree.column("line", width=60, anchor=tk.CENTER)
        self.script_tree.column("cmd", width=95)
        self.script_tree.column("path", width=300)
        self.script_tree.column("status", width=85, anchor=tk.CENTER)
        self.script_tree.column("elapsed", width=75, anchor=tk.CENTER)
        self.script_tree.column("details", width=360)

        s_scroll_y = ttk.Scrollbar(self.tab_scripts, orient=tk.VERTICAL, command=self.script_tree.yview)
        self.script_tree.configure(yscrollcommand=s_scroll_y.set)

        self.script_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        s_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

    # ------------------------------------------
    # Tab 4: Server & Port Monitor Dashboard
    # ------------------------------------------
    def _build_monitor_tab(self):
        m_container = ttk.Frame(self.tab_monitor)
        m_container.pack(fill=tk.BOTH, expand=True)

        # Card 1: Daemon Process
        c1 = ttk.LabelFrame(m_container, text=" 🛡️ Daemon 後台守護行程狀態 ", padding=14)
        c1.pack(fill=tk.X, pady=(0, 10))

        self.lbl_mon_daemon = tk.Label(
            c1,
            text="Daemon 狀態:  檢查中...\n行程 PID:      -\n運行時間:      -\nIPC 通訊埠:    127.0.0.1:6001 (LISTENING)\n活躍執行緒:    -",
            font=("Consolas", 10),
            justify=tk.LEFT,
            bg="#ffffff",
            fg="#0f172a"
        )
        self.lbl_mon_daemon.pack(anchor=tk.W)

        # Card 2: Network & Port Monitor
        c2 = ttk.LabelFrame(m_container, text=" 🔌 通訊埠 (Ports) 監聽與佔用檢測 ", padding=14)
        c2.pack(fill=tk.X, pady=(0, 10))

        self.lbl_mon_ports = tk.Label(
            c2,
            text="Port 61614 (STOMP Broker):  檢測中...\nPort 6001  (IPC Server):    檢測中...\nPort 5353  (mDNS Discovery): READY",
            font=("Consolas", 10),
            justify=tk.LEFT,
            bg="#ffffff",
            fg="#0f172a"
        )
        self.lbl_mon_ports.pack(anchor=tk.W)

        # Card 3: STOMP Protocol & Queues
        c3 = ttk.LabelFrame(m_container, text=" 🌐 STOMP 協議與佇列配置 ", padding=14)
        c3.pack(fill=tk.BOTH, expand=True)

        self.lbl_mon_broker = tk.Label(
            c3,
            text="通訊協議:        STOMP 1.2\nBroker 位址:     127.0.0.1:61614\nController ID:   proto::controller.default\n接收佇列:        /queue/usp.controller.default\n已知 Agent 總數: 0",
            font=("Consolas", 10),
            justify=tk.LEFT,
            bg="#ffffff",
            fg="#0f172a"
        )
        self.lbl_mon_broker.pack(anchor=tk.W)

    # ------------------------------------------
    # Tab 5: Live Protocol & STOMP Logs
    # ------------------------------------------
    def _build_logs_tab(self):
        l_paned = ttk.PanedWindow(self.tab_logs, orient=tk.VERTICAL)
        l_paned.pack(fill=tk.BOTH, expand=True)

        # Upper: Log Table
        l_top = ttk.Frame(l_paned)
        l_paned.add(l_top, weight=1)

        l_bar = ttk.Frame(l_top)
        l_bar.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(l_bar, text="🔄 刷新日誌", command=self.refresh_logs).pack(side=tk.LEFT)
        ttk.Button(l_bar, text="🧹 清空日誌", command=self.on_clear_logs_clicked).pack(side=tk.LEFT, padx=6)
        ttk.Checkbutton(l_bar, text="自動更新 (每 1.5 秒)", variable=self.auto_refresh_logs).pack(side=tk.RIGHT)

        cols = ("id", "time", "type", "msg")
        self.log_tree = ttk.Treeview(l_top, columns=cols, show="headings", selectmode="browse")
        self.log_tree.heading("id", text="ID")
        self.log_tree.heading("time", text="時間戳記")
        self.log_tree.heading("type", text="類型")
        self.log_tree.heading("msg", text="訊息內容")

        self.log_tree.column("id", width=50, anchor=tk.CENTER)
        self.log_tree.column("time", width=140, anchor=tk.W)
        self.log_tree.column("type", width=85, anchor=tk.CENTER)
        self.log_tree.column("msg", width=620, anchor=tk.W)

        l_scroll = ttk.Scrollbar(l_top, orient=tk.VERTICAL, command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=l_scroll.set)

        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        l_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.bind("<<TreeviewSelect>>", self.on_log_row_selected)

        # Lower: Raw Frame / Log Details Viewer
        l_bottom = ttk.LabelFrame(l_paned, text=" 封包與日誌詳細內容檢視 (Raw Packet / Frame Details) ", padding=6)
        l_paned.add(l_bottom, weight=1)

        self.log_detail_text = scrolledtext.ScrolledText(
            l_bottom,
            wrap=tk.WORD,
            font=("Consolas", 10),
            background="#0f172a",
            foreground="#f8fafc",
            relief="flat",
            padx=10,
            pady=10
        )
        self.log_detail_text.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------
    # Tab 6: System & Network Configuration
    # ------------------------------------------
    def _build_config_tab(self):
        container = ttk.Frame(self.tab_config)
        container.pack(fill=tk.BOTH, expand=True)

        # 2 Column layout
        # Left column: STOMP Broker & Network Settings
        left_col = ttk.LabelFrame(container, text=" 🌐 STOMP Message Broker 連線設定 (支援外部/雲端/本機站點) ", padding=14)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        # Field: Broker Host
        row0 = ttk.Frame(left_col)
        row0.pack(fill=tk.X, pady=6)
        ttk.Label(row0, text="Broker 主機 / IP:", width=20, anchor=tk.W, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(row0, textvariable=self.cfg_broker_host_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: Broker Port
        row1 = ttk.Frame(left_col)
        row1.pack(fill=tk.X, pady=6)
        ttk.Label(row1, text="Broker 通訊埠 (Port):", width=20, anchor=tk.W, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.cfg_broker_port_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: Username
        row2 = ttk.Frame(left_col)
        row2.pack(fill=tk.X, pady=6)
        ttk.Label(row2, text="STOMP 帳號 (Username):", width=20, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.cfg_broker_user_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: Password
        row3 = ttk.Frame(left_col)
        row3.pack(fill=tk.X, pady=6)
        ttk.Label(row3, text="STOMP 密碼 (Password):", width=20, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(row3, textvariable=self.cfg_broker_pass_var, show="*").pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Test Broker Connection Button
        btn_test = ttk.Button(left_col, text="⚡ 測試外部 Broker 連線 (TCP Ping)", style="Action.TButton", command=self.on_test_broker_conn_clicked)
        btn_test.pack(fill=tk.X, pady=(16, 6))
        self.lbl_broker_test_result = ttk.Label(left_col, text="點擊上方按鈕測試目標 Broker IP / Port 是否通暢可達", foreground="#64748b", font=("Segoe UI", 9))
        self.lbl_broker_test_result.pack(anchor=tk.W)

        # Right column: Controller & System Settings
        right_col = ttk.LabelFrame(container, text=" 🛡️ USP Controller 主機與系統參數設定 ", padding=14)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        # Field: Controller ID
        rrow0 = ttk.Frame(right_col)
        rrow0.pack(fill=tk.X, pady=6)
        ttk.Label(rrow0, text="Controller Endpoint ID:", width=22, anchor=tk.W, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(rrow0, textvariable=self.cfg_controller_id_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: Receive Topic
        rrow1 = ttk.Frame(right_col)
        rrow1.pack(fill=tk.X, pady=6)
        ttk.Label(rrow1, text="接收監聽佇列 (Topic):", width=22, anchor=tk.W, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Entry(rrow1, textvariable=self.cfg_rx_topic_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: IPC Port
        rrow2 = ttk.Frame(right_col)
        rrow2.pack(fill=tk.X, pady=6)
        ttk.Label(rrow2, text="IPC API 通訊埠 (Port):", width=22, anchor=tk.W).pack(side=tk.LEFT)
        ttk.Entry(rrow2, textvariable=self.cfg_ipc_port_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Field: Debug Level
        rrow3 = ttk.Frame(right_col)
        rrow3.pack(fill=tk.X, pady=6)
        ttk.Label(rrow3, text="日誌調試級別 (Debug):", width=22, anchor=tk.W).pack(side=tk.LEFT)
        debug_cb = ttk.Combobox(rrow3, textvariable=self.cfg_debug_level_var, values=["0 - 僅 Agent (簡潔)", "1 - 雙向 Payload (標準)", "2 - 完整 STOMP 幀與細節 (除錯)"], state="readonly")
        debug_cb.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Checkboxes
        ttk.Checkbutton(right_col, text="自動註冊與記錄新連線的 USP Agent", variable=self.cfg_auto_register_var).pack(anchor=tk.W, pady=(10, 4))
        ttk.Checkbutton(right_col, text="啟用 mDNS 區域網路 Agent 自動廣播發現 (Port 5353)", variable=self.cfg_mdns_var).pack(anchor=tk.W, pady=4)

        # Status Label Row
        status_row = ttk.Frame(self.tab_config, padding=(0, 6, 0, 0))
        status_row.pack(fill=tk.X, side=tk.BOTTOM)
        self.lbl_cfg_save_status = ttk.Label(status_row, text="", font=("Segoe UI", 9, "bold"))
        self.lbl_cfg_save_status.pack(side=tk.LEFT)

        # Bottom Action Bar
        action_bar = ttk.Frame(self.tab_config, padding=(0, 14, 0, 0))
        action_bar.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Button(action_bar, text="💾 儲存設定至 config.json", style="Primary.TButton", command=self.on_save_config_clicked).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_bar, text="🔄 重新載入 config.json", command=self._load_config_to_vars).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_bar, text="💡 產生 DUT 設定指南", style="Action.TButton", command=self.on_show_dut_guide_clicked).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_bar, text="🚀 重啟 Controller 套用新設定", style="Launch.TButton", command=self.on_restart_controller_clicked).pack(side=tk.RIGHT)

    def _load_config_to_vars(self):
        """Load configuration from config.json into Tk variables"""
        try:
            cfg_path = Path(__file__).parent / "config.json"
            if cfg_path.exists():
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                usp = data.get("usp_controller", {})
                self.cfg_broker_host_var.set(usp.get("broker_host", "127.0.0.1"))
                self.cfg_broker_port_var.set(str(usp.get("broker_port", 61614)))
                self.cfg_broker_user_var.set(usp.get("username", "guest"))
                self.cfg_broker_pass_var.set(usp.get("password", "guest"))
                self.cfg_controller_id_var.set(usp.get("controller_endpoint_id", "proto::controller.default"))
                self.cfg_rx_topic_var.set(usp.get("receive_topic", "/queue/usp.controller.default"))

                ipc = data.get("ipc", {})
                self.cfg_ipc_port_var.set(str(ipc.get("port", 6001)))

                dbg = usp.get("debug_level", 1)
                dbg_map = {0: "0 - 僅 Agent (簡潔)", 1: "1 - 雙向 Payload (標準)", 2: "2 - 完整 STOMP 幀與細節 (除錯)"}
                self.cfg_debug_level_var.set(dbg_map.get(dbg, "1 - 雙向 Payload (標準)"))

                self.cfg_auto_register_var.set(usp.get("auto_register_devices", True))
                self.cfg_mdns_var.set(usp.get("enable_mdns_discovery", True))
                if hasattr(self, 'lbl_cfg_save_status'):
                    self.lbl_cfg_save_status.config(text="🔄 已成功從 config.json 重新載入設定！", foreground="#0284c7")
        except Exception as e:
            print(f"[GUI] Error loading config: {e}")

    def on_save_config_clicked(self):
        """Save form variables into config.json"""
        host = self.cfg_broker_host_var.get().strip()
        port_str = self.cfg_broker_port_var.get().strip()
        user = self.cfg_broker_user_var.get().strip()
        pwd = self.cfg_broker_pass_var.get().strip()
        ctrl_id = self.cfg_controller_id_var.get().strip()
        rx_topic = self.cfg_rx_topic_var.get().strip()
        ipc_port_str = self.cfg_ipc_port_var.get().strip()

        if not host or not port_str:
            if hasattr(self, 'lbl_cfg_save_status'):
                self.lbl_cfg_save_status.config(text="⚠️ STOMP Broker 主機與通訊埠不可為空！", foreground="#dc2626")
            return

        try:
            port = int(port_str)
            ipc_port = int(ipc_port_str)
        except ValueError:
            if hasattr(self, 'lbl_cfg_save_status'):
                self.lbl_cfg_save_status.config(text="⚠️ 通訊埠必須為數字格式！", foreground="#dc2626")
            return

        dbg_str = self.cfg_debug_level_var.get().split()[0]
        dbg_val = int(dbg_str) if dbg_str.isdigit() else 1

        cfg_path = Path(__file__).parent / "config.json"
        data = {}
        if cfg_path.exists():
            try:
                with open(cfg_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception:
                pass

        if "usp_controller" not in data:
            data["usp_controller"] = {}

        data["usp_controller"]["broker_host"] = host
        data["usp_controller"]["broker_port"] = port
        data["usp_controller"]["username"] = user
        data["usp_controller"]["password"] = pwd
        data["usp_controller"]["controller_endpoint_id"] = ctrl_id
        data["usp_controller"]["receive_topic"] = rx_topic
        data["usp_controller"]["debug_level"] = dbg_val
        data["usp_controller"]["auto_register_devices"] = self.cfg_auto_register_var.get()
        data["usp_controller"]["enable_mdns_discovery"] = self.cfg_mdns_var.get()

        if "ipc" not in data:
            data["ipc"] = {}
        data["ipc"]["port"] = ipc_port

        try:
            with open(cfg_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            if hasattr(self, 'lbl_cfg_save_status'):
                self.lbl_cfg_save_status.config(text=f"✅ 已成功儲存設定至 config.json (目標 Broker: {host}:{port})", foreground="#059669")
        except Exception as e:
            if hasattr(self, 'lbl_cfg_save_status'):
                self.lbl_cfg_save_status.config(text=f"❌ 儲存失敗: {e}", foreground="#dc2626")

    def on_test_broker_conn_clicked(self):
        """Test TCP connection to the specified Broker host and port"""
        host = self.cfg_broker_host_var.get().strip()
        port_str = self.cfg_broker_port_var.get().strip()
        try:
            port = int(port_str)
        except ValueError:
            self.lbl_broker_test_result.config(text="⚠️ 通訊埠必須為數字。", foreground="#dc2626")
            return

        self.lbl_broker_test_result.config(text=f"正在測試連線至 {host}:{port} ...", foreground="#0284c7")
        self.root.update_idletasks()

        def do_test():
            t0 = time.time()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                res = s.connect_ex((host, port))
                s.close()
                elapsed = round((time.time() - t0) * 1000, 1)
                if res == 0:
                    self.root.after(0, lambda: self.lbl_broker_test_result.config(
                        text=f"✅ 連線成功！{host}:{port} 可正常通訊 (延遲: {elapsed} ms)",
                        foreground="#059669"
                    ))
                else:
                    self.root.after(0, lambda: self.lbl_broker_test_result.config(
                        text=f"❌ 連線失敗！無法連接 {host}:{port} (錯誤代碼: {res})",
                        foreground="#dc2626"
                    ))
            except Exception as e:
                self.root.after(0, lambda: self.lbl_broker_test_result.config(
                    text=f"❌ 連線異常: {e}",
                    foreground="#dc2626"
                ))

        threading.Thread(target=do_test, daemon=True).start()

    def on_restart_controller_clicked(self):
        """Restart Controller daemon process to apply new config.json"""
        if hasattr(self, 'lbl_cfg_save_status'):
            self.lbl_cfg_save_status.config(text="🚀 正在重新啟動 Controller 守護進程...", foreground="#7c3aed")
        try:
            self.ipc_client.shutdown_daemon()
        except Exception:
            pass
        time.sleep(0.6)
        self.launch_daemon_black_window()
        if hasattr(self, 'lbl_cfg_save_status'):
            self.lbl_cfg_save_status.config(text="🚀 已啟動 Controller 黑窗！將自動連線至目標 Broker", foreground="#059669")


    def on_show_dut_guide_clicked(self):
        """Open a dedicated dialog presenting DUT TR-181 DataModel setup recommendations"""
        from usp_controller.device.dut_generator import DUTConfigGenerator, get_host_lan_ip
        from usp_controller.config import ConfigManager

        top = tk.Toplevel(self.root)
        top.title("📖 DUT (USP Agent) TR-181 DataModel 連線設定方向指南")
        top.geometry("860x640")
        top.minsize(700, 500)
        top.configure(bg="#f8fafc")

        # Top Bar
        header = ttk.Frame(top, padding=12)
        header.pack(fill=tk.X)

        ttk.Label(header, text="💡 DUT 連線設定指南生成器", font=("Segoe UI", 12, "bold"), foreground="#0369a1").pack(anchor=tk.W)
        ttk.Label(header, text="協助測試工程師快速了解外部 DUT 應設定哪些 TR-181 參數與建議數值以連上 Controller 與 Broker (Broker IP 預設自動帶入本機對外實體 LAN IP)", foreground="#64748b").pack(anchor=tk.W)

        # Controls Row
        ctrl_row = ttk.Frame(top, padding=(12, 4))
        ctrl_row.pack(fill=tk.X)

        default_agent = self.active_device_id or "proto::agent.001"
        agent_id_var = tk.StringVar(value=default_agent)
        fmt_var = tk.StringVar(value="📖 完整方向指南與參數說明")

        # Resolve initial broker host (auto-resolve loopback to LAN IP)
        init_cfg = None
        try:
            init_cfg = ConfigManager.load_config("config.json")
        except Exception:
            pass

        cfg_b_host = getattr(getattr(init_cfg, 'transport', None), 'host', '127.0.0.1') if init_cfg else '127.0.0.1'
        if cfg_b_host in ['127.0.0.1', 'localhost', '0.0.0.0', '::1', '']:
            default_broker_host = get_host_lan_ip()
        else:
            default_broker_host = cfg_b_host

        broker_host_var = tk.StringVar(value=default_broker_host)

        ttk.Label(ctrl_row, text="DUT Agent ID:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        ent_agent = ttk.Entry(ctrl_row, textvariable=agent_id_var, width=18)
        ent_agent.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(ctrl_row, text="Broker 對外 IP:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        ent_broker = ttk.Entry(ctrl_row, textvariable=broker_host_var, width=16)
        ent_broker.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(ctrl_row, text="展示格式:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        cb_fmt = ttk.Combobox(
            ctrl_row,
            textvariable=fmt_var,
            values=[
                "📖 完整方向指南與參數說明",
                "📜 TR-181 原生參數清單 (快速複製)",
                "🌐 OpenWrt / prplOS (UCI 指令)",
                "⚡ 一鍵 Shell 腳本 (setup_dut.sh)",
                "🐧 Broadband Forum (OB-USP-Agent)",
                "📄 JSON DataModel Profile"
            ],
            state="readonly",
            width=28
        )
        cb_fmt.pack(side=tk.LEFT, padx=(0, 8))

        # Text Display Area
        txt_frame = ttk.Frame(top, padding=12)
        txt_frame.pack(fill=tk.BOTH, expand=True)

        txt_guide = scrolledtext.ScrolledText(
            txt_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            background="#0f172a",
            foreground="#f8fafc",
            relief="flat",
            padx=10,
            pady=10
        )
        txt_guide.pack(fill=tk.BOTH, expand=True)

        def update_content(*args):
            dut_id = agent_id_var.get().strip() or "proto::agent.001"
            selected_fmt = fmt_var.get()
            custom_b_host = broker_host_var.get().strip() or None

            # Load latest config
            cfg = None
            try:
                cfg = ConfigManager.load_config("config.json")
            except Exception:
                pass

            if "完整方向指南" in selected_fmt:
                text = DUTConfigGenerator.generate_guide(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            elif "TR-181" in selected_fmt:
                text = DUTConfigGenerator.generate_tr181_commands(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            elif "OpenWrt" in selected_fmt:
                text = DUTConfigGenerator.generate_openwrt_uci(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            elif "Shell" in selected_fmt:
                text = DUTConfigGenerator.generate_shell_script(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            elif "OB-USP-Agent" in selected_fmt:
                text = DUTConfigGenerator.generate_obuspa_config(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            elif "JSON" in selected_fmt:
                text = DUTConfigGenerator.generate_json_profile(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)
            else:
                text = DUTConfigGenerator.generate_guide(cfg, dut_endpoint_id=dut_id, broker_host=custom_b_host)

            txt_guide.delete("1.0", tk.END)
            txt_guide.insert(tk.END, text)

        agent_id_var.trace_add("write", update_content)
        broker_host_var.trace_add("write", update_content)
        fmt_var.trace_add("write", update_content)
        update_content()


        # Bottom Buttons
        btn_bar = ttk.Frame(top, padding=(12, 10))
        btn_bar.pack(fill=tk.X, side=tk.BOTTOM)

        def copy_to_clipboard():
            content = txt_guide.get("1.0", tk.END).strip()
            top.clipboard_clear()
            top.clipboard_append(content)
            show_selectable_dialog(top, "已複製", "✅ 設定指南已成功複製至剪貼簿！", dialog_type="success")

        def save_to_file():
            from tkinter import filedialog
            content = txt_guide.get("1.0", tk.END).strip()
            fpath = filedialog.asksaveasfilename(
                title="另存設定指南檔案",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("Shell Scripts", "*.sh"), ("All files", "*.*")],
                parent=top
            )
            if fpath:
                try:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(content)
                    show_selectable_dialog(top, "成功", f"✅ 已成功儲存至:\n{fpath}", dialog_type="success")
                except Exception as ex:
                    show_selectable_dialog(top, "錯誤", f"儲存檔案失敗:\n{ex}", dialog_type="error")

        ttk.Button(btn_bar, text="📋 複製到剪貼簿", style="Primary.TButton", command=copy_to_clipboard).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_bar, text="💾 另存為檔案...", command=save_to_file).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_bar, text="關閉", command=top.destroy).pack(side=tk.RIGHT)

    # ==========================================
    # Event Handlers & IPC Logic
    # ==========================================


    def _periodic_daemon_polling(self):
        """Periodic background status & log polling"""
        while self.polling_running:
            try:

                alive = self.ipc_client.is_daemon_alive(timeout=0.3)
                if alive:
                    st = self.ipc_client.get_status()
                    devs, active = self.ipc_client.get_devices()
                    logs = self.ipc_client.get_logs(since_id=self.last_log_id, max_count=25) if self.auto_refresh_logs.get() else []
                    self.root.after(0, lambda s=st, d=devs, a=active, l=logs: self._update_gui_from_poll(s, d, a, l))
                else:
                    self.root.after(0, self._update_gui_offline)
            except Exception:
                pass
            time.sleep(1.5)

    def _update_gui_from_poll(self, status: dict, devices: list, active: str, logs: list):
        self.cached_devices = devices
        self.active_device_id = active

        d_info = status.get("daemon", {})
        pid = d_info.get("pid", "-")
        uptime = d_info.get("uptime", 0)

        b_info = status.get("broker", {})
        b_conn = b_info.get("connected", False)
        b_state = b_info.get("state", "CONNECTED" if b_conn else "DISCONNECTED")
        b_info = status.get("broker", {})
        b_conn = b_info.get("connected", False)
        b_state = b_info.get("state", "CONNECTED" if b_conn else "DISCONNECTED")
        b_host = b_info.get("host", "127.0.0.1")
        b_port = b_info.get("port", 61614)
        rx_topic = b_info.get("receive_topic", "/queue/usp.controller.default")
        reply_q = b_info.get("reply_to_queue", "/queue/proto::controller.default")
        subs = b_info.get("subscriptions", [])

        p_info = status.get("ports", {})
        b_listening = check_port_listening(b_host, b_port, timeout=0.1)

        # Update Top Header
        conn_str = f"🟢 {b_state}" if b_conn else f"🔴 {b_state}"
        self.lbl_header_status.config(
            text=f"Controller: 🟢 RUNNING (PID {pid}, Uptime {uptime}s) | Broker Port: {'🟢 61614' if b_listening else '🔴 CLOSED'} | Controller ↔ Broker: {conn_str}"
        )
        self.btn_daemon_toggle.config(
            text="🛑 關閉 Controller",
            style="Danger.TButton",
            state="normal",
            command=self.on_stop_daemon_clicked
        )

        # Update Sub Bar
        if b_listening:
            self.lbl_sub_broker_port.config(text=f"{b_port} (LISTENING)", foreground="#059669")
            self.btn_broker_toggle.config(text="🛑 關閉 Broker", style="Danger.TButton", command=self.stop_broker_process)
        else:
            self.lbl_sub_broker_port.config(text=f"{b_port} (CLOSED)", foreground="#dc2626")
            self.btn_broker_toggle.config(text="⚡ 啟動 Broker 黑窗", style="Launch.TButton", command=self.launch_broker_black_window)

        self.lbl_sub_broker_conn.config(
            text=f"🟢 {b_state}" if b_conn else f"🔴 {b_state}",
            foreground="#059669" if b_conn else "#dc2626"
        )
        self.lbl_sub_ipc.config(text=f"6001 (LISTENING, PID {pid})", foreground="#059669")
        self.lbl_sub_target.config(text=active or "(未設定)", foreground="#0284c7" if active else "#d97706")

        # Update Monitor Tab Cards
        self.lbl_mon_daemon.config(
            text=f"Controller 狀態: 🟢 RUNNING (正常運行中)\n行程 PID:        {pid}\n運行時間:        {uptime} 秒\nIPC 通訊埠:      127.0.0.1:6001 (LISTENING)\n活躍執行緒:      {d_info.get('active_threads', '-')}"
        )
        self.lbl_mon_ports.config(
            text=f"Port {b_port} (STOMP Broker):  {'● LISTENING (已監聽)' if b_listening else '○ CLOSED (未開啟)'}\nPort 6001  (IPC Server):    ● LISTENING (IPC API Ready)\nPort 5353  (mDNS Discovery): ● READY"
        )
        self.lbl_mon_broker.config(
            text=f"Controller ↔ Broker: {'🟢 CONNECTED (正常連線通訊中)' if b_conn else '🔴 DISCONNECTED (尚未連線/等待 Broker 啟動)'}\n連線狀態 (State):   {b_state}\n通訊協議:          STOMP 1.2\nBroker 終端:       {b_host}:{b_port} ({'● LISTENING 已監聽' if b_listening else '○ CLOSED 未開啟'})\nController ID:     proto::controller.default\n接收監聽佇列:      {rx_topic}\n回覆回應佇列:      {reply_q}\n已訂閱主題:        {subs or [rx_topic]}\n已知 Agent 總數:   {len(devices)}"
        )

        # Update Device List
        self._render_devices_tree(devices)

        # Append Logs
        if logs:
            for entry in logs:
                entry_id = entry.get("id", -1)
                if entry_id > self.last_log_id:
                    self.last_log_id = entry_id
                    t_str = str(entry.get("time") or entry.get("timestamp") or time.strftime("%H:%M:%S"))
                    l_type = str(entry.get("type", "INFO")).upper()
                    msg = str(entry.get("msg") or entry.get("message") or "")
                    self.log_tree.insert("", 0, values=(entry_id, t_str, l_type, msg))


        self.status_bar.config(text=f"Controller 已連線 (PID {pid}) | Broker: {'已監聽' if b_listening else '未開啟'} | Controller↔Broker: {b_state}")

    def _update_gui_offline(self):
        b_listening = check_port_listening("127.0.0.1", 61614, timeout=0.1)
        self.lbl_header_status.config(
            text=f"Controller: 🔴 OFFLINE | STOMP Broker: {'🟢 61614 (LISTENING)' if b_listening else '🔴 61614 (CLOSED)'} | IPC: 🔴 6001 (CLOSED)"
        )
        self.btn_daemon_toggle.config(
            text="🚀 啟動 Controller 黑窗",
            style="Launch.TButton",
            state="normal",
            command=self.launch_daemon_black_window
        )

        if b_listening:
            self.lbl_sub_broker_port.config(text="61614 (LISTENING)", foreground="#059669")
            self.btn_broker_toggle.config(text="🛑 關閉 Broker", style="Danger.TButton", command=self.stop_broker_process)
        else:
            self.lbl_sub_broker_port.config(text="61614 (CLOSED)", foreground="#dc2626")
            self.btn_broker_toggle.config(text="⚡ 啟動 Broker 黑窗", style="Launch.TButton", command=self.launch_broker_black_window)

        self.lbl_sub_broker_conn.config(text="⚪ OFFLINE (Controller 離線)", foreground="#94a3b8")
        self.lbl_sub_ipc.config(text="6001 (OFFLINE)", foreground="#dc2626")

        self.lbl_mon_daemon.config(text="Controller 狀態: 🔴 OFFLINE (未啟動)\n行程 PID:        -\n運行時間:        -\nIPC 通訊埠:      127.0.0.1:6001 (CLOSED)\n活躍執行緒:      -")
        self.lbl_mon_ports.config(
            text=f"Port 61614 (STOMP Broker):  {'● LISTENING (已監聽)' if b_listening else '○ CLOSED (未開啟)'}\nPort 6001  (IPC Server):    ○ CLOSED (Controller 未啟動)\nPort 5353  (mDNS Discovery): ● READY"
        )
        self.lbl_mon_broker.config(
            text=f"Controller ↔ Broker: ⚪ OFFLINE (Controller 未啟動)\n通訊協議:          STOMP 1.2\nBroker 位址:       127.0.0.1:61614 ({'● LISTENING 已監聽' if b_listening else '○ CLOSED 未開啟'})\nController ID:     proto::controller.default\n接收佇列:          /queue/usp.controller.default\n已知 Agent 總數:   0"
        )
        self.status_bar.config(text="Controller 未啟動。可分別啟動 Broker 黑窗與 Controller 黑窗。")





    def _filter_devices(self):
        self._render_devices_tree(self.cached_devices)

    def _render_devices_tree(self, devices: list):
        self.cached_devices = devices or []
        filter_text = self.dev_filter_var.get().strip().lower()

        filtered = []
        for d in self.cached_devices:
            ep = d.get("endpoint_id", "")
            if filter_text and filter_text not in ep.lower():
                continue
            filtered.append(d)

        self.lbl_dev_count.config(text=f"已發現 {len(filtered)} 個設備 (每 1.5 秒自動更新)")

        # Remember currently selected endpoint before clearing
        current_sel = self.dev_tree.selection()
        selected_ep = self.dev_tree.item(current_sel[0])["values"][1] if current_sel and len(self.dev_tree.item(current_sel[0])["values"]) > 1 else self.active_device_id

        self.dev_tree.delete(*self.dev_tree.get_children())
        for d in filtered:
            ep = d.get("endpoint_id", "")
            is_online = (d.get("status") == "online")
            st_text = "🟢 [ON]" if is_online else "🔴 [OFF]"
            ip = d.get("ip_address", d.get("reply_to", "STOMP"))
            proto = d.get("protocol", "STOMP").upper()
            tag = "online" if is_online else "offline"

            item_id = self.dev_tree.insert("", tk.END, values=(st_text, ep, ip, proto), tags=(tag,))
            if ep == selected_ep or (not selected_ep and ep == self.active_device_id):
                self.dev_tree.selection_set(item_id)
                self.selected_device_id = ep

    def on_device_selected(self, event=None):
        selected = self.dev_tree.selection()
        if not selected:
            return
        vals = self.dev_tree.item(selected[0])["values"]
        if not vals or len(vals) < 2:
            return
        ep = str(vals[1])
        self.selected_device_id = ep
        self.lbl_selected_title.config(text=f"當前選中設備: {ep}")
        st_label = "在線" if "[ON]" in str(vals[0]) else "離線"
        self.lbl_selected_detail.config(text=f"通道: {vals[2]} | 通訊協議: {vals[3]} | 狀態: {st_label}")
        
        # Auto sync active target on click
        if self.active_device_id != ep:
            self.active_device_id = ep
            self.lbl_sub_target.config(text=ep, foreground="#0284c7")
            threading.Thread(target=lambda: self.ipc_client.set_target(ep), daemon=True).start()


    def on_set_active_target(self):
        if not self.selected_device_id:
            self.show_info("提示", "請先在左側清單中選擇一個 Agent 設備。")
            return
        ok = self.ipc_client.set_target(self.selected_device_id)
        if ok:
            self.active_device_id = self.selected_device_id
            self.lbl_sub_target.config(text=self.active_device_id, foreground="#0284c7")
            self.show_success("成功", f"已將主控目標切換為:\n{self.selected_device_id}")
        else:
            self.show_error("失敗", "切換目標設備失敗，請確認 Daemon 運行狀態。")

    def on_probe_agent_clicked(self):
        """Prompt user for Agent Endpoint ID and proactively probe/discover it"""
        ep = simpledialog.askstring("探測 / 新增 Agent", "請輸入欲連線與探測的 Agent Endpoint ID:\n(例如: proto::agent.001)", parent=self.root)
        if not ep or not ep.strip():
            return
        ep = ep.strip()
        if not self._acquire_request_lock(f"探測 Agent ({ep})"):
            return

        self.status_bar.config(text=f"正在向 {ep} 發送 USP 探測請求 (Get Device.DeviceInfo.) ...")
        self.root.update_idletasks()

        def do_probe():
            try:
                res = self.ipc_client.exec_cmd(f"get {ep} Device.DeviceInfo.", timeout=8.0)
                def on_done():
                    if res.success:
                        self.ipc_client.set_target(ep)
                        self.refresh_devices()
                        self.status_bar.config(text=f"已成功探測並連線至 Agent: {ep}")
                        self.show_success("探測成功", f"已成功收到來自 {ep} 的回應，並已自動註冊至設備清單！")
                    else:
                        self.status_bar.config(text=f"探測 {ep} 未收到回應: {res.error}")
                        self.show_warning("探測未回應", f"向 {ep} 發送請求未收到回應。\n\n可能原因:\n1. DUT 尚未啟動或尚未連上 STOMP Broker (192.168.1.126:61614)\n2. Windows 防火牆未放行 61614 埠\n3. DUT 的 Controller 白名單未設定 Controller ID: proto::controller.default\n4. DUT 的接收 Topic 與設定不一致\n\n詳細錯誤訊息:\n{res.error}")
                self.root.after(0, on_done)
            finally:
                self._release_request_lock()

        threading.Thread(target=do_probe, daemon=True).start()

    def on_remove_selected_device_clicked(self):
        if not self.selected_device_id:
            self.show_info("提示", "請先在左側清單中選擇欲移除的設備。")
            return
        if messagebox.askyesno("確認移除", f"確定要從設備清單中移除「{self.selected_device_id}」嗎？"):
            ok = self.ipc_client.remove_device(self.selected_device_id)
            if ok:
                self.selected_device_id = None
                self.refresh_devices()
                self.status_bar.config(text="已移除指定設備。")
            else:
                self.show_error("錯誤", "移除設備失敗。")

    def on_clear_offline_clicked(self):
        count = self.ipc_client.clear_offline_devices()
        self.refresh_devices()
        self.status_bar.config(text=f"已清理 {count} 個離線設備。")
        self.show_success("清理完成", f"已成功清除 {count} 個離線設備！")

    def on_refresh_connect_clicked(self):
        self.refresh_devices()


    def launch_broker_black_window(self):
        """Launch standalone STOMP Broker in its own dedicated black window"""
        try:
            if sys.platform == 'win32':
                subprocess.Popen(
                    [sys.executable, "tools/embedded_broker.py", "--port", "61614"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=str(Path(__file__).parent)
                )
            else:
                subprocess.Popen([sys.executable, "tools/embedded_broker.py", "--port", "61614"], cwd=str(Path(__file__).parent))
        except Exception as e:
            self.show_error("啟動錯誤", f"無法啟動 STOMP Broker:\n{e}")

    def stop_broker_process(self):
        """Stop standalone STOMP Broker process and close port 61614"""
        try:
            from tools.embedded_broker import kill_process_on_port
            kill_process_on_port(61614)
            if self.internal_broker:
                try:
                    self.internal_broker.stop()
                except Exception:
                    pass
                self.internal_broker = None
            time.sleep(0.3)
            self._update_gui_offline()
        except Exception as e:
            self.show_error("錯誤", f"關閉 STOMP Broker 失敗:\n{e}")

    def launch_daemon_black_window(self):
        """Launch USP Controller Daemon in its own dedicated black console window"""
        try:
            if sys.platform == 'win32':
                subprocess.Popen(
                    [sys.executable, "tools/usp_daemon.py"],
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    cwd=str(Path(__file__).parent)
                )
            else:
                subprocess.Popen([sys.executable, "tools/usp_daemon.py"], cwd=str(Path(__file__).parent))
        except Exception as e:
            self.show_error("啟動錯誤", f"無法啟動 Controller:\n{e}")

    def on_stop_daemon_clicked(self):
        """Ask Controller Daemon to shut down and close its console window"""
        ok = self.ipc_client.shutdown_daemon()
        self._update_gui_offline()



    def on_ping_clicked(self):

        t0 = time.time()
        ok = self.ipc_client.ping()
        elapsed = round((time.time() - t0) * 1000, 2)
        if ok:
            self.show_success("Ping 測試", f"Daemon 伺服器連線正常！\n(延遲: {elapsed} ms)")
        else:
            self.show_error("Ping 測試", "無法連接 Daemon 伺服器 (127.0.0.1:6001)。\n請確認 Controller 守護進程是否已啟動。")

    # ------------------------------------------
    # Parameter Operations
    # ------------------------------------------
    def _get_target_prefix(self) -> str:
        target = self.selected_device_id or self.active_device_id
        return f"{target} " if target else ""

    def _on_param_row_clicked(self, event=None):
        selected = self.param_tree.selection()
        if not selected:
            return
        vals = self.param_tree.item(selected[0])["values"]
        if vals and len(vals) > 0:
            self.param_path_var.set(vals[0])

    def _on_param_double_clicked(self, event=None):
        """Quickly fill the double-clicked parameter path into the top path entry"""
        selected = self.param_tree.selection()
        if not selected:
            return
        vals = self.param_tree.item(selected[0])["values"]
        if vals and len(vals) > 0:
            path = vals[0]
            self.param_path_var.set(path)
            self.status_bar.config(text=f"已帶入參數路徑: {path}")

    def on_clear_param_tree_clicked(self):
        """Clear all parameter rows in the table"""
        self.cached_params.clear()
        self.param_tree.delete(*self.param_tree.get_children())
        if hasattr(self, 'lbl_param_count'):
            self.lbl_param_count.config(text="顯示: 0 / 0 筆")
        self.status_bar.config(text="已清空參數檢視表。")



    def on_param_get_clicked(self):
        path = self.param_path_var.get().strip()
        if not path:
            self.show_warning("警告", "請輸入欲查詢的參數路徑。")
            return

        cmd = f"get {self._get_target_prefix()}{path}"
        self._execute_param_cmd_and_render(cmd)

    def on_param_set_clicked(self):
        path = self.param_path_var.get().strip()
        val = simpledialog.askstring("修改參數值 (Set)", f"請輸入參數 '{path}' 的新數值:")
        if val is None:
            return

        cmd = f"set {self._get_target_prefix()}{path} {val}"
        self._execute_param_cmd_and_render(cmd)

    def on_param_add_clicked(self):
        path = self.param_path_var.get().strip()
        if not path.endswith("."):
            path += "."
        cmd = f"add {self._get_target_prefix()}{path}"
        self._execute_param_cmd_and_render(cmd)

    def on_param_delete_clicked(self):
        path = self.param_path_var.get().strip()
        if not messagebox.askyesno("確認刪除", f"確定要刪除實例物件 '{path}' 嗎？"):
            return
        cmd = f"delete {self._get_target_prefix()}{path}"
        self._execute_param_cmd_and_render(cmd)

    def on_param_get_dm_clicked(self):
        path = self.param_path_var.get().strip()
        cmd = f"get_supported_dm {self._get_target_prefix()}{path}"
        self._execute_param_cmd_and_render(cmd)

    def on_param_get_inst_clicked(self):
        path = self.param_path_var.get().strip()
        cmd = f"get_instances {self._get_target_prefix()}{path}"
        self._execute_param_cmd_and_render(cmd)

    def _execute_param_cmd_and_render(self, cmd_line: str):
        op_name = cmd_line.split()[0].upper()
        if not self._acquire_request_lock(f"參數操作 ({op_name})"):
            return

        def run():
            try:
                res = self.ipc_client.exec_cmd(cmd_line, timeout=12.0)
                self.root.after(0, lambda r=res: self._handle_param_result(r))
            except Exception as e:
                from usp_controller.ipc import IPCResponse
                err_res = IPCResponse(success=False, error=f"請求異常: {e}")
                self.root.after(0, lambda r=err_res: self._handle_param_result(r))
            finally:
                self._release_request_lock()

        threading.Thread(target=run, daemon=True).start()

    def _handle_param_result(self, res, show_dialog: bool = True):
        if not res.success:
            if show_dialog:
                err_msg = res.error or "指令執行未成功"
                if res.data:
                    err_msg += f"\n\n【詳細資訊 / Error Data】:\n{json.dumps(res.data, indent=2, ensure_ascii=False)}"
                self.show_error("操作失敗", err_msg)
            return

        now_str = time.strftime("%H:%M:%S")
        updated_count = 0

        # TR-369 Type & Access Decoders
        val_type_map = {
            0: "Unknown", 1: "Unspecified", 2: "Boolean", 3: "DateTime",
            4: "Int", 5: "UnsignedInt", 6: "Long", 7: "UnsignedLong",
            8: "String", 9: "Bytes", 10: "Base64", 11: "HexBinary", 12: "Decimal"
        }
        param_access_map = {0: "唯讀 (RO)", 1: "可讀寫 (RW)", 2: "唯寫 (WO)"}
        obj_access_map = {0: "唯讀 (RO)", 1: "可增刪 (RW)", 2: "僅新增 (Add)", 3: "僅刪除 (Del)"}

        def parse_supported_dm_item(item_obj):
            nonlocal updated_count
            s_objs = item_obj.get("supported_objs", [])
            for s_obj in s_objs:
                obj_path = s_obj.get("supported_obj_path", "")
                raw_obj_acc = s_obj.get("access", 0)
                obj_acc = obj_access_map.get(raw_obj_acc, "物件 (RO)") if isinstance(raw_obj_acc, int) else str(raw_obj_acc)
                if obj_path:
                    self._upsert_param_row(obj_path, "(Object Schema)", "Object", obj_acc, now_str)
                    updated_count += 1

                for p in s_obj.get("supported_params", []):
                    p_name = p.get("param_name", "")
                    full_path = (obj_path + p_name) if obj_path.endswith(".") else f"{obj_path}.{p_name}"
                    raw_t = p.get("value_type", 8)
                    p_type = val_type_map.get(raw_t, str(raw_t)) if isinstance(raw_t, int) else str(raw_t)
                    raw_a = p.get("access", 0)
                    p_acc = param_access_map.get(raw_a, "可讀寫 (RW)" if raw_a == 1 else "唯讀 (RO)") if isinstance(raw_a, int) else str(raw_a)
                    self._upsert_param_row(full_path, "(Schema Definition)", p_type, p_acc, now_str)
                    updated_count += 1

                for cmd in s_obj.get("supported_commands", []):
                    c_name = cmd.get("command_name", "")
                    full_path = (obj_path + c_name) if obj_path.endswith(".") else f"{obj_path}.{c_name}"
                    self._upsert_param_row(full_path, "(Command RPC)", "Command", "可執行 (Exec)", now_str)
                    updated_count += 1

                for ev in s_obj.get("supported_events", []):
                    e_name = ev.get("event_name", "")
                    full_path = (obj_path + e_name) if obj_path.endswith(".") else f"{obj_path}.{e_name}"
                    self._upsert_param_row(full_path, "(Event)", "Event", "事件通知", now_str)
                    updated_count += 1

        if isinstance(res.data, list):
            for item in res.data:
                if isinstance(item, dict):
                    # Check if GetSupportedDM format
                    if "supported_objs" in item or "req_obj_path" in item:
                        parse_supported_dm_item(item)
                    else:
                        # Format: {"Parameter": "...", "Value": "..."} or {"path": "...", "value": "..."}
                        p = item.get("Parameter") or item.get("path") or item.get("param") or item.get("instantiated_path")
                        v = item.get("Value") if "Value" in item else item.get("value", "")
                        ptype = item.get("Type") or item.get("type") or (type(v).__name__ if v != "" else "String")
                        pacc = item.get("access") or item.get("writable")
                        pacc_str = "可讀寫 (RW)" if pacc is True or pacc == 1 else ("唯讀 (RO)" if pacc is False or pacc == 0 else (str(pacc) if pacc else "-"))
                        if p:
                            self._upsert_param_row(str(p), str(v), str(ptype), pacc_str, now_str)
                            updated_count += 1
                elif isinstance(item, str):
                    # Format: list of instance paths e.g. "Device.IP.Interface.1."
                    self._upsert_param_row(str(item), "(Instance / Object)", "Object", "實例 (Inst)", now_str)
                    updated_count += 1

        elif isinstance(res.data, dict):
            if "supported_dm" in res.data and isinstance(res.data["supported_dm"], list):
                for dm_item in res.data["supported_dm"]:
                    parse_supported_dm_item(dm_item)
            elif "instances" in res.data and isinstance(res.data["instances"], list):
                for inst_path in res.data["instances"]:
                    self._upsert_param_row(str(inst_path), "(Instance / Object)", "Object", "實例 (Inst)", now_str)
                    updated_count += 1
            else:
                params = res.data.get("parameters", res.data)
                if isinstance(params, dict):
                    for p, v in params.items():
                        ptype = type(v).__name__
                        self._upsert_param_row(str(p), str(v), ptype, "-", now_str)
                        updated_count += 1
                elif isinstance(params, list):
                    for item in params:
                        if isinstance(item, dict):
                            if "supported_objs" in item:
                                parse_supported_dm_item(item)
                            else:
                                p = item.get("Parameter") or item.get("path") or item.get("param")
                                v = item.get("Value", item.get("value", ""))
                                if p:
                                    self._upsert_param_row(str(p), str(v), "String", "-", now_str)
                                    updated_count += 1
                        else:
                            self._upsert_param_row(str(item), "(Instance / Object)", "Object", "實例 (Inst)", now_str)
                            updated_count += 1

        if updated_count > 0:
            self._filter_params()
            self.status_bar.config(text=f"已成功更新 {updated_count} 筆參數至檢視表 ({now_str})")

        # Show complete result & payload dialog
        if show_dialog:
            lines = []
            if res.message:
                lines.append(f"【狀態訊息】\n{res.message}\n")
            elif updated_count > 0:
                lines.append(f"【狀態訊息】\n已成功查詢並更新 {updated_count} 筆參數/架構至檢視表！\n")
            else:
                lines.append("【狀態訊息】\n操作已成功完成！\n")

            if res.data is not None:
                lines.append("【回應 Payload 內容】")
                if isinstance(res.data, (dict, list)):
                    lines.append(json.dumps(res.data, indent=2, ensure_ascii=False))
                else:
                    lines.append(str(res.data))

            msg = "\n".join(lines) if lines else "操作成功完成 (無回傳內容)"
            self.show_success("操作成功與 Payload 回應", msg)

    def _normalize_schema_pattern(self, schema_path: str) -> str:
        """Convert a schema path with {i} to a regex pattern matching instances"""
        import re
        escaped = re.escape(schema_path)
        pattern = escaped.replace(r'\{i\}', r'\d+')
        return f"^{pattern}$"

    def _sync_schema_to_instances(self, schema_path: str, ptype: str, access: str):
        """When a schema path with {i} is updated, propagate its type & access to all existing instantiated paths"""
        import re
        if "{i}" not in schema_path:
            return
        pattern = self._normalize_schema_pattern(schema_path)
        prog = re.compile(pattern)
        for path, item in self.cached_params.items():
            if "{i}" not in path and prog.match(path):
                if access and access != "-":
                    item["access"] = access
                if ptype and ptype not in ("-", "String", "Object") and item.get("type") in ("-", "String"):
                    item["type"] = ptype

    def _find_schema_for_instance(self, inst_path: str):
        """Find matching schema definition for an instantiated path to inherit type & access"""
        import re
        for path, item in self.cached_params.items():
            if "{i}" in path:
                pattern = self._normalize_schema_pattern(path)
                if re.match(pattern, inst_path):
                    return item.get("type"), item.get("access")
        return None, None

    def _clear_param_filter(self):
        """Clear filter entry and show all parameters"""
        self.param_filter_var.set("")
        self._filter_params()

    def _filter_params(self):
        """Filter parameters by path, value, type, or access in real time (supporting instance matching)"""
        import re
        filter_text = self.param_filter_var.get().strip().lower()
        self.param_tree.delete(*self.param_tree.get_children())

        displayed = 0
        total = len(self.cached_params)

        # Build normalized filter regex if user typed numbered instance
        filter_norm = re.sub(r'\.\d+\.', '.{i}.', filter_text) if filter_text else ""

        for path, item in sorted(self.cached_params.items()):
            val = str(item.get("value", ""))
            ptype = str(item.get("type", ""))
            access = str(item.get("access", "-"))
            updated = str(item.get("updated", ""))

            # Filter matches path, value, type, or access
            if filter_text:
                path_lower = path.lower()
                matches_path = (filter_text in path_lower) or (filter_norm and filter_norm in path_lower)
                if (not matches_path and 
                    filter_text not in val.lower() and 
                    filter_text not in ptype.lower() and 
                    filter_text not in access.lower()):
                    continue

            self.param_tree.insert("", tk.END, values=(path, val, ptype, access, updated))
            displayed += 1

        self.lbl_param_count.config(text=f"顯示: {displayed} / {total} 筆")

    def _upsert_param_row(self, path: str, val: str, ptype: str, access: str, now_str: str):
        """Store into cache dict with access/writable support and schema-to-instance inheritance"""
        existing = self.cached_params.get(path, {})

        # If this is an instance path (without {i}) and access is unknown, inherit from matching schema
        if "{i}" not in path and (access == "-" or not access):
            schema_type, schema_acc = self._find_schema_for_instance(path)
            if schema_acc:
                access = schema_acc
            if schema_type and (ptype == "-" or ptype == "String"):
                ptype = schema_type

        # If new access is unspecified ("-"), preserve existing known access
        if access == "-" and "access" in existing and existing["access"] != "-":
            access = existing["access"]

        # If new val is "(Schema Definition)" and existing has an actual runtime value, keep the runtime value
        if val == "(Schema Definition)" and existing.get("value") and existing["value"] not in ("(Schema Definition)", "(Instance / Object)"):
            val = existing["value"]

        self.cached_params[path] = {
            "path": path,
            "value": val,
            "type": ptype,
            "access": access,
            "updated": now_str
        }

        # If this was a schema path with {i}, propagate to all matching existing instances in cache
        if "{i}" in path:
            self._sync_schema_to_instances(path, ptype, access)



    # ------------------------------------------
    # Direct CMD and Scripts
    # ------------------------------------------
    def on_action_cmd_enter(self):
        cmd = self.action_cmd_entry.get().strip()
        if not cmd:
            return
        self.action_cmd_entry.delete(0, tk.END)
        self.send_ipc_cmd_async(cmd)

    def send_ipc_cmd_async(self, cmd_line: str):
        if not self._acquire_request_lock(f"指令 ({cmd_line.split()[0]})"):
            return

        def run():
            try:
                res = self.ipc_client.exec_cmd(cmd_line, timeout=15.0)
                self.root.after(0, lambda r=res: self._show_cmd_result(r))
            except Exception as e:
                from usp_controller.ipc import IPCResponse
                err_res = IPCResponse(success=False, error=f"執行異常: {e}")
                self.root.after(0, lambda r=err_res: self._show_cmd_result(r))
            finally:
                self._release_request_lock()

        threading.Thread(target=run, daemon=True).start()

    def _show_cmd_result(self, res):
        if not res.success:
            err_msg = res.error or "指令執行失敗"
            if res.data:
                err_msg += f"\n\n【詳細數據 / Error Data】:\n{json.dumps(res.data, indent=2, ensure_ascii=False)}"
            self.show_error("執行失敗", err_msg)
        else:
            lines = []
            if res.message:
                lines.append(f"【狀態訊息】\n{res.message}\n")
            
            if res.data is not None:
                lines.append("【回應 Payload 內容】")
                if isinstance(res.data, (dict, list)):
                    lines.append(json.dumps(res.data, indent=2, ensure_ascii=False))
                else:
                    lines.append(str(res.data))
            
            msg = "\n".join(lines) if lines else "指令執行成功 (無額外回傳內容)"
            
            # Also auto-update parameters into Parameter Explorer table if data contains parameters
            if res.data:
                try:
                    self._handle_param_result(res, show_dialog=False)
                except Exception:
                    pass
                    
            self.show_success("執行結果與 Payload", msg)

    def _reload_scripts_dropdown(self):
        scripts_dir = Path(__file__).parent / "scripts"
        if scripts_dir.exists():
            txt_files = sorted([f.name for f in scripts_dir.glob("*.txt")])
            self.combo_scripts["values"] = txt_files
            if txt_files and not self.combo_scripts.get():
                self.combo_scripts.set(txt_files[0])

    def on_run_script_clicked(self):
        script_name = self.combo_scripts.get()
        if not script_name:
            self.show_warning("警告", "請選擇測試腳本。")
            return

        script_path = str(Path(__file__).parent / "scripts" / script_name)
        self.script_tree.delete(*self.script_tree.get_children())
        self.lbl_script_metrics.config(text=f"正在執行測試腳本: {script_name}...", foreground="#0284c7")

        def run():
            res = self.ipc_client.run_script(script_path, timeout=120.0)
            self.root.after(0, lambda r=res, s=script_name: self._handle_script_done(r, s))

        threading.Thread(target=run, daemon=True).start()

    def _handle_script_done(self, rep: dict, script_name: str):
        status = rep.get("status", "FAIL")
        total = rep.get("total_steps", 0)
        passed = rep.get("passed_count", 0)
        failed = rep.get("failed_count", 0)
        errors = rep.get("error_count", 0)
        elapsed = rep.get("elapsed_sec", 0.0)

        color = "#059669" if status == "PASS" else "#dc2626"
        summary = f"測試結果: {status}  |  {passed}/{total} 通過, {failed} 失敗, {errors} 錯誤  |  耗時: {elapsed} 秒  ({script_name})"
        self.lbl_script_metrics.config(text=summary, foreground=color)

    def refresh_devices(self):
        def run():
            devs, active = self.ipc_client.get_devices()
            self.root.after(0, lambda d=devs, a=active: self._render_devices_tree(d))

        threading.Thread(target=run, daemon=True).start()

    def refresh_logs(self):
        def run():
            logs = self.ipc_client.get_logs(since_id=-1, max_count=50)
            self.root.after(0, lambda l=logs: self._render_logs_full(l))

        threading.Thread(target=run, daemon=True).start()

    def _render_logs_full(self, logs: list):
        self.log_tree.delete(*self.log_tree.get_children())
        for entry in logs:
            entry_id = entry.get("id", -1)
            t_str = str(entry.get("time") or entry.get("timestamp") or time.strftime("%H:%M:%S"))
            l_type = str(entry.get("type", "INFO")).upper()
            msg = str(entry.get("msg") or entry.get("message") or "")
            self.log_tree.insert("", 0, values=(entry_id, t_str, l_type, msg))

    def on_log_row_selected(self, event=None):
        selected = self.log_tree.selection()
        if not selected:
            return
        vals = self.log_tree.item(selected[0])["values"]
        self.log_detail_text.delete("1.0", tk.END)
        log_id = vals[0] if len(vals) > 0 else "-"
        t_str = vals[1] if len(vals) > 1 else "-"
        l_type = vals[2] if len(vals) > 2 else "-"
        msg = vals[3] if len(vals) > 3 else ""

        detail_text = (
            f"======================================================================\n"
            f" [LOG DETAIL] ID: {log_id} | Time: {t_str} | Level: {l_type}\n"
            f"======================================================================\n\n"
            f"{msg}\n"
        )
        self.log_detail_text.insert(tk.END, detail_text)


    def on_clear_logs_clicked(self):
        self.ipc_client.clear_logs()
        self.log_tree.delete(*self.log_tree.get_children())
        self.log_detail_text.delete("1.0", tk.END)

    def on_close_window(self):
        self.polling_running = False
        if self.internal_broker:
            try:
                self.internal_broker.stop()
            except Exception:
                pass
            self.internal_broker = None
        self.root.destroy()



def main():
    root = tk.Tk()
    app = USPGuiApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
