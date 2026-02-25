#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI Adapter Base Class
GUI 適配器基類，用於適配現有的 Tkinter GUI
"""

from abc import abstractmethod
from typing import Any, Callable, Dict, Optional
from .base import InterfaceBase, InterfaceType, CommandContext, CommandResult
from .command_handler import CommandHandler


class GUIAdapterBase(InterfaceBase):
    """
    GUI 適配器基類
    
    用於將現有的 GUI（如 Tkinter）適配到統一的介面層
    """
    
    def __init__(self, interface_type: InterfaceType = InterfaceType.GUI_TKINTER):
        super().__init__(interface_type)
        self._command_handler = CommandHandler()
        self._gui_callbacks: Dict[str, Callable] = {}
    
    def set_gui_callback(self, event: str, callback: Callable):
        """
        設置 GUI 特定的回調
        
        事件類型：
        - 'update_log': 更新日誌顯示
        - 'update_devices': 更新設備列表
        - 'update_status': 更新狀態欄
        """
        self._gui_callbacks[event] = callback
    
    def _trigger_gui_callback(self, event: str, *args, **kwargs):
        """觸發 GUI 回調"""
        callback = self._gui_callbacks.get(event)
        if callback:
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"[!] GUI callback error ({event}): {e}")
    
    @abstractmethod
    def update_log(self, message: str, level: str = "info"):
        """更新日誌顯示"""
        pass
    
    @abstractmethod
    def update_device_list(self, devices: list):
        """更新設備列表"""
        pass
    
    @abstractmethod
    def update_status(self, status: str):
        """更新狀態欄"""
        pass
    
    @abstractmethod
    def show_dialog(self, title: str, message: str, dialog_type: str = "info"):
        """
        顯示對話框
        
        參數:
            title: 標題
            message: 訊息內容
            dialog_type: 類型 (info, warning, error, question)
        """
        pass


class TkinterGUIAdapter(GUIAdapterBase):
    """
    Tkinter GUI 適配器
    
    用於適配現有的 usp_gui.py
    """
    
    def __init__(self, gui_instance=None):
        super().__init__(InterfaceType.GUI_TKINTER)
        self._gui = gui_instance
        self._running = False
    
    def set_gui_instance(self, gui_instance):
        """設置 GUI 實例"""
        self._gui = gui_instance
    
    def initialize(self) -> bool:
        """初始化 GUI 適配器"""
        if self._gui is None:
            print("[!] No GUI instance provided")
            return False
        
        return True
    
    def run(self):
        """啟動 GUI 主循環（由 GUI 本身控制）"""
        self._running = True
        # Tkinter 的 mainloop() 由 GUI 類自己調用
    
    def shutdown(self):
        """關閉 GUI"""
        self._running = False
        if self._gui and hasattr(self._gui, 'root'):
            try:
                self._gui.root.quit()
            except:
                pass
    
    def display_output(self, result: CommandResult):
        """顯示輸出（更新 GUI）"""
        if result.success:
            if result.message:
                self.update_log(result.message, "success")
            if result.data:
                # 根據數據類型更新相應的 GUI 元素
                if isinstance(result.data, list):
                    self.update_device_list(result.data)
                else:
                    self.update_log(str(result.data), "info")
        else:
            self.display_error(result.error or "Unknown error")
    
    def display_error(self, error: str):
        """顯示錯誤"""
        self.update_log(f"Error: {error}", "error")
        self.show_dialog("Error", error, "error")
    
    def display_info(self, message: str):
        """顯示訊息"""
        self.update_log(message, "info")
    
    def prompt_input(self, prompt: str = "") -> str:
        """GUI 不使用 prompt_input"""
        raise NotImplementedError("GUI uses widgets for input, not prompt_input")
    
    def confirm_action(self, message: str) -> bool:
        """請求確認（使用對話框）"""
        if self._gui and hasattr(self._gui, 'root'):
            from tkinter import messagebox
            return messagebox.askyesno("Confirm", message)
        return False
    
    def update_log(self, message: str, level: str = "info"):
        """更新日誌顯示"""
        if self._gui and hasattr(self._gui, '_append_log'):
            # 調用 GUI 的日誌添加方法
            self._gui._append_log(message, level)
        else:
            # 降級到控制台輸出
            print(f"[{level.upper()}] {message}")
    
    def update_device_list(self, devices: list):
        """更新設備列表"""
        if self._gui and hasattr(self._gui, 'update_device_list'):
            self._gui.update_device_list(devices)
        else:
            self.update_log(f"Devices updated: {len(devices)} devices", "info")
    
    def update_status(self, status: str):
        """更新狀態欄"""
        if self._gui and hasattr(self._gui, 'update_status'):
            self._gui.update_status(status)
        else:
            self.update_log(f"Status: {status}", "info")
    
    def show_dialog(self, title: str, message: str, dialog_type: str = "info"):
        """顯示對話框"""
        if self._gui and hasattr(self._gui, 'root'):
            from tkinter import messagebox
            
            if dialog_type == "info":
                messagebox.showinfo(title, message)
            elif dialog_type == "warning":
                messagebox.showwarning(title, message)
            elif dialog_type == "error":
                messagebox.showerror(title, message)
            elif dialog_type == "question":
                return messagebox.askyesno(title, message)
        else:
            print(f"[{dialog_type.upper()}] {title}: {message}")
    
    def execute_command(self, command_str: str) -> CommandResult:
        """
        執行命令（GUI 特定方法）
        
        GUI 可以通過此方法執行命令並獲取結果
        """
        context = self._command_handler.parse_command(command_str)
        result = self._command_handler.execute(context)
        
        # 更新 GUI 顯示
        self.display_output(result)
        
        return result


# 註冊到工廠
from .base import InterfaceFactory

InterfaceFactory.register(InterfaceType.GUI_TKINTER, TkinterGUIAdapter)
