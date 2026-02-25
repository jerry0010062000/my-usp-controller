#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interface Base Classes
定義統一的介面抽象層，類似 Transport 層設計
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field


class InterfaceType(Enum):
    """介面類型"""
    CLI = "cli"              # 命令行介面
    GUI_TKINTER = "gui_tk"   # Tkinter GUI
    WEB = "web"              # Web UI (未來)
    MOBILE = "mobile"        # Mobile App (未來)
    API = "api"              # REST API (未來)


@dataclass
class CommandContext:
    """
    命令執行上下文
    包含命令執行所需的所有資訊
    """
    command: str                              # 命令名稱 (get, set, list, etc.)
    args: List[str] = field(default_factory=list)  # 位置參數
    kwargs: Dict[str, Any] = field(default_factory=dict)  # 關鍵字參數
    raw_input: str = ""                       # 原始輸入
    user_data: Dict[str, Any] = field(default_factory=dict)  # 自定義數據
    
    @property
    def endpoint(self) -> Optional[str]:
        """獲取 endpoint（如果存在）"""
        return self.args[0] if len(self.args) > 0 else None
    
    @property
    def path(self) -> Optional[str]:
        """獲取 path（如果存在）"""
        return self.args[1] if len(self.args) > 1 else None
    
    @property
    def value(self) -> Optional[str]:
        """獲取 value（如果存在）"""
        return self.args[2] if len(self.args) > 2 else None


@dataclass
class CommandResult:
    """
    命令執行結果
    統一返回格式
    """
    success: bool                             # 是否成功
    message: str = ""                         # 訊息
    data: Any = None                          # 結果數據
    error: Optional[str] = None               # 錯誤訊息
    metadata: Dict[str, Any] = field(default_factory=dict)  # 元數據
    
    def __bool__(self) -> bool:
        return self.success


class InterfaceBase(ABC):
    """
    介面抽象基類
    
    所有 UI 實現（CLI/GUI/Web）都必須繼承此類
    類似 TransportProtocol 的設計理念
    """
    
    def __init__(self, interface_type: InterfaceType):
        self.interface_type = interface_type
        self._command_handler: Optional[Any] = None
        self._formatter: Optional[Any] = None
        self._callbacks: Dict[str, List[Callable]] = {
            'on_command': [],
            'on_result': [],
            'on_error': []
        }
    
    def set_command_handler(self, handler):
        """設置命令處理器"""
        self._command_handler = handler
    
    def set_formatter(self, formatter):
        """設置輸出格式化器"""
        self._formatter = formatter
    
    def register_callback(self, event: str, callback: Callable):
        """註冊回調函數"""
        if event in self._callbacks:
            self._callbacks[event].append(callback)
    
    def _emit(self, event: str, *args, **kwargs):
        """觸發回調"""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                print(f"[!] Callback error: {e}")
    
    @abstractmethod
    def initialize(self) -> bool:
        """
        初始化介面
        返回: 是否成功
        """
        pass
    
    @abstractmethod
    def run(self):
        """
        啟動介面主循環
        - CLI: input() 循環
        - GUI: mainloop()
        - Web: run server
        """
        pass
    
    @abstractmethod
    def shutdown(self):
        """關閉介面"""
        pass
    
    @abstractmethod
    def display_output(self, result: CommandResult):
        """
        顯示輸出結果
        不同介面有不同的顯示方式
        """
        pass
    
    @abstractmethod
    def display_error(self, error: str):
        """顯示錯誤訊息"""
        pass
    
    @abstractmethod
    def display_info(self, message: str):
        """顯示一般訊息"""
        pass
    
    @abstractmethod
    def prompt_input(self, prompt: str = "") -> str:
        """
        獲取使用者輸入
        - CLI: input()
        - GUI: Entry widget
        - Web: form submission
        """
        pass
    
    @abstractmethod
    def confirm_action(self, message: str) -> bool:
        """
        請求使用者確認
        返回: True/False
        """
        pass


class InterfaceFactory:
    """
    介面工廠
    類似 TransportFactory 的設計
    """
    
    _registry: Dict[InterfaceType, type] = {}
    
    @classmethod
    def register(cls, interface_type: InterfaceType, interface_class: type):
        """註冊介面實現"""
        cls._registry[interface_type] = interface_class
    
    @classmethod
    def create(cls, interface_type: InterfaceType, **kwargs) -> InterfaceBase:
        """
        創建介面實例
        
        參數:
            interface_type: 介面類型
            **kwargs: 傳遞給介面構造函數的參數
        
        返回:
            InterfaceBase 實例
        
        異常:
            ValueError: 未註冊的介面類型
        """
        if interface_type not in cls._registry:
            available = ", ".join([t.value for t in cls._registry.keys()])
            raise ValueError(
                f"Interface type '{interface_type.value}' not registered. "
                f"Available: {available}"
            )
        
        interface_class = cls._registry[interface_type]
        return interface_class(**kwargs)
    
    @classmethod
    def list_available(cls) -> List[InterfaceType]:
        """列出可用的介面類型"""
        return list(cls._registry.keys())
    
    @classmethod
    def is_available(cls, interface_type: InterfaceType) -> bool:
        """檢查介面是否可用"""
        return interface_type in cls._registry
