#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日誌系統模組
提供執行緒安全的日誌記錄和歷史管理
"""

import threading
from datetime import datetime
from typing import List, Dict, Optional, Callable
from enum import Enum


class LogLevel(Enum):
    """日誌級別"""
    CRITICAL = 0
    ERROR = 1
    SUCCESS = 2
    INFO = 3
    DEBUG = 4


class LogType(Enum):
    """日誌類型"""
    CRITICAL = "critical"
    ERROR = "error"
    SUCCESS = "success"
    INFO = "info"
    DATA = "data"
    USP = "usp"
    STOMP = "stomp"
    DETAIL = "detail"


class LogEntry:
    """日誌條目"""
    def __init__(self, log_id: int, timestamp: str, log_type: str, message: str):
        self.id = log_id
        self.time = timestamp
        self.type = log_type
        self.msg = message
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'time': self.time,
            'type': self.type,
            'msg': self.msg
        }


class Logger:
    """
    線程安全的日誌管理器
    
    特性：
    - 執行緒安全
    - 記憶體循環緩衝區
    - 支援多種日誌類型
    - 可配置的輸出過濾
    - 支援callback通知
    """
    
    # 類別變數
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """單例模式"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """初始化日誌系統"""
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self.history: List[LogEntry] = []
            self.log_counter = 0
            self.max_history = 5000
            self.debug_level = 0
            self.callbacks: List[Callable] = []
            self._history_lock = threading.Lock()
    
    def set_debug_level(self, level: int) -> bool:
        """設置調試級別 (0-2)"""
        if 0 <= level <= 2:
            self.debug_level = level
            return True
        return False
    
    def add_callback(self, callback: Callable[[LogEntry], None]):
        """添加日誌回調函數"""
        with self._history_lock:
            if callback not in self.callbacks:
                self.callbacks.append(callback)
    
    def remove_callback(self, callback: Callable):
        """移除日誌回調函數"""
        with self._history_lock:
            if callback in self.callbacks:
                self.callbacks.remove(callback)
    
    def _add_entry(self, log_type: str, message: str) -> LogEntry:
        """添加日誌條目（內部方法）"""
        with self._history_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            entry = LogEntry(self.log_counter, timestamp, log_type, str(message))
            self.log_counter += 1
            self.history.append(entry)
            
            # 限制歷史大小
            if len(self.history) > self.max_history:
                self.history.pop(0)
            
            # 通知所有回調
            for callback in self.callbacks:
                try:
                    callback(entry)
                except Exception as e:
                    print(f"[Logger] Callback error: {e}")
            
            return entry
    
    def critical(self, message: str):
        """關鍵錯誤（總是顯示）"""
        print(f"[!] {message}")
        self._add_entry(LogType.CRITICAL.value, message)
    
    def error(self, message: str, level: int = 0):
        """錯誤訊息"""
        if self.debug_level >= level:
            print(f"[✗] {message}")
            self._add_entry(LogType.ERROR.value, message)
    
    def success(self, message: str, level: int = 1):
        """成功訊息"""
        if self.debug_level >= level:
            print(f"[✓] {message}")
            self._add_entry(LogType.SUCCESS.value, message)
    
    def info(self, message: str, level: int = 1):
        """一般資訊"""
        if self.debug_level >= level:
            print(f"[*] {message}")
            self._add_entry(LogType.INFO.value, message)
    
    def data(self, message: str, level: int = 0):
        """數據輸出"""
        if self.debug_level >= level:
            print(message)
            self._add_entry(LogType.DATA.value, message)
    
    def stomp_frame(self, direction: str, headers: Dict, body_preview: Optional[bytes] = None, level: int = 2):
        """STOMP幀日誌"""
        if self.debug_level < level:
            return
        
        arrow = ">>>>" if direction == "send" else "<<<<"
        print(f"\n{arrow} STOMP Frame {arrow}")
        
        if self.debug_level >= 2 and headers:
            for key, value in headers.items():
                print(f"  {key}: {value}")
        
        if self.debug_level >= 3 and body_preview:
            if isinstance(body_preview, bytes):
                if len(body_preview) > 100:
                    print(f"  Body: {body_preview[:100].hex()}... ({len(body_preview)} bytes)")
                else:
                    print(f"  Body: {body_preview.hex()}")
            else:
                print(f"  Body: {body_preview}")
        print("")
        
        self._add_entry(LogType.STOMP.value, f"{arrow} STOMP {direction}")
    
    def usp_message(self, direction: str, endpoint: str, msg_type: str, 
                    details: Optional[Dict] = None, level: int = 1):
        """USP訊息日誌"""
        if self.debug_level < level:
            return
        
        arrow = "→" if direction == "send" else "←"
        log_msg = f"{arrow} USP {msg_type} {arrow} {endpoint}"
        print(log_msg)
        self._add_entry(LogType.USP.value, log_msg)
        
        if self.debug_level >= 2 and details:
            for key, value in details.items():
                detail_msg = f"    {key}: {value}"
                print(detail_msg)
                self._add_entry(LogType.DETAIL.value, detail_msg)
    
    def get_history(self, since_id: int = -1, max_count: int = 100) -> List[Dict]:
        """獲取日誌歷史"""
        with self._history_lock:
            if since_id < 0:
                # 返回最後max_count條
                return [entry.to_dict() for entry in self.history[-max_count:]]
            else:
                # 返回ID大於since_id的條目
                return [entry.to_dict() for entry in self.history 
                       if entry.id > since_id][:max_count]
    
    def clear_history(self):
        """清空歷史記錄"""
        with self._history_lock:
            self.history.clear()
            self.log_counter = 0


# 全局logger實例
_logger_instance = Logger()


# 便捷函數（向後兼容）
def set_debug_level(level: int) -> bool:
    """設置調試級別"""
    return _logger_instance.set_debug_level(level)


def get_logger() -> Logger:
    """獲取logger實例"""
    return _logger_instance


# 導出便捷函數
critical = _logger_instance.critical
error = _logger_instance.error
success = _logger_instance.success
info = _logger_instance.info
data = _logger_instance.data
stomp_frame = _logger_instance.stomp_frame
usp_message = _logger_instance.usp_message
get_history = _logger_instance.get_history
clear_history = _logger_instance.clear_history
