#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Output Formatters
統一的輸出格式化器，支援多種格式和跨平台彩色輸出
"""

import json
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from enum import Enum


class OutputFormat(Enum):
    """輸出格式類型"""
    TEXT = "text"        # 純文字
    TABLE = "table"      # 表格
    JSON = "json"        # JSON 格式
    COLORED = "colored"  # 彩色文字
    RICH = "rich"        # Rich 庫（進階）


class ColorCode:
    """
    跨平台彩色代碼
    自動檢測終端支援度
    """
    
    # 檢測是否支援顏色
    _supports_color = (
        hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and
        sys.platform != 'win32'  # Windows 需要特殊處理
    )
    
    # Windows 10+ 支援 ANSI
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            _supports_color = True
        except:
            _supports_color = False
    
    # ANSI 顏色碼
    RESET = '\033[0m' if _supports_color else ''
    BOLD = '\033[1m' if _supports_color else ''
    
    # 前景色
    BLACK = '\033[30m' if _supports_color else ''
    RED = '\033[31m' if _supports_color else ''
    GREEN = '\033[32m' if _supports_color else ''
    YELLOW = '\033[33m' if _supports_color else ''
    BLUE = '\033[34m' if _supports_color else ''
    MAGENTA = '\033[35m' if _supports_color else ''
    CYAN = '\033[36m' if _supports_color else ''
    WHITE = '\033[37m' if _supports_color else ''
    
    # 背景色
    BG_RED = '\033[41m' if _supports_color else ''
    BG_GREEN = '\033[42m' if _supports_color else ''
    BG_YELLOW = '\033[43m' if _supports_color else ''
    BG_BLUE = '\033[44m' if _supports_color else ''
    
    @classmethod
    def supports_color(cls) -> bool:
        """檢查是否支援彩色輸出"""
        return cls._supports_color


class OutputFormatter(ABC):
    """輸出格式化器基類"""
    
    @abstractmethod
    def format_result(self, data: Any, **kwargs) -> str:
        """格式化結果數據"""
        pass
    
    @abstractmethod
    def format_error(self, error: str) -> str:
        """格式化錯誤訊息"""
        pass
    
    @abstractmethod
    def format_info(self, message: str) -> str:
        """格式化一般訊息"""
        pass


class TextFormatter(OutputFormatter):
    """純文字格式化器"""
    
    def format_result(self, data: Any, **kwargs) -> str:
        if isinstance(data, dict):
            return self._format_dict(data)
        elif isinstance(data, list):
            return self._format_list(data)
        else:
            return str(data)
    
    def _format_dict(self, data: dict, indent: int = 0) -> str:
        lines = []
        prefix = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.append(self._format_dict(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                lines.append(self._format_list(value, indent + 1))
            else:
                lines.append(f"{prefix}{key}: {value}")
        return "\n".join(lines)
    
    def _format_list(self, data: list, indent: int = 0) -> str:
        lines = []
        prefix = "  " * indent
        for i, item in enumerate(data):
            if isinstance(item, dict):
                lines.append(f"{prefix}[{i}]:")
                lines.append(self._format_dict(item, indent + 1))
            else:
                lines.append(f"{prefix}- {item}")
        return "\n".join(lines)
    
    def format_error(self, error: str) -> str:
        return f"[ERROR] {error}"
    
    def format_info(self, message: str) -> str:
        return f"[INFO] {message}"


class TableFormatter(OutputFormatter):
    """表格格式化器（ASCII 表格）"""
    
    def format_result(self, data: Any, headers: Optional[List[str]] = None, **kwargs) -> str:
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return self._format_table_from_dicts(data, headers)
        elif isinstance(data, dict):
            return self._format_table_from_dict(data)
        else:
            return str(data)
    
    def _format_table_from_dicts(self, data: List[dict], headers: Optional[List[str]] = None) -> str:
        """從字典列表創建表格"""
        if not data:
            return ""
        
        # 自動提取 headers
        if headers is None:
            headers = list(data[0].keys())
        
        # 計算列寬
        col_widths = {}
        for header in headers:
            col_widths[header] = len(header)
        
        for row in data:
            for header in headers:
                value = str(row.get(header, ""))
                col_widths[header] = max(col_widths[header], len(value))
        
        # 構建表格
        lines = []
        
        # 上邊框
        lines.append("┌" + "┬".join(["─" * (col_widths[h] + 2) for h in headers]) + "┐")
        
        # 標題行
        header_row = "│"
        for header in headers:
            header_row += f" {header:{col_widths[header]}} │"
        lines.append(header_row)
        
        # 標題分隔線
        lines.append("├" + "┼".join(["─" * (col_widths[h] + 2) for h in headers]) + "┤")
        
        # 數據行
        for row in data:
            data_row = "│"
            for header in headers:
                value = str(row.get(header, ""))
                data_row += f" {value:{col_widths[header]}} │"
            lines.append(data_row)
        
        # 下邊框
        lines.append("└" + "┴".join(["─" * (col_widths[h] + 2) for h in headers]) + "┘")
        
        return "\n".join(lines)
    
    def _format_table_from_dict(self, data: dict) -> str:
        """從單個字典創建表格"""
        if not data:
            return ""
        
        # 找到最大鍵長度
        max_key_len = max(len(str(k)) for k in data.keys())
        max_val_len = max(len(str(v)) for v in data.values())
        
        lines = []
        lines.append("┌" + "─" * (max_key_len + 2) + "┬" + "─" * (max_val_len + 2) + "┐")
        
        for key, value in data.items():
            lines.append(f"│ {str(key):{max_key_len}} │ {str(value):{max_val_len}} │")
        
        lines.append("└" + "─" * (max_key_len + 2) + "┴" + "─" * (max_val_len + 2) + "┘")
        
        return "\n".join(lines)
    
    def format_error(self, error: str) -> str:
        return f"┌─ ERROR ─────────────────\n│ {error}\n└─────────────────────────"
    
    def format_info(self, message: str) -> str:
        return f"ℹ {message}"


class JSONFormatter(OutputFormatter):
    """JSON 格式化器"""
    
    def __init__(self, indent: int = 2):
        self.indent = indent
    
    def format_result(self, data: Any, **kwargs) -> str:
        try:
            return json.dumps(data, indent=self.indent, ensure_ascii=False)
        except Exception as e:
            return f'{{"error": "Failed to serialize: {e}"}}'
    
    def format_error(self, error: str) -> str:
        return json.dumps({"status": "error", "message": error}, indent=self.indent)
    
    def format_info(self, message: str) -> str:
        return json.dumps({"status": "info", "message": message}, indent=self.indent)


class ColoredFormatter(OutputFormatter):
    """彩色文字格式化器（跨平台）"""
    
    def format_result(self, data: Any, **kwargs) -> str:
        if isinstance(data, dict):
            return self._format_dict_colored(data)
        elif isinstance(data, list):
            return self._format_list_colored(data)
        else:
            return f"{ColorCode.GREEN}{data}{ColorCode.RESET}"
    
    def _format_dict_colored(self, data: dict, indent: int = 0) -> str:
        lines = []
        prefix = "  " * indent
        for key, value in data.items():
            key_colored = f"{ColorCode.CYAN}{key}{ColorCode.RESET}"
            if isinstance(value, dict):
                lines.append(f"{prefix}{key_colored}:")
                lines.append(self._format_dict_colored(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key_colored}:")
                lines.append(self._format_list_colored(value, indent + 1))
            else:
                value_colored = f"{ColorCode.GREEN}{value}{ColorCode.RESET}"
                lines.append(f"{prefix}{key_colored}: {value_colored}")
        return "\n".join(lines)
    
    def _format_list_colored(self, data: list, indent: int = 0) -> str:
        lines = []
        prefix = "  " * indent
        for i, item in enumerate(data):
            bullet = f"{ColorCode.YELLOW}●{ColorCode.RESET}"
            if isinstance(item, dict):
                lines.append(f"{prefix}{bullet} [{i}]:")
                lines.append(self._format_dict_colored(item, indent + 1))
            else:
                value_colored = f"{ColorCode.GREEN}{item}{ColorCode.RESET}"
                lines.append(f"{prefix}{bullet} {value_colored}")
        return "\n".join(lines)
    
    def format_error(self, error: str) -> str:
        symbol = "✗" if ColorCode.supports_color() else "[ERROR]"
        return f"{ColorCode.RED}{ColorCode.BOLD}{symbol} {error}{ColorCode.RESET}"
    
    def format_info(self, message: str) -> str:
        symbol = "ℹ" if ColorCode.supports_color() else "[INFO]"
        return f"{ColorCode.BLUE}{symbol} {message}{ColorCode.RESET}"
    
    def format_success(self, message: str) -> str:
        symbol = "✓" if ColorCode.supports_color() else "[OK]"
        return f"{ColorCode.GREEN}{symbol} {message}{ColorCode.RESET}"
    
    def format_warning(self, message: str) -> str:
        symbol = "⚠" if ColorCode.supports_color() else "[WARN]"
        return f"{ColorCode.YELLOW}{symbol} {message}{ColorCode.RESET}"


# Rich 庫集成（可選，需要安裝 rich）
try:
    from rich.console import Console
    from rich.table import Table as RichTable
    from rich.panel import Panel
    from rich.syntax import Syntax
    
    class RichFormatter(OutputFormatter):
        """Rich 庫進階格式化器"""
        
        def __init__(self):
            self.console = Console()
        
        def format_result(self, data: Any, **kwargs) -> str:
            # Rich 直接打印，不返回字符串
            if isinstance(data, list) and data and isinstance(data[0], dict):
                table = RichTable(show_header=True, header_style="bold magenta")
                
                headers = list(data[0].keys())
                for header in headers:
                    table.add_column(header)
                
                for row in data:
                    table.add_row(*[str(row.get(h, "")) for h in headers])
                
                self.console.print(table)
            else:
                self.console.print(data)
            
            return ""  # Rich 已經打印
        
        def format_error(self, error: str) -> str:
            panel = Panel(error, title="Error", border_style="red")
            self.console.print(panel)
            return ""
        
        def format_info(self, message: str) -> str:
            self.console.print(f"[blue]ℹ[/blue] {message}")
            return ""

except ImportError:
    # Rich 未安裝，跳過
    RichFormatter = None


def get_formatter(format_type: OutputFormat = OutputFormat.COLORED) -> OutputFormatter:
    """
    獲取格式化器實例
    
    參數:
        format_type: 格式類型
    
    返回:
        OutputFormatter 實例
    """
    formatters = {
        OutputFormat.TEXT: TextFormatter,
        OutputFormat.TABLE: TableFormatter,
        OutputFormat.JSON: JSONFormatter,
        OutputFormat.COLORED: ColoredFormatter,
    }
    
    if format_type == OutputFormat.RICH:
        if RichFormatter is None:
            print("[!] Rich library not installed, falling back to ColoredFormatter")
            return ColoredFormatter()
        return RichFormatter()
    
    formatter_class = formatters.get(format_type, TextFormatter)
    return formatter_class()
