#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI Interface Implementation
跨平台命令行介面實現（Windows/Linux/macOS）
"""

import sys
import platform
from typing import Optional
from .base import InterfaceBase, InterfaceType, CommandContext, CommandResult
from .formatter import OutputFormatter, ColoredFormatter, get_formatter, OutputFormat
from .command_handler import CommandHandler


class CLIInterface(InterfaceBase):
    """
    CLI 介面實現
    
    特性：
    - 跨平台支援（Windows/Linux/macOS）
    - 彩色輸出（自動檢測終端支援）
    - 命令歷史
    - 簡潔的輸入提示
    """
    
    def __init__(
        self,
        prompt: str = "usp> ",
        formatter: Optional[OutputFormatter] = None,
        command_handler: Optional[CommandHandler] = None
    ):
        super().__init__(InterfaceType.CLI)
        
        self._prompt = prompt
        self._running = False
        self._formatter = formatter or ColoredFormatter()
        self._command_handler = command_handler or CommandHandler()
        
        # 平台檢測
        self._platform = platform.system()
        self._is_windows = self._platform == "Windows"
        
        # 嘗試啟用 Windows ANSI 支援
        if self._is_windows:
            self._enable_windows_ansi()
    
    def _enable_windows_ansi(self):
        """啟用 Windows 10+ ANSI 顏色支援"""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # 啟用虛擬終端處理
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass  # 失敗則使用普通輸出
    
    def initialize(self) -> bool:
        """初始化 CLI 介面"""
        try:
            # 顯示歡迎訊息
            self._display_banner()
            return True
        except Exception as e:
            print(f"Failed to initialize CLI: {e}")
            return False
    
    def _display_banner(self):
        """顯示歡迎橫幅"""
        banner = f"""
{self._formatter.format_success("="*60)}
  USP Controller - Interactive CLI
  Platform: {self._platform}
  Type 'help' for available commands, 'quit' to exit
{self._formatter.format_success("="*60)}
"""
        print(banner)
    
    def run(self):
        """啟動 CLI 主循環"""
        self._running = True
        
        while self._running:
            try:
                # 獲取使用者輸入
                user_input = self.prompt_input(self._prompt)
                
                if not user_input.strip():
                    continue
                
                # 解析命令
                context = self._command_handler.parse_command(user_input)
                
                # 觸發回調
                self._emit('on_command', context)
                
                # 執行命令
                result = self._command_handler.execute(context)
                
                # 顯示結果
                self.display_output(result)
                
                # 觸發回調
                self._emit('on_result', result)
                
                # 檢查是否退出
                if result.metadata.get('action') == 'quit':
                    self._running = False
                
            except KeyboardInterrupt:
                # Ctrl+C 處理
                print(f"\n{self._formatter.format_info('Use quit or exit to leave')}")
                continue
            except EOFError:
                # Ctrl+D (Unix) 或 Ctrl+Z (Windows)
                print("\n" + self._formatter.format_info("Goodbye!"))
                break
            except Exception as e:
                self.display_error(f"Unexpected error: {e}")
    
    def shutdown(self):
        """關閉 CLI 介面"""
        self._running = False
        print(self._formatter.format_info("CLI shutdown complete"))
    
    def display_output(self, result: CommandResult):
        """顯示命令執行結果"""
        if not result.success:
            self.display_error(result.error or "Command failed")
            return
        
        # 顯示訊息
        if result.message:
            print(result.message)
        
        # 顯示數據
        if result.data is not None:
            formatted = self._formatter.format_result(result.data)
            if formatted:  # Rich formatter 可能返回空字符串
                print(formatted)
    
    def display_error(self, error: str):
        """顯示錯誤訊息"""
        print(self._formatter.format_error(error))
    
    def display_info(self, message: str):
        """顯示一般訊息"""
        print(self._formatter.format_info(message))
    
    def prompt_input(self, prompt: str = "") -> str:
        """獲取使用者輸入"""
        try:
            return input(prompt)
        except EOFError:
            raise
        except KeyboardInterrupt:
            raise
    
    def confirm_action(self, message: str) -> bool:
        """請求使用者確認"""
        try:
            response = input(f"{message} (y/n): ").strip().lower()
            return response in ['y', 'yes']
        except (EOFError, KeyboardInterrupt):
            return False
    
    def set_prompt(self, prompt: str):
        """設置命令提示符"""
        self._prompt = prompt
    
    def set_formatter(self, formatter: OutputFormatter):
        """設置格式化器"""
        self._formatter = formatter


# 進階 CLI 實現（使用 prompt_toolkit）
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.styles import Style
    
    class EnhancedCLIInterface(CLIInterface):
        """
        增強型 CLI 介面
        
        需要安裝: pip install prompt_toolkit
        
        特性：
        - 命令自動補全（Tab 鍵）
        - 命令歷史（上下鍵）
        - 語法高亮
        - Ctrl+R 反向搜索
        """
        
        def __init__(
            self,
            prompt: str = "usp> ",
            formatter: Optional[OutputFormatter] = None,
            command_handler: Optional[CommandHandler] = None
        ):
            super().__init__(prompt, formatter, command_handler)
            
            # 創建 prompt_toolkit session
            self._history = InMemoryHistory()
            self._session = None
            
            # 樣式定義
            self._style = Style.from_dict({
                'prompt': 'ansigreen bold',
            })
        
        def initialize(self) -> bool:
            """初始化增強 CLI"""
            if not super().initialize():
                return False
            
            try:
                # 獲取命令列表用於自動補全
                command_names = self._command_handler.get_command_names()
                completer = WordCompleter(command_names, ignore_case=True)
                
                # 創建 session
                self._session = PromptSession(
                    message=self._prompt,
                    completer=completer,
                    history=self._history,
                    style=self._style
                )
                
                self.display_info("Enhanced CLI mode enabled (Tab for completion, ↑↓ for history)")
                return True
            
            except Exception as e:
                print(f"[!] Failed to initialize enhanced CLI: {e}")
                print("[!] Falling back to basic CLI")
                return True  # 降級到基本模式
        
        def prompt_input(self, prompt: str = "") -> str:
            """獲取使用者輸入（增強版）"""
            if self._session:
                try:
                    return self._session.prompt()
                except:
                    # 降級到基本輸入
                    return input(prompt)
            else:
                return input(prompt)

except ImportError:
    # prompt_toolkit 未安裝
    EnhancedCLIInterface = None


def create_cli_interface(
    enhanced: bool = True,
    prompt: str = "usp> ",
    output_format: OutputFormat = OutputFormat.COLORED
) -> CLIInterface:
    """
    創建 CLI 介面實例
    
    參數:
        enhanced: 是否使用增強模式（需要 prompt_toolkit）
        prompt: 命令提示符
        output_format: 輸出格式
    
    返回:
        CLIInterface 實例
    """
    formatter = get_formatter(output_format)
    command_handler = CommandHandler()
    
    # 嘗試創建增強版
    if enhanced and EnhancedCLIInterface is not None:
        try:
            return EnhancedCLIInterface(prompt, formatter, command_handler)
        except:
            pass
    
    # 降級到基本版
    return CLIInterface(prompt, formatter, command_handler)
