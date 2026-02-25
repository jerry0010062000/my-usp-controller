#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Handler
統一的命令處理器，解析和執行命令
"""

import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from .base import CommandContext, CommandResult


class CommandHandler:
    """
    統一命令處理器
    
    負責：
    1. 命令解析（parsing）
    2. 參數驗證（validation）
    3. 命令路由（routing）
    4. 結果封裝（result wrapping）
    """
    
    def __init__(self):
        self._commands: Dict[str, Dict[str, Any]] = {}
        self._aliases: Dict[str, str] = {}
        self._controller = None  # USP Controller 實例
        
        # 註冊內置命令
        self._register_builtin_commands()
    
    def set_controller(self, controller):
        """設置 USP Controller 實例"""
        self._controller = controller
    
    def register_command(
        self,
        name: str,
        handler: Callable,
        aliases: Optional[List[str]] = None,
        description: str = "",
        usage: str = "",
        min_args: int = 0,
        max_args: Optional[int] = None
    ):
        """
        註冊命令
        
        參數:
            name: 命令名稱
            handler: 處理函數 (context: CommandContext) -> CommandResult
            aliases: 命令別名列表
            description: 命令描述
            usage: 使用說明
            min_args: 最少參數數量
            max_args: 最多參數數量（None 表示無限制）
        """
        self._commands[name] = {
            'handler': handler,
            'description': description,
            'usage': usage,
            'min_args': min_args,
            'max_args': max_args
        }
        
        # 註冊別名
        if aliases:
            for alias in aliases:
                self._aliases[alias] = name
    
    def parse_command(self, input_str: str) -> CommandContext:
        """
        解析命令字符串
        
        支持格式:
        - 簡單命令: help
        - 帶參數: get agent-001 Device.DeviceInfo.
        - 帶選項: set agent-001 path=Device.X value=123
        - 帶引號: set agent-001 "Device.X.Name" "My Device"
        
        返回:
            CommandContext 對象
        """
        input_str = input_str.strip()
        
        # 解析命令和參數（支持引號）
        tokens = self._tokenize(input_str)
        
        if not tokens:
            return CommandContext(command="", raw_input=input_str)
        
        command = tokens[0].lower()
        args = []
        kwargs = {}
        
        # 處理別名
        if command in self._aliases:
            command = self._aliases[command]
        
        # 解析參數
        for token in tokens[1:]:
            if '=' in token:
                # 關鍵字參數
                key, value = token.split('=', 1)
                kwargs[key] = value
            else:
                # 位置參數
                args.append(token)
        
        return CommandContext(
            command=command,
            args=args,
            kwargs=kwargs,
            raw_input=input_str
        )
    
    def _tokenize(self, input_str: str) -> List[str]:
        """
        分詞，支持引號
        
        示例:
            'get agent "Device.X" value'
            -> ['get', 'agent', 'Device.X', 'value']
        """
        # 使用正則表達式處理引號
        pattern = r'''((?:[^\s"']|"[^"]*"|'[^']*')+)'''
        tokens = re.findall(pattern, input_str)
        
        # 移除引號
        result = []
        for token in tokens:
            if (token.startswith('"') and token.endswith('"')) or \
               (token.startswith("'") and token.endswith("'")):
                token = token[1:-1]
            result.append(token)
        
        return result
    
    def execute(self, context: CommandContext) -> CommandResult:
        """
        執行命令
        
        參數:
            context: 命令上下文
        
        返回:
            CommandResult 對象
        """
        command = context.command
        
        # 檢查命令是否存在
        if command not in self._commands:
            return CommandResult(
                success=False,
                error=f"Unknown command: {command}. Type 'help' for available commands."
            )
        
        cmd_info = self._commands[command]
        handler = cmd_info['handler']
        
        # 驗證參數數量
        arg_count = len(context.args)
        min_args = cmd_info['min_args']
        max_args = cmd_info['max_args']
        
        if arg_count < min_args:
            return CommandResult(
                success=False,
                error=f"Too few arguments. Usage: {cmd_info['usage']}"
            )
        
        if max_args is not None and arg_count > max_args:
            return CommandResult(
                success=False,
                error=f"Too many arguments. Usage: {cmd_info['usage']}"
            )
        
        # 執行命令
        try:
            result = handler(context)
            return result
        except Exception as e:
            return CommandResult(
                success=False,
                error=f"Command execution failed: {e}"
            )
    
    def _register_builtin_commands(self):
        """註冊內置命令"""
        
        # help 命令
        self.register_command(
            name='help',
            handler=self._cmd_help,
            aliases=['h', '?'],
            description='Show available commands',
            usage='help [command]'
        )
        
        # list 命令
        self.register_command(
            name='list',
            handler=self._cmd_list,
            aliases=['ls', 'devices'],
            description='List known devices',
            usage='list'
        )
        
        # status 命令
        self.register_command(
            name='status',
            handler=self._cmd_status,
            aliases=['stat', 'info'],
            description='Show connection status',
            usage='status'
        )
        
        # quit 命令
        self.register_command(
            name='quit',
            handler=self._cmd_quit,
            aliases=['exit', 'q'],
            description='Exit program',
            usage='quit'
        )
        
        # clear 命令
        self.register_command(
            name='clear',
            handler=self._cmd_clear,
            aliases=['cls'],
            description='Clear screen',
            usage='clear'
        )
        
        # debug 命令
        self.register_command(
            name='debug',
            handler=self._cmd_debug,
            description='Show/set debug level',
            usage='debug [0-2]',
            max_args=1
        )
    
    # ==================== 內置命令處理函數 ====================
    
    def _cmd_help(self, context: CommandContext) -> CommandResult:
        """help 命令處理"""
        if context.args:
            # 顯示特定命令的幫助
            cmd_name = context.args[0]
            if cmd_name in self._commands:
                cmd_info = self._commands[cmd_name]
                help_text = f"\nCommand: {cmd_name}\n"
                help_text += f"Description: {cmd_info['description']}\n"
                help_text += f"Usage: {cmd_info['usage']}\n"
                
                # 顯示別名
                aliases = [k for k, v in self._aliases.items() if v == cmd_name]
                if aliases:
                    help_text += f"Aliases: {', '.join(aliases)}\n"
                
                return CommandResult(success=True, message=help_text)
            else:
                return CommandResult(
                    success=False,
                    error=f"Unknown command: {cmd_name}"
                )
        
        # 顯示所有命令
        help_text = "\n" + "="*60 + "\n"
        help_text += "USP Controller - Available Commands\n"
        help_text += "="*60 + "\n\n"
        
        # 分組顯示
        groups = {
            "Basic": ['help', 'list', 'status', 'clear', 'debug', 'quit'],
            "USP Operations": ['get', 'set', 'add', 'delete', 'discover', 'operate'],
        }
        
        for group_name, cmd_names in groups.items():
            help_text += f"{group_name}:\n"
            for cmd_name in cmd_names:
                if cmd_name in self._commands:
                    cmd_info = self._commands[cmd_name]
                    aliases = [k for k, v in self._aliases.items() if v == cmd_name]
                    alias_str = f" ({', '.join(aliases)})" if aliases else ""
                    help_text += f"  {cmd_name}{alias_str:<20} - {cmd_info['description']}\n"
            help_text += "\n"
        
        help_text += "Type 'help <command>' for detailed usage.\n"
        help_text += "="*60 + "\n"
        
        return CommandResult(success=True, message=help_text)
    
    def _cmd_list(self, context: CommandContext) -> CommandResult:
        """list 命令處理"""
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        
        # 獲取設備列表
        devices = getattr(self._controller, 'devices', {})
        
        if not devices:
            return CommandResult(
                success=True,
                message="No devices registered yet."
            )
        
        # 構建設備列表
        device_list = []
        for endpoint_id, info in devices.items():
            device_list.append({
                'Endpoint': endpoint_id,
                'Reply-To': info.get('reply_to', 'N/A'),
                'Last Seen': info.get('last_seen', 'N/A')
            })
        
        return CommandResult(
            success=True,
            message=f"Known Devices ({len(devices)})",
            data=device_list
        )
    
    def _cmd_status(self, context: CommandContext) -> CommandResult:
        """status 命令處理"""
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        
        # 獲取狀態信息
        status_info = {
            'Controller ID': getattr(self._controller, 'config', None).controller_endpoint_id if hasattr(self._controller, 'config') else 'N/A',
            'Transport': getattr(self._controller, 'transport', None).__class__.__name__ if hasattr(self._controller, 'transport') else 'N/A',
            'Connected': str(getattr(getattr(self._controller, 'transport', None), 'is_connected', lambda: False)()),
            'Known Devices': str(len(getattr(self._controller, 'devices', {})))
        }
        
        return CommandResult(
            success=True,
            message="Controller Status",
            data=status_info
        )
    
    def _cmd_quit(self, context: CommandContext) -> CommandResult:
        """quit 命令處理"""
        return CommandResult(
            success=True,
            message="Goodbye!",
            metadata={'action': 'quit'}
        )
    
    def _cmd_clear(self, context: CommandContext) -> CommandResult:
        """clear 命令處理"""
        import os
        import platform
        
        # 跨平台清屏
        if platform.system() == "Windows":
            os.system('cls')
        else:
            os.system('clear')
        
        return CommandResult(success=True, message="")
    
    def _cmd_debug(self, context: CommandContext) -> CommandResult:
        """debug 命令處理"""
        from ..logger import get_logger, set_debug_level, get_debug_level
        
        if not context.args:
            # 顯示當前調試級別
            level = get_debug_level()
            level_names = ["Agent Only", "Both Payloads", "Full Details"]
            message = f"Current debug level: {level} ({level_names[level]})\n"
            message += "Usage: debug <0|1|2>\n"
            message += "  0 - Agent Only: Only agent response data\n"
            message += "  1 - Both Payloads: Controller + Agent USP messages\n"
            message += "  2 - Full Details: STOMP headers + payloads"
            
            return CommandResult(success=True, message=message)
        
        # 設置調試級別
        try:
            new_level = int(context.args[0])
            if 0 <= new_level <= 2:
                set_debug_level(new_level)
                level_names = ["Agent Only", "Both Payloads", "Full Details"]
                return CommandResult(
                    success=True,
                    message=f"Debug level set to {new_level} ({level_names[new_level]})"
                )
            else:
                return CommandResult(
                    success=False,
                    error="Debug level must be 0-2"
                )
        except ValueError:
            return CommandResult(
                success=False,
                error="Invalid debug level. Use 0, 1, or 2"
            )
    
    def get_command_names(self) -> List[str]:
        """獲取所有命令名稱（用於自動補全）"""
        return list(self._commands.keys()) + list(self._aliases.keys())
