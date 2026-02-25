#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller - Interface Layer
統一的使用者介面抽象層，支援多平台（CLI/GUI/Web）

設計理念：
- 類似 Transport 層的抽象設計
- 統一命令處理邏輯
- 跨平台一致體驗
- 可擴展到未來的 Web/Mobile 介面
"""

from .base import (
    InterfaceType,
    InterfaceBase,
    InterfaceFactory,
    CommandContext,
    CommandResult
)
from .formatter import (
    OutputFormatter,
    OutputFormat,
    TableFormatter,
    JSONFormatter, 
    ColoredFormatter,
    get_formatter
)
from .command_handler import CommandHandler
from .cli import CLIInterface, create_cli_interface
from .gui_adapter import GUIAdapterBase, TkinterGUIAdapter

# 註冊 CLI 到工廠
InterfaceFactory.register(InterfaceType.CLI, CLIInterface)

__all__ = [
    'InterfaceType',
    'InterfaceBase',
    'InterfaceFactory',
    'CommandContext',
    'CommandResult',
    'OutputFormatter',
    'OutputFormat',
    'TableFormatter',
    'JSONFormatter',
    'ColoredFormatter',
    'get_formatter',
    'CommandHandler',
    'CLIInterface',
    'create_cli_interface',
    'GUIAdapterBase',
    'TkinterGUIAdapter'
]
