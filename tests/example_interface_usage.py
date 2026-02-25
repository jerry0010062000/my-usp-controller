#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
統一介面層使用示例

展示如何使用新的 Interface 層創建跨平台的 USP Controller 介面
"""

import sys
from pathlib import Path

# 添加模組路徑（專案根目錄）
sys.path.insert(0, str(Path(__file__).parent.parent))

from usp_controller.interface import (
    InterfaceFactory,
    InterfaceType,
    CommandHandler,
    CommandContext,
    CommandResult,
    OutputFormat,
    create_cli_interface
)


# ==================== 示例 1: 基本 CLI 介面 ====================

def example_basic_cli():
    """示例：使用基本 CLI 介面"""
    print("\n=== Example 1: Basic CLI Interface ===\n")
    
    # 創建 CLI 介面（基本模式，彩色輸出）
    cli = create_cli_interface(
        enhanced=False,
        prompt="usp> ",
        output_format=OutputFormat.COLORED
    )
    
    # 初始化
    if cli.initialize():
        print("CLI initialized successfully")
        
        # 模擬命令執行
        test_commands = [
            "help",
            "status",
            "list"
        ]
        
        for cmd in test_commands:
            print(f"\n執行命令: {cmd}")
            context = cli._command_handler.parse_command(cmd)
            result = cli._command_handler.execute(context)
            cli.display_output(result)
    
    # 如果要啟動互動模式，可以調用：
    # cli.run()


# ==================== 示例 2: 增強 CLI 介面 ====================

def example_enhanced_cli():
    """示例：使用增強 CLI 介面（需要 prompt_toolkit）"""
    print("\n=== Example 2: Enhanced CLI Interface ===\n")
    
    # 創建增強 CLI（自動補全、歷史記錄）
    cli = create_cli_interface(
        enhanced=True,  # 嘗試使用增強模式
        prompt="usp> ",
        output_format=OutputFormat.COLORED
    )
    
    if cli.initialize():
        print("Enhanced CLI ready (Tab for completion, ↑↓ for history)")
        # cli.run()  # 啟動互動模式


# ==================== 示例 3: 自定義命令處理 ====================

def example_custom_commands():
    """示例：註冊自定義命令"""
    print("\n=== Example 3: Custom Command Registration ===\n")
    
    # 創建命令處理器
    handler = CommandHandler()
    
    # 定義自定義命令處理函數
    def cmd_hello(context: CommandContext) -> CommandResult:
        name = context.args[0] if context.args else "World"
        return CommandResult(
            success=True,
            message=f"Hello, {name}!"
        )
    
    def cmd_calc(context: CommandContext) -> CommandResult:
        try:
            expr = " ".join(context.args)
            result = eval(expr)  # 注意：實際應用中不要這樣做！
            return CommandResult(
                success=True,
                message=f"{expr} = {result}"
            )
        except Exception as e:
            return CommandResult(
                success=False,
                error=f"Calculation error: {e}"
            )
    
    # 註冊自定義命令
    handler.register_command(
        name='hello',
        handler=cmd_hello,
        aliases=['hi', 'greet'],
        description='Say hello',
        usage='hello [name]',
        max_args=1
    )
    
    handler.register_command(
        name='calc',
        handler=cmd_calc,
        description='Simple calculator',
        usage='calc <expression>',
        min_args=1
    )
    
    # 創建 CLI 並設置自定義處理器
    cli = create_cli_interface()
    cli._command_handler = handler
    
    if cli.initialize():
        # 測試自定義命令
        test_commands = [
            "hello Alice",
            "calc 2 + 3 * 4",
            "help"
        ]
        
        for cmd in test_commands:
            print(f"\n執行: {cmd}")
            context = handler.parse_command(cmd)
            result = handler.execute(context)
            cli.display_output(result)


# ==================== 示例 4: 不同輸出格式 ====================

def example_output_formats():
    """示例：使用不同的輸出格式"""
    print("\n=== Example 4: Different Output Formats ===\n")
    
    # 測試數據
    test_data = {
        'devices': [
            {'endpoint': 'agent-001', 'status': 'online', 'type': 'CPE'},
            {'endpoint': 'agent-002', 'status': 'offline', 'type': 'CPE'},
            {'endpoint': 'agent-003', 'status': 'online', 'type': 'ACS'},
        ]
    }
    
    formats = [
        OutputFormat.TEXT,
        OutputFormat.TABLE,
        OutputFormat.JSON,
        OutputFormat.COLORED
    ]
    
    for fmt in formats:
        print(f"\n--- Format: {fmt.value} ---")
        cli = create_cli_interface(output_format=fmt)
        cli.initialize()
        
        result = CommandResult(
            success=True,
            message=f"Device List ({fmt.value} format)",
            data=test_data['devices']
        )
        cli.display_output(result)


# ==================== 示例 5: 工廠模式創建介面 ====================

def example_factory_pattern():
    """示例：使用工廠模式創建不同介面"""
    print("\n=== Example 5: Factory Pattern ===\n")
    
    # 列出可用的介面類型
    available = InterfaceFactory.list_available()
    print(f"Available interfaces: {[t.value for t in available]}")
    
    # 使用工廠創建 CLI 介面
    cli = InterfaceFactory.create(InterfaceType.CLI, prompt="usp> ")
    
    if cli.initialize():
        print(f"Created interface: {cli.interface_type.value}")
        
        # 測試命令
        context = cli._command_handler.parse_command("status")
        result = cli._command_handler.execute(context)
        cli.display_output(result)


# ==================== 示例 6: USP 命令註冊 ====================

def example_usp_commands():
    """示例：註冊 USP 特定命令"""
    print("\n=== Example 6: USP Command Registration ===\n")
    
    handler = CommandHandler()
    
    # 定義 USP GET 命令
    def cmd_get(context: CommandContext) -> CommandResult:
        if len(context.args) < 2:
            return CommandResult(
                success=False,
                error="Usage: get <endpoint> <path>"
            )
        
        endpoint = context.args[0]
        path = context.args[1]
        
        # 這裡應該調用實際的 USP Controller
        # controller.send_get(endpoint, path)
        
        return CommandResult(
            success=True,
            message=f"GET {path} from {endpoint}",
            data={
                'endpoint': endpoint,
                'path': path,
                'status': 'sent'
            }
        )
    
    # 註冊 USP 命令
    handler.register_command(
        name='get',
        handler=cmd_get,
        description='Get USP parameter value',
        usage='get <endpoint> <path>',
        min_args=2,
        max_args=2
    )
    
    # 類似地註冊其他 USP 命令
    usp_commands = ['set', 'add', 'delete', 'discover', 'operate']
    for cmd_name in usp_commands:
        handler.register_command(
            name=cmd_name,
            handler=lambda ctx: CommandResult(
                success=True,
                message=f"{cmd_name.upper()} command (placeholder)"
            ),
            description=f'USP {cmd_name.upper()} operation',
            usage=f'{cmd_name} <args...>'
        )
    
    # 測試
    cli = create_cli_interface()
    cli._command_handler = handler
    cli.initialize()
    
    test_commands = [
        "get agent-001 Device.DeviceInfo.",
        "set agent-001 Device.X.Value 123",
        "help get"
    ]
    
    for cmd in test_commands:
        print(f"\n執行: {cmd}")
        context = handler.parse_command(cmd)
        result = handler.execute(context)
        cli.display_output(result)


# ==================== 主函數 ====================

def main():
    """運行所有示例"""
    examples = [
        ("Basic CLI", example_basic_cli),
        ("Enhanced CLI", example_enhanced_cli),
        ("Custom Commands", example_custom_commands),
        ("Output Formats", example_output_formats),
        ("Factory Pattern", example_factory_pattern),
        ("USP Commands", example_usp_commands),
    ]
    
    print("="*60)
    print("統一介面層使用示例")
    print("="*60)
    
    for i, (name, func) in enumerate(examples, 1):
        print(f"\n[{i}] {name}")
    
    print("\n選擇要運行的示例 (1-{}, 0=全部運行): ".format(len(examples)), end="")
    
    try:
        choice = input().strip()
        
        if choice == '0':
            for name, func in examples:
                try:
                    func()
                    input("\n按 Enter 繼續...")
                except Exception as e:
                    print(f"Error in {name}: {e}")
        else:
            idx = int(choice) - 1
            if 0 <= idx < len(examples):
                examples[idx][1]()
            else:
                print("無效選擇")
    
    except (KeyboardInterrupt, EOFError):
        print("\n\nGoodbye!")
    except Exception as e:
        print(f"\nError: {e}")


if __name__ == "__main__":
    main()
