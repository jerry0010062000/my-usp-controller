#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試統一介面層
快速驗證新的 Interface Layer 是否正常工作
"""

import sys
from pathlib import Path

# 添加模組路徑（專案根目錄）
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """測試模組導入"""
    print("Testing imports...")
    try:
        from usp_controller.interface import (
            InterfaceType,
            InterfaceBase,
            InterfaceFactory,
            CommandContext,
            CommandResult,
            OutputFormatter,
            OutputFormat,
            CommandHandler,
            CLIInterface,
            create_cli_interface
        )
        print("✓ All imports successful")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False


def test_command_parsing():
    """測試命令解析"""
    print("\nTesting command parsing...")
    try:
        from usp_controller.interface import CommandHandler
        
        handler = CommandHandler()
        
        # 測試簡單命令
        ctx = handler.parse_command("help")
        assert ctx.command == "help"
        assert len(ctx.args) == 0
        
        # 測試帶參數命令
        ctx = handler.parse_command("get agent-001 Device.DeviceInfo.")
        assert ctx.command == "get"
        assert len(ctx.args) == 2
        assert ctx.endpoint == "agent-001"
        assert ctx.path == "Device.DeviceInfo."
        
        # 測試帶引號的命令
        ctx = handler.parse_command('set agent "Device.X" "value with spaces"')
        assert ctx.command == "set"
        assert ctx.args[1] == "Device.X"
        assert ctx.args[2] == "value with spaces"
        
        print("✓ Command parsing works correctly")
        return True
    except Exception as e:
        print(f"✗ Command parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_formatters():
    """測試輸出格式化器"""
    print("\nTesting formatters...")
    try:
        from usp_controller.interface import get_formatter, OutputFormat
        
        test_data = [
            {'name': 'Alice', 'age': 30},
            {'name': 'Bob', 'age': 25}
        ]
        
        # 測試各種格式
        formats = [OutputFormat.TEXT, OutputFormat.TABLE, OutputFormat.JSON, OutputFormat.COLORED]
        
        for fmt in formats:
            formatter = get_formatter(fmt)
            output = formatter.format_result(test_data)
            assert output is not None
            print(f"  ✓ {fmt.value} formatter works")
        
        print("✓ All formatters work correctly")
        return True
    except Exception as e:
        print(f"✗ Formatter test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_command_execution():
    """測試命令執行"""
    print("\nTesting command execution...")
    try:
        from usp_controller.interface import CommandHandler, CommandResult
        
        handler = CommandHandler()
        
        # 測試內置命令
        builtin_commands = ['help', 'list', 'status', 'debug']
        
        for cmd_name in builtin_commands:
            ctx = handler.parse_command(cmd_name)
            result = handler.execute(ctx)
            assert isinstance(result, CommandResult)
            print(f"  ✓ {cmd_name} command executed")
        
        print("✓ Command execution works correctly")
        return True
    except Exception as e:
        print(f"✗ Command execution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli_interface():
    """測試 CLI 介面"""
    print("\nTesting CLI interface...")
    try:
        from usp_controller.interface import create_cli_interface, OutputFormat
        
        # 創建 CLI
        cli = create_cli_interface(
            enhanced=False,
            prompt="test> ",
            output_format=OutputFormat.COLORED
        )
        
        # 初始化
        assert cli.initialize() == True
        print("  ✓ CLI initialization successful")
        
        # 測試命令執行
        test_commands = ["help", "status", "list"]
        for cmd in test_commands:
            ctx = cli._command_handler.parse_command(cmd)
            result = cli._command_handler.execute(ctx)
            assert result is not None
            print(f"  ✓ CLI executed '{cmd}' command")
        
        print("✓ CLI interface works correctly")
        return True
    except Exception as e:
        print(f"✗ CLI interface test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_factory_pattern():
    """測試工廠模式"""
    print("\nTesting factory pattern...")
    try:
        from usp_controller.interface import InterfaceFactory, InterfaceType
        
        # 列出可用介面
        available = InterfaceFactory.list_available()
        assert InterfaceType.CLI in available
        print(f"  ✓ Available interfaces: {[t.value for t in available]}")
        
        # 創建 CLI 介面
        cli = InterfaceFactory.create(InterfaceType.CLI, prompt="test> ")
        assert cli is not None
        assert cli.interface_type == InterfaceType.CLI
        print("  ✓ Factory created CLI interface")
        
        print("✓ Factory pattern works correctly")
        return True
    except Exception as e:
        print(f"✗ Factory pattern test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_custom_command():
    """測試自定義命令註冊"""
    print("\nTesting custom command registration...")
    try:
        from usp_controller.interface import CommandHandler, CommandContext, CommandResult
        
        handler = CommandHandler()
        
        # 定義自定義命令
        def custom_cmd(context: CommandContext) -> CommandResult:
            return CommandResult(
                success=True,
                message="Custom command executed",
                data={'test': 'success'}
            )
        
        # 註冊
        handler.register_command(
            name='custom',
            handler=custom_cmd,
            aliases=['c'],
            description='Test custom command',
            usage='custom',
            min_args=0,
            max_args=0
        )
        
        # 執行
        ctx = handler.parse_command("custom")
        result = handler.execute(ctx)
        assert result.success == True
        assert result.data['test'] == 'success'
        
        # 測試別名
        ctx = handler.parse_command("c")
        result = handler.execute(ctx)
        assert result.success == True
        
        print("✓ Custom command registration works correctly")
        return True
    except Exception as e:
        print(f"✗ Custom command test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_color_support():
    """測試跨平台彩色支援"""
    print("\nTesting cross-platform color support...")
    try:
        from usp_controller.interface.formatter import ColorCode
        
        supports_color = ColorCode.supports_color()
        print(f"  ℹ Color support detected: {supports_color}")
        
        # 測試顏色輸出
        test_text = f"{ColorCode.GREEN}Success{ColorCode.RESET}"
        print(f"  ✓ Color output test: {test_text}")
        
        print("✓ Color support works correctly")
        return True
    except Exception as e:
        print(f"✗ Color support test failed: {e}")
        return False


def main():
    """運行所有測試"""
    print("="*60)
    print("統一介面層測試")
    print("="*60)
    
    tests = [
        ("Imports", test_imports),
        ("Command Parsing", test_command_parsing),
        ("Formatters", test_formatters),
        ("Command Execution", test_command_execution),
        ("CLI Interface", test_cli_interface),
        ("Factory Pattern", test_factory_pattern),
        ("Custom Command", test_custom_command),
        ("Color Support", test_color_support),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success))
        except Exception as e:
            print(f"\n✗ Unexpected error in {name}: {e}")
            results.append((name, False))
    
    # 總結
    print("\n" + "="*60)
    print("測試總結")
    print("="*60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} | {name}")
    
    print("="*60)
    print(f"結果: {passed}/{total} 測試通過")
    
    if passed == total:
        print("✓ 所有測試通過！")
        return 0
    else:
        print("✗ 部分測試失敗")
        return 1


if __name__ == "__main__":
    sys.exit(main())
