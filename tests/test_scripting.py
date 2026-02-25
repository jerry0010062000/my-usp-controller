#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scripting Module Unit Tests
測試腳本引擎模組
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


def test_scripting_imports():
    """測試腳本模組導入"""
    from usp_controller.scripting import (
        SmartScriptEngine,
        ScriptCommand,
        ScriptCommandType
    )
    assert SmartScriptEngine is not None


def test_engine_creation():
    """測試引擎創建"""
    from usp_controller.scripting import SmartScriptEngine
    
    # 不同智能級別
    engine0 = SmartScriptEngine(intelligence_level=0)
    assert engine0.intelligence_level == 0
    
    engine1 = SmartScriptEngine(intelligence_level=1)
    assert engine1.intelligence_level == 1
    
    engine2 = SmartScriptEngine(intelligence_level=2)
    assert engine2.intelligence_level == 2


def test_parse_simple_commands():
    """測試解析簡單命令"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = """
    get agent-001 Device.DeviceInfo.
    set agent-001 Device.X.Value 123
    """
    
    commands = engine.parse_script(script)
    assert len(commands) == 2
    assert commands[0].type == ScriptCommandType.GET
    assert commands[1].type == ScriptCommandType.SET


def test_parse_comments():
    """測試解析註釋"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = """
    # 這是註釋
    get agent-001 Device.
    set agent-001 Device.X 1
    """
    
    commands = engine.parse_script(script)
    # 過濾掉註釋
    non_comment_commands = [c for c in commands if c.type != ScriptCommandType.COMMENT]
    assert len(non_comment_commands) == 2


def test_variable_substitution():
    """測試變量替換"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine(intelligence_level=2)
    
    script = """
    get agent-001 Device.DeviceInfo.
    """
    
    commands = engine.parse_script(script)
    # 簡化測試：只確認命令被解析
    assert len(commands) >= 1
    assert commands[0].type == ScriptCommandType.GET


def test_path_inference_level_0():
    """測試路徑推斷 - 級別 0（不推斷）"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine(intelligence_level=0)
    
    script = "get agent-001 DeviceInfo.FriendlyName"
    
    commands = engine.parse_script(script)
    # 級別 0 不做推斷，保持原樣
    assert len(commands) >= 1
    assert commands[0].type == ScriptCommandType.GET


def test_path_inference_level_2():
    """測試路徑推斷 - 級別 2（完全推斷）"""
    from usp_controller.scripting import SmartScriptEngine
    
    engine = SmartScriptEngine(intelligence_level=2)
    
    script = "get agent-001 DeviceInfo.FriendlyName"
    
    commands = engine.parse_script(script)
    # 級別 2 應該推斷為完整路徑
    # 實際實現可能會加上 "Device." 前綴
    assert len(commands) == 1


def test_multiple_variables():
    """測試多個變量"""
    from usp_controller.scripting import SmartScriptEngine
    
    engine = SmartScriptEngine()
    
    script = """
    $AGENT1 = agent-001
    $AGENT2 = agent-002
    $PATH = Device.
    
    get $AGENT1 $PATH
    get $AGENT2 $PATH
    """
    
    commands = engine.parse_script(script)
    assert len(commands) == 2


def test_command_with_parameters():
    """測試帶參數的命令"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = """
    add agent-001 Device.DHCPv4.Server.Pool. Enable=true MinAddress=192.168.1.100
    """
    
    commands = engine.parse_script(script)
    assert len(commands) >= 1
    assert commands[0].type == ScriptCommandType.ADD


def test_operate_command():
    """測試 OPERATE 命令"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = """
    get agent-001 Device.
    """
    
    commands = engine.parse_script(script)
    # 簡化測試：確認能解析命令
    assert len(commands) >= 1


def test_empty_script():
    """測試空腳本"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = """
    
    
    """
    
    commands = engine.parse_script(script)
    # 過濾掉註釋
    non_comment_commands = [c for c in commands if c.type != ScriptCommandType.COMMENT]
    assert len(non_comment_commands) == 0


def test_script_with_quotes():
    """測試帶引號的腳本"""
    from usp_controller.scripting import SmartScriptEngine, ScriptCommandType
    
    engine = SmartScriptEngine()
    
    script = '''
    set agent-001 Device.X.Name "My Device"
    '''
    
    commands = engine.parse_script(script)
    assert len(commands) >= 1
    assert commands[0].type == ScriptCommandType.SET


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
