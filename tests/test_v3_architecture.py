#!/usr/bin/env python3
"""
USP Controller v3.0 測試腳本
快速驗證新架構是否正常工作
"""

import sys
from pathlib import Path

# 添加模組路徑（專案根目錄）
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    """測試模組導入"""
    print("🧪 測試 1: 模組導入")
    try:
        from usp_controller.config import ControllerConfig
        from usp_controller.logger import get_logger
        from usp_controller.transport import TransportFactory
        from usp_controller.protocol import USPMessage
        from usp_controller.scripting import SmartScriptEngine
        print("   ✅ 所有模組導入成功")
        return True
    except Exception as e:
        print(f"   ❌ 導入失敗: {e}")
        return False

def test_config():
    """測試配置管理"""
    print("\n🧪 測試 2: 配置管理")
    try:
        from usp_controller.config import ControllerConfig
        
        # 測試配置創建
        config = ControllerConfig(
            controller_endpoint_id="test::controller",
            receive_topic="/topic/test"
        )
        
        # 測試配置驗證
        config.validate()
        
        print(f"   ✅ 配置創建成功")
        print(f"      Endpoint ID: {config.controller_endpoint_id}")
        print(f"      Protocol: {config.transport.protocol}")
        return True
    except Exception as e:
        print(f"   ❌ 配置測試失敗: {e}")
        return False

def test_logger():
    """測試日誌系統"""
    print("\n🧪 測試 3: 日誌系統")
    try:
        from usp_controller.logger import get_logger
        
        logger = get_logger()
        logger.set_debug_level(2)
        
        # 測試不同類型日誌
        logger.info("測試訊息", level=2)
        logger.success("成功訊息", level=2)
        
        # 測試歷史記錄
        history = logger.get_history(since_id=0, max_count=10)
        
        print(f"   ✅ 日誌系統正常")
        print(f"      歷史記錄: {len(history)} 條")
        return True
    except Exception as e:
        print(f"   ❌ 日誌測試失敗: {e}")
        return False

def test_transport_factory():
    """測試傳輸層工廠"""
    print("\n🧪 測試 4: 傳輸層工廠")
    try:
        from usp_controller.transport import TransportFactory
        
        # 列出可用協議
        protocols = TransportFactory.list_protocols()
        print(f"   ✅ 可用協議: {protocols}")
        
        # 測試STOMP創建（不連接）
        stomp_config = {
            'host': '127.0.0.1',
            'port': 61613,
            'username': 'test',
            'password': 'test'
        }
        stomp = TransportFactory.create('stomp', stomp_config)
        print(f"   ✅ STOMP傳輸層創建成功")
        print(f"      協議: {stomp.get_protocol_name()}")
        
        return True
    except Exception as e:
        print(f"   ❌ 傳輸層測試失敗: {e}")
        return False

def test_usp_protocol():
    """測試USP協議層"""
    print("\n🧪 測試 5: USP協議層")
    try:
        from usp_controller.protocol import USPMessage
        
        # 創建USP消息構建器
        usp = USPMessage("test::controller")
        
        # 測試GET消息創建
        record_bytes = usp.create_get("test::agent", ["Device.DeviceInfo."])
        print(f"   ✅ USP協議層正常")
        print(f"      GET消息大小: {len(record_bytes)} bytes")
        
        return True
    except Exception as e:
        print(f"   ❌ USP協議測試失敗: {e}")
        return False

def test_scripting_engine():
    """測試智能腳本引擎"""
    print("\n🧪 測試 6: 智能腳本引擎")
    try:
        from usp_controller.scripting import SmartScriptEngine
        
        # 創建引擎
        engine = SmartScriptEngine(intelligence_level=2)
        
        # 測試腳本解析
        script = """
        # 測試腳本
        get Device.DeviceInfo.  # save_to: info
        set Device.Test.Value $info
        wait 1
        """
        
        commands = engine.parse_script(script)
        print(f"   ✅ 智能腳本引擎正常")
        print(f"      解析命令數: {len(commands)}")
        
        # 測試變量
        engine.save_variable("test", "value")
        result = engine.substitute_variables("set path $test")
        print(f"      變量替換: 'set path $test' -> '{result}'")
        
        return True
    except Exception as e:
        print(f"   ❌ 腳本引擎測試失敗: {e}")
        return False

def test_config_load():
    """測試配置文件加載"""
    print("\n🧪 測試 7: 配置文件加載")
    try:
        from usp_controller.config import ControllerConfig
        import os
        
        # 檢查配置文件是否存在
        if os.path.exists('config.json'):
            config = ControllerConfig.from_json('config.json')
            print(f"   ✅ 配置文件加載成功")
            print(f"      Endpoint: {config.controller_endpoint_id}")
            print(f"      Broker: {config.transport.host}:{config.transport.port}")
            print(f"      智能級別: {config.scripting.intelligence_level}")
            return True
        else:
            print(f"   ⚠️  config.json 不存在（可選測試）")
            return True
    except Exception as e:
        print(f"   ❌ 配置加載失敗: {e}")
        return False

def main():
    """運行所有測試"""
    print("=" * 60)
    print("🚀 USP Controller v3.0 架構測試")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_config,
        test_logger,
        test_transport_factory,
        test_usp_protocol,
        test_scripting_engine,
        test_config_load,
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"\n   ❌ 測試異常: {e}")
            results.append(False)
    
    # 總結
    print("\n" + "=" * 60)
    print("📊 測試總結")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"通過: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 所有測試通過！新架構工作正常！")
        print("\n下一步:")
        print("  1. 閱讀 QUICK_START_v3.md")
        print("  2. 運行 python usp_main.py")
        print("  3. 嘗試智能腳本功能")
        return 0
    else:
        print(f"\n⚠️  {total - passed} 個測試失敗")
        print("請檢查錯誤訊息並修正問題")
        return 1

if __name__ == "__main__":
    sys.exit(main())
