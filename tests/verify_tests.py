#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Test Verification
快速測試驗證 - 確保測試模組正常工作
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def verify_test_module(module_name, test_file):
    """驗證測試模組"""
    print(f"\n{'='*60}")
    print(f"Testing: {module_name}")
    print(f"File: {test_file}")
    print('='*60)
    
    try:
        # 嘗試導入測試模組
        exec(f"import {test_file.stem}")
        print(f"✅ {module_name} - Import successful")
        return True
    except Exception as e:
        print(f"❌ {module_name} - Import failed: {e}")
        return False


def main():
    """主函數"""
    print("\n" + "="*60)
    print("USP Controller Test Suite Verification")
    print("USP 控制器測試套件驗證")
    print("="*60)
    
    test_dir = Path(__file__).parent
    
    # 測試文件列表
    test_modules = [
        ('Config Module', 'test_config'),
        ('Logger Module', 'test_logger'),
        ('Transport Module', 'test_transport'),
        ('Protocol Module', 'test_protocol'),
        ('Scripting Module', 'test_scripting'),
        ('Integration Tests', 'test_integration'),
        ('Interface Layer', 'test_interface_layer'),
        ('V3 Architecture', 'test_v3_architecture'),
    ]
    
    results = {}
    
    for module_name, test_name in test_modules:
        test_file = test_dir / f"{test_name}.py"
        
        if test_file.exists():
            # 簡單檢查文件內容
            content = test_file.read_text(encoding='utf-8')
            
            # 統計測試函數
            test_count = content.count('def test_')
            
            print(f"\n📝 {module_name}")
            print(f"   File: {test_file.name}")
            print(f"   Tests: {test_count} test functions")
            
            results[module_name] = {
                'exists': True,
                'test_count': test_count
            }
        else:
            print(f"\n❌ {module_name} - File not found!")
            results[module_name] = {
                'exists': False,
                'test_count': 0
            }
    
    # 統計
    print("\n" + "="*60)
    print("Summary / 總結")
    print("="*60)
    
    total_modules = len(results)
    existing_modules = sum(1 for r in results.values() if r['exists'])
    total_tests = sum(r['test_count'] for r in results.values())
    
    print(f"\n📊 Test Modules: {existing_modules}/{total_modules}")
    print(f"📊 Total Test Functions: {total_tests}")
    
    # 檢查 pytest 配置
    print("\n" + "="*60)
    print("Configuration Files / 配置文件")
    print("="*60)
    
    config_files = [
        ('pytest.ini', Path(__file__).parent.parent / 'pytest.ini'),
        ('conftest.py', test_dir / 'conftest.py'),
        ('test_utils.py', test_dir / 'test_utils.py'),
    ]
    
    for name, filepath in config_files:
        if filepath.exists():
            print(f"✅ {name} - Found")
        else:
            print(f"❌ {name} - Not found")
    
    # 檢查測試運行器
    print("\n" + "="*60)
    print("Test Runners / 測試運行器")
    print("="*60)
    
    runners = [
        ('run_tests.bat', Path(__file__).parent.parent / 'run_tests.bat'),
        ('run_tests.py', Path(__file__).parent.parent / 'run_tests.py'),
    ]
    
    for name, filepath in runners:
        if filepath.exists():
            print(f"✅ {name} - Found")
        else:
            print(f"❌ {name} - Not found")
    
    # 最終狀態
    print("\n" + "="*60)
    print("Status / 狀態")
    print("="*60)
    
    if existing_modules == total_modules and total_tests > 0:
        print("\n✅ All test modules are ready!")
        print("✅ 所有測試模組已就緒！")
        print("\nRun tests with:")
        print("  Windows: run_tests.bat")
        print("  Command: python run_tests.py")
        print("  Pytest:  pytest tests/ -v")
    else:
        print("\n⚠️  Some test modules are missing or empty")
        print("⚠️  部分測試模組缺失或為空")
    
    print()


if __name__ == '__main__':
    main()
