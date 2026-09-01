#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller Test Suite Runner
Runs all unit and integration tests with automatic fixture injection.
"""

import sys
import io
import inspect
import time
from pathlib import Path

# Force UTF-8 encoding
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    except Exception:
        pass

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "tests"))

from usp_controller.protocol import USPMessage
from usp_controller.logger import get_logger

# Built-in fixture registry
FIXTURES = {
    'usp_message': lambda: USPMessage(controller_id="test-controller"),
    'clean_logger': lambda: get_logger(),
    'sample_usp_paths': lambda: ["Device.", "Device.DeviceInfo."],
    'sample_script': lambda: "get agent-001 Device.DeviceInfo.\n",
    'mock_agent_response': lambda: {"Device.DeviceInfo.SoftwareVersion": "1.0.0"}
}

TEST_MODULES = [
    ('test_config', 'Config Module'),
    ('test_logger', 'Logger Module'),
    ('test_transport', 'Transport Module'),
    ('test_protocol', 'Protocol Module'),
    ('test_scripting', 'Scripting Module'),
    ('test_ipc', 'IPC Daemon & Server Monitor'),
    ('test_dut_generator', 'DUT DataModel Guide Generator'),
    ('test_interface_layer', 'Interface Layer'),
    ('test_v3_architecture', 'V3 Architecture'),
    ('test_integration', 'Integration Tests'),
]




def run_module_tests(module_name: str, display_name: str):
    """Run all test_* functions in a module"""
    print(f"\n{'=' * 65}")
    print(f"  Testing: {display_name} ({module_name}.py)")
    print(f"{'=' * 65}")

    try:
        mod = __import__(module_name)
    except Exception as e:
        print(f"  [FAIL] FAILED TO IMPORT {module_name}: {e}")
        return 0, 1

    test_funcs = [
        (name, func) for name, func in inspect.getmembers(mod, inspect.isfunction)
        if name.startswith('test_')
    ]

    passed = 0
    failed = 0

    for name, func in test_funcs:
        t0 = time.time()
        try:
            # Inspect parameters to supply fixtures if needed
            sig = inspect.signature(func)
            kwargs = {}
            for param_name in sig.parameters:
                if param_name in FIXTURES:
                    kwargs[param_name] = FIXTURES[param_name]()

            func(**kwargs)
            elapsed = time.time() - t0
            print(f"  [OK] {name:<40} PASS ({elapsed:.3f}s)")
            passed += 1
        except Exception as e:
            elapsed = time.time() - t0
            print(f"  [FAIL] {name:<40} FAIL: {e} ({elapsed:.3f}s)")
            failed += 1

    return passed, failed


def main():
    print("\n" + "=" * 65)
    print("  USP Controller - Comprehensive Test Suite")
    print("=" * 65)

    total_passed = 0
    total_failed = 0
    start_time = time.time()

    for mod_name, disp_name in TEST_MODULES:
        p, f = run_module_tests(mod_name, disp_name)
        total_passed += p
        total_failed += f

    total_elapsed = time.time() - start_time

    print("\n" + "=" * 65)
    print(f"  TEST SUMMARY: {total_passed} Passed, {total_failed} Failed in {total_elapsed:.2f}s")
    print("=" * 65)

    if total_failed == 0:
        print("  [OK] ALL TESTS PASSED SUCCESSFULLY!\n")
        return 0
    else:
        print(f"  [!] {total_failed} TEST(S) FAILED. Please review output above.\n")
        return 1



if __name__ == "__main__":
    sys.exit(main())
