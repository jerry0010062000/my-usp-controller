#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Runner Script
測試運行腳本 - 提供更多測試選項
"""

import sys
import subprocess
from pathlib import Path
import argparse


def run_tests(args):
    """運行測試"""
    
    # 構建 pytest 命令
    cmd = [sys.executable, '-m', 'pytest']
    
    # 添加測試路徑
    if args.path:
        cmd.append(args.path)
    else:
        cmd.append('tests/')
    
    # 添加選項
    if args.verbose:
        cmd.append('-v')
    
    if args.coverage:
        cmd.extend(['--cov=usp_controller', '--cov-report=html', '--cov-report=term'])
    
    if args.markers:
        cmd.extend(['-m', args.markers])
    
    if args.keyword:
        cmd.extend(['-k', args.keyword])
    
    if args.failed_first:
        cmd.append('--failed-first')
    
    if args.exitfirst:
        cmd.append('-x')
    
    # 顯示命令
    print("=" * 60)
    print("Running tests with command:")
    print(" ".join(cmd))
    print("=" * 60)
    print()
    
    # 執行
    result = subprocess.run(cmd)
    
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description='USP Controller Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Run all tests
  %(prog)s --coverage                # Run with coverage report
  %(prog)s -m unit                   # Run only unit tests
  %(prog)s -k "test_config"          # Run tests matching keyword
  %(prog)s tests/test_config.py      # Run specific test file
  %(prog)s -x                        # Stop on first failure
        """
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        help='Path to test file or directory (default: tests/)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '-c', '--coverage',
        action='store_true',
        help='Run with coverage report'
    )
    
    parser.add_argument(
        '-m', '--markers',
        help='Run tests with specific markers (unit, integration, slow, network)'
    )
    
    parser.add_argument(
        '-k', '--keyword',
        help='Run tests matching keyword expression'
    )
    
    parser.add_argument(
        '-f', '--failed-first',
        action='store_true',
        help='Run failed tests first'
    )
    
    parser.add_argument(
        '-x', '--exitfirst',
        action='store_true',
        help='Exit on first test failure'
    )
    
    args = parser.parse_args()
    
    # 檢查 pytest 是否安裝
    try:
        subprocess.run(
            [sys.executable, '-m', 'pytest', '--version'],
            check=True,
            capture_output=True
        )
    except subprocess.CalledProcessError:
        print("Error: pytest is not installed!")
        print("Please install test dependencies:")
        print("  pip install -r requirements.txt")
        return 1
    
    # 運行測試
    return run_tests(args)


if __name__ == '__main__':
    sys.exit(main())
