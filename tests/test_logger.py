#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logger Module Unit Tests
測試日誌系統模組
"""

import sys
from pathlib import Path
import threading
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


def test_logger_imports():
    """測試日誌模組導入"""
    from usp_controller.logger import (
        get_logger,
        set_debug_level,
        LogType
    )
    assert get_logger is not None


def test_logger_singleton():
    """測試日誌器單例模式"""
    from usp_controller.logger import get_logger
    
    logger1 = get_logger()
    logger2 = get_logger()
    
    assert logger1 is logger2


def test_logger_basic_logging():
    """測試基本日誌記錄"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    
    # 記錄不同級別的日誌
    logger.critical("Critical message")
    logger.error("Error message")
    logger.success("Success message")
    logger.info("Info message")
    logger.data("Data message")
    
    # 獲取歷史記錄
    history = logger.get_history(max_count=10)
    assert len(history) >= 3  # 至少有一些日誌


def test_logger_debug_level():
    """測試調試級別設置"""
    from usp_controller.logger import get_logger, set_debug_level
    
    logger = get_logger()
    
    # 設置調試級別
    set_debug_level(0)
    assert logger.debug_level == 0
    
    set_debug_level(1)
    assert logger.debug_level == 1
    
    set_debug_level(2)
    assert logger.debug_level == 2


def test_logger_usp_message():
    """測試 USP 訊息日誌"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    
    logger.usp_message(
        direction="send",
        endpoint="agent-001",
        msg_type="GET",
        details={"path": "Device.DeviceInfo."}
    )
    
    history = logger.get_history(max_count=1)
    assert len(history) >= 1


def test_logger_thread_safety():
    """測試日誌器執行緒安全性"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    results = []
    
    def log_messages(thread_id):
        for i in range(10):
            logger.info(f"Thread {thread_id} - Message {i}")
    
    # 創建多個執行緒
    threads = []
    for i in range(5):
        t = threading.Thread(target=log_messages, args=(i,))
        threads.append(t)
        t.start()
    
    # 等待所有執行緒完成
    for t in threads:
        t.join()
    
    # 檢查歷史記錄（獲取最近50條）
    history = logger.get_history(max_count=50)
    # 由於是單例模式，可能有之前的日誌
    assert len(history) >= 10  # 至少有當前測試的一部分


def test_logger_history_limit():
    """測試歷史記錄限制"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    
    # 清空歷史
    logger.clear_history()
    
    # 記錄大量日誌
    for i in range(100):
        logger.info(f"Message {i}")
    
    history = logger.get_history(max_count=200)
    assert len(history) >= 100


def test_logger_callback():
    """測試日誌回調功能"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    callback_called = []
    
    def test_callback(log_entry):
        callback_called.append(log_entry)
    
    logger.add_callback(test_callback)
    
    logger.info("Test callback message")
    
    # 等待回調執行
    time.sleep(0.1)
    
    assert len(callback_called) > 0


def test_logger_history_retrieval():
    """測試歷史記錄檢索"""
    from usp_controller.logger import get_logger
    
    logger = get_logger()
    logger.clear_history()
    
    # 記錄一些訊息
    logger.error("Error 1")
    logger.info("Info 1")
    logger.success("Success 1")
    
    # 獲取最後 N 條記錄
    last_2 = logger.get_history(max_count=2)
    assert len(last_2) == 2
    
    # 獲取所有記錄
    all_logs = logger.get_history(max_count=100)
    assert len(all_logs) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
