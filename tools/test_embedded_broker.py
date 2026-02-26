#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
嵌入式 Broker 測試腳本

快速測試 embedded broker 的基本功能
"""

import sys
import time
import threading
from pathlib import Path

# 添加項目路徑
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.embedded_broker import EmbeddedBroker
import stomp


def test_basic_connection():
    """測試基本連接"""
    print("=" * 60)
    print("測試 1: 基本連接")
    print("=" * 60)
    
    # 啟動 broker
    broker = EmbeddedBroker(port=61615)
    broker.start()
    time.sleep(2)
    
    try:
        # 連接客戶端
        conn = stomp.Connection([('127.0.0.1', 61615)])
        conn.connect('guest', 'guest', wait=True)
        
        print("✅ 連接成功")
        
        conn.disconnect()
        print("✅ 斷開連接成功")
        
        return True
        
    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        return False
    
    finally:
        broker.stop()
        time.sleep(1)


def test_pub_sub():
    """測試發布訂閱"""
    print("\n" + "=" * 60)
    print("測試 2: 發布訂閱")
    print("=" * 60)
    
    # 啟動 broker
    broker = EmbeddedBroker(port=61616)
    broker.start()
    time.sleep(2)
    
    messages_received = []
    
    class TestListener(stomp.ConnectionListener):
        def on_message(self, frame):
            messages_received.append(frame.body)
            print(f"📨 收到消息: {frame.body}")
    
    try:
        # 訂閱者
        sub_conn = stomp.Connection([('127.0.0.1', 61616)])
        sub_conn.set_listener('test', TestListener())
        sub_conn.connect('guest', 'guest', wait=True)
        sub_conn.subscribe(destination='/topic/test', id=1, ack='auto')
        
        print("✅ 訂閱成功: /topic/test")
        
        time.sleep(1)
        
        # 發布者
        pub_conn = stomp.Connection([('127.0.0.1', 61616)])
        pub_conn.connect('guest', 'guest', wait=True)
        
        # 發送消息
        test_messages = ['Hello', 'World', 'Test']
        for msg in test_messages:
            pub_conn.send(body=msg, destination='/topic/test')
            print(f"📤 發送消息: {msg}")
            time.sleep(0.5)
        
        time.sleep(2)
        
        # 驗證
        if len(messages_received) == len(test_messages):
            print(f"✅ 成功收到所有 {len(test_messages)} 條消息")
            return True
        else:
            print(f"❌ 預期 {len(test_messages)} 條，實際收到 {len(messages_received)} 條")
            return False
        
    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        try:
            sub_conn.disconnect()
            pub_conn.disconnect()
        except:
            pass
        broker.stop()
        time.sleep(1)


def test_multiple_subscribers():
    """測試多個訂閱者"""
    print("\n" + "=" * 60)
    print("測試 3: 多個訂閱者")
    print("=" * 60)
    
    # 啟動 broker
    broker = EmbeddedBroker(port=61617)
    broker.start()
    time.sleep(2)
    
    messages_received_1 = []
    messages_received_2 = []
    
    class TestListener1(stomp.ConnectionListener):
        def on_message(self, frame):
            messages_received_1.append(frame.body)
            print(f"📨 訂閱者1 收到: {frame.body}")
    
    class TestListener2(stomp.ConnectionListener):
        def on_message(self, frame):
            messages_received_2.append(frame.body)
            print(f"📨 訂閱者2 收到: {frame.body}")
    
    try:
        # 訂閱者 1
        conn1 = stomp.Connection([('127.0.0.1', 61617)])
        conn1.set_listener('test1', TestListener1())
        conn1.connect('guest', 'guest', wait=True)
        conn1.subscribe(destination='/topic/multi', id=1, ack='auto')
        
        # 訂閱者 2
        conn2 = stomp.Connection([('127.0.0.1', 61617)])
        conn2.set_listener('test2', TestListener2())
        conn2.connect('guest', 'guest', wait=True)
        conn2.subscribe(destination='/topic/multi', id=2, ack='auto')
        
        print("✅ 兩個訂閱者已連接")
        
        time.sleep(1)
        
        # 發布者
        pub_conn = stomp.Connection([('127.0.0.1', 61617)])
        pub_conn.connect('guest', 'guest', wait=True)
        
        # 發送消息
        pub_conn.send(body='Broadcast', destination='/topic/multi')
        print("📤 發送廣播消息")
        
        time.sleep(2)
        
        # 驗證
        if len(messages_received_1) == 1 and len(messages_received_2) == 1:
            print("✅ 兩個訂閱者都收到消息")
            return True
        else:
            print(f"❌ 訂閱者1: {len(messages_received_1)}, 訂閱者2: {len(messages_received_2)}")
            return False
        
    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        try:
            conn1.disconnect()
            conn2.disconnect()
            pub_conn.disconnect()
        except:
            pass
        broker.stop()
        time.sleep(1)


def main():
    """運行所有測試"""
    print("\n🧪 嵌入式 Broker 測試套件\n")
    
    results = []
    
    # 測試 1
    results.append(("基本連接", test_basic_connection()))
    
    # 測試 2
    results.append(("發布訂閱", test_pub_sub()))
    
    # 測試 3
    results.append(("多個訂閱者", test_multiple_subscribers()))
    
    # 總結
    print("\n" + "=" * 60)
    print("測試總結")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ 通過" if result else "❌ 失敗"
        print(f"{status} - {name}")
    
    print(f"\n總計: {passed}/{total} 通過")
    
    if passed == total:
        print("\n🎉 所有測試通過！")
        return 0
    else:
        print("\n⚠️  部分測試失敗")
        return 1


if __name__ == "__main__":
    sys.exit(main())
