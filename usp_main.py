#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller - 模組化版本
使用新的可擴展架構

使用方法:
  python usp_main.py                    # 互動模式
  python usp_main.py --daemon           # Daemon模式
  python usp_main.py --protocol mqtt    # 使用MQTT協議（未來）
"""

import sys
import argparse
from pathlib import Path
from usp_version import FULL_VERSION

# 添加模組路徑
sys.path.insert(0, str(Path(__file__).parent))

from usp_controller.config import ControllerConfig, load_config
from usp_controller.logger import get_logger, set_debug_level
from usp_controller.transport import TransportFactory, TransportState
from usp_controller.protocol import USPMessage
from usp_controller.scripting import SmartScriptEngine

logger = get_logger()


class USPController:
    """
    USP控制器主類（模組化版本）
    """
    
    def __init__(self, config: ControllerConfig):
        self.config = config
        self.transport = None
        self.usp_message = None
        self.script_engine = None
        
        # 設置調試級別
        set_debug_level(config.debug_level)
        
        logger.info(f"=== USP Controller v{FULL_VERSION} ===", level=0)
        logger.info(f"Controller ID: {config.controller_endpoint_id}", level=0)
    
    def initialize(self) -> bool:
        """初始化控制器"""
        try:
            # 創建傳輸層
            logger.info(f"Initializing transport: {self.config.transport.protocol}", level=0)
            self.transport = TransportFactory.create(
                self.config.transport.protocol,
                {
                    'host': self.config.transport.host,
                    'port': self.config.transport.port,
                    'username': self.config.transport.username,
                    'password': self.config.transport.password,
                    **self.config.transport.extra
                }
            )
            
            # 設置回調
            self.transport.set_message_callback(self._on_message)
            self.transport.set_state_callback(self._on_state_change)
            
            # 創建USP消息構建器
            self.usp_message = USPMessage(self.config.controller_endpoint_id)
            
            # 創建智能腳本引擎
            self.script_engine = SmartScriptEngine(
                intelligence_level=self.config.scripting.intelligence_level,
                auto_discovery=self.config.scripting.auto_discovery
            )
            
            logger.success("Controller initialized", level=0)
            return True
            
        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            return False
    
    def connect(self) -> bool:
        """連接到broker"""
        if not self.transport:
            logger.error("Transport not initialized")
            return False
        
        if self.transport.connect():
            # 訂閱接收主題
            self.transport.subscribe(self.config.receive_topic)
            logger.success(f"Subscribed to {self.config.receive_topic}", level=0)
            return True
        
        return False
    
    def disconnect(self):
        """斷開連接"""
        if self.transport:
            self.transport.disconnect()
    
    def _on_message(self, headers: dict, body: bytes, sender: str):
        """處理接收到的訊息"""
        logger.info(f"Message received from {sender or 'unknown'}", level=1)
        
        # 解析USP Record
        from_id, to_id, usp_msg = USPMessage.parse_record(body)
        
        if usp_msg:
            msg_type = usp_msg.header.msg_type
            logger.usp_message("recv", from_id, str(msg_type), level=1)
            
            # 處理不同類型的訊息
            if usp_msg.body.HasField('response'):
                self._handle_response(from_id, usp_msg)
            elif usp_msg.body.HasField('request'):
                self._handle_request(from_id, usp_msg)
            elif usp_msg.body.HasField('error'):
                logger.error(f"USP Error from {from_id}: {usp_msg.body.error.err_msg}")
    
    def _handle_response(self, from_id: str, usp_msg):
        """處理響應訊息"""
        resp = usp_msg.body.response
        
        if resp.HasField('get_resp'):
            self._display_get_response(resp.get_resp)
        elif resp.HasField('set_resp'):
            logger.success("SET operation completed", level=0)
        elif resp.HasField('add_resp'):
            logger.success("ADD operation completed", level=0)
        elif resp.HasField('delete_resp'):
            logger.success("DELETE operation completed", level=0)
    
    def _handle_request(self, from_id: str, usp_msg):
        """處理請求訊息（例如NOTIFY）"""
        logger.info(f"Request received from {from_id}", level=0)
    
    def _display_get_response(self, get_resp):
        """顯示GET響應"""
        total = 0
        logger.data("=== GET Response ===")
        for r in get_resp.req_path_results:
            status = '✓' if r.err_code == 0 else '✗'
            logger.data(f"Path: {r.requested_path} ({status})")
            for res in r.resolved_path_results:
                logger.data(f"  {res.resolved_path}")
                for p, v in res.result_params.items():
                    logger.data(f"    {p} = {v}")
                    total += 1
        logger.data(f"=== Total: {total} parameters ===")
    
    def _on_state_change(self, new_state: TransportState):
        """處理傳輸層狀態變化"""
        logger.info(f"Transport state: {new_state.value}", level=1)
    
    def send_get(self, endpoint: str, path: str) -> bool:
        """發送GET請求"""
        try:
            record_bytes = self.usp_message.create_get(endpoint, [path])
            
            # 獲取目標地址（這裡需要設備管理器支援）
            destination = f"/queue/{endpoint}"
            
            return self.transport.send(
                destination,
                record_bytes,
                {
                    'content-type': 'application/vnd.bbf.usp.msg',
                    'reply-to-dest': self.config.reply_to_queue
                }
            )
        except Exception as e:
            logger.error(f"Failed to send GET: {e}")
            return False
    
    def send_set(self, endpoint: str, path: str, value: str) -> bool:
        """發送SET請求"""
        try:
            record_bytes = self.usp_message.create_set(endpoint, {path: value})
            destination = f"/queue/{endpoint}"
            
            return self.transport.send(
                destination,
                record_bytes,
                {
                    'content-type': 'application/vnd.bbf.usp.msg',
                    'reply-to-dest': self.config.reply_to_queue
                }
            )
        except Exception as e:
            logger.error(f"Failed to send SET: {e}")
            return False


def interactive_mode(controller: USPController):
    """互動模式"""
    print("\n=== Interactive Mode ===")
    print("Type 'help' for commands, 'quit' to exit\n")
    
    while True:
        try:
            cmd = input("usp> ").strip()
            if not cmd:
                continue
            
            parts = cmd.split()
            cmd_type = parts[0].lower()
            
            if cmd_type == 'quit' or cmd_type == 'exit':
                break
            
            elif cmd_type == 'help':
                print("\nAvailable commands:")
                print("  get <endpoint> <path>      - Get parameter value")
                print("  set <endpoint> <path> <val> - Set parameter value")
                print("  status                     - Show status")
                print("  debug [0-2]                - Set debug level")
                print("  quit                       - Exit")
                print()
            
            elif cmd_type == 'status':
                print(f"Transport: {controller.transport.get_protocol_name()}")
                print(f"State: {controller.transport.get_state().value}")
                print(f"Controller ID: {controller.config.controller_endpoint_id}")
            
            elif cmd_type == 'debug':
                if len(parts) > 1:
                    level = int(parts[1])
                    set_debug_level(level)
                    print(f"Debug level set to {level}")
                else:
                    print(f"Current debug level: {logger.debug_level}")
            
            elif cmd_type == 'get':
                if len(parts) < 3:
                    print("Usage: get <endpoint> <path>")
                    continue
                endpoint = parts[1]
                path = parts[2]
                controller.send_get(endpoint, path)
            
            elif cmd_type == 'set':
                if len(parts) < 4:
                    print("Usage: set <endpoint> <path> <value>")
                    continue
                endpoint = parts[1]
                path = parts[2]
                value = ' '.join(parts[3:])
                controller.send_set(endpoint, path, value)
            
            else:
                print(f"Unknown command: {cmd_type}")
        
        except KeyboardInterrupt:
            print("\nUse 'quit' to exit")
            continue
        except Exception as e:
            print(f"Error: {e}")


def main():
    """主函數"""
    parser = argparse.ArgumentParser(
        description=f"USP Controller v{FULL_VERSION} - Modular Architecture"
    )
    parser.add_argument('--daemon', action='store_true',
                       help='Run as daemon with IPC')
    parser.add_argument('--config', default='config.json',
                       help='Config file path')
    parser.add_argument('--protocol', choices=['stomp', 'mqtt', 'websocket'],
                       help='Override transport protocol')
    parser.add_argument('--debug', type=int, choices=[0, 1, 2],
                       help='Debug level')
    
    args = parser.parse_args()
    
    # 加載配置
    try:
        config = load_config(args.config)
    except Exception as e:
        logger.critical(f"Failed to load config: {e}")
        return 1
    
    # 命令列覆蓋
    if args.protocol:
        config.transport.protocol = args.protocol
    if args.debug is not None:
        config.debug_level = args.debug
    
    # 創建控制器
    controller = USPController(config)
    
    # 初始化
    if not controller.initialize():
        return 1
    
    # 連接
    if not controller.connect():
        logger.critical("Failed to connect to broker")
        return 1
    
    try:
        if args.daemon:
            # Daemon模式（需要實現IPC服務器）
            logger.info("Daemon mode not fully implemented yet", level=0)
            logger.info("Please use usp_controller.py --daemon for now", level=0)
            import time
            while True:
                time.sleep(1)
        else:
            # 互動模式
            interactive_mode(controller)
    
    except KeyboardInterrupt:
        logger.info("Shutting down...", level=0)
    finally:
        controller.disconnect()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
