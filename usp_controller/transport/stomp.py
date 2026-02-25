#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STOMP 傳輸協議實現
"""

import socket
import threading
import time
from typing import Dict, Optional, Any
from .base import TransportProtocol, TransportState, TransportFactory
from ..logger import get_logger

logger = get_logger()


class STOMPTransport(TransportProtocol):
    """
    STOMP 1.2 傳輸協議實現
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get('host', '127.0.0.1')
        self.port = config.get('port', 61613)
        self.username = config.get('username', 'guest')
        self.password = config.get('password', 'guest')
        self.heartbeat = config.get('heartbeat', '0,0')
        
        self.sock: Optional[socket.socket] = None
        self.recv_thread: Optional[threading.Thread] = None
        self.running = False
        self.subscriptions: Dict[str, str] = {}  # destination -> subscription_id
        self.subscription_counter = 0
        self._lock = threading.Lock()
    
    def connect(self) -> bool:
        """建立STOMP連接"""
        try:
            self._notify_state_change(TransportState.CONNECTING)
            
            # 創建socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            
            # 發送CONNECT幀
            connect_frame = (
                f"CONNECT\n"
                f"accept-version:1.2\n"
                f"host:/\n"
                f"login:{self.username}\n"
                f"passcode:{self.password}\n"
                f"heart-beat:{self.heartbeat}\n"
                f"\n\0"
            )
            
            self.sock.sendall(connect_frame.encode('utf-8'))
            logger.stomp_frame("send", {
                "command": "CONNECT",
                "accept-version": "1.2",
                "login": self.username
            })
            
            # 接收CONNECTED響應
            response = self.sock.recv(1024)
            if b'CONNECTED' not in response:
                logger.error(f"STOMP connection failed: {response}")
                self._notify_state_change(TransportState.ERROR)
                return False
            
            logger.success(f"STOMP connected to {self.host}:{self.port}", level=0)
            
            # 啟動接收線程
            self.running = True
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()
            
            self._notify_state_change(TransportState.CONNECTED)
            return True
            
        except Exception as e:
            logger.error(f"STOMP connection error: {e}")
            self._notify_state_change(TransportState.ERROR)
            if self.sock:
                self.sock.close()
                self.sock = None
            return False
    
    def disconnect(self) -> bool:
        """斷開STOMP連接"""
        try:
            self._notify_state_change(TransportState.DISCONNECTING)
            self.running = False
            
            if self.sock:
                # 發送DISCONNECT幀
                disconnect_frame = "DISCONNECT\n\n\0"
                try:
                    self.sock.sendall(disconnect_frame.encode('utf-8'))
                except:
                    pass
                
                self.sock.close()
                self.sock = None
            
            # 等待接收線程結束
            if self.recv_thread and self.recv_thread.is_alive():
                self.recv_thread.join(timeout=2)
            
            logger.info("STOMP disconnected", level=1)
            self._notify_state_change(TransportState.DISCONNECTED)
            return True
            
        except Exception as e:
            logger.error(f"STOMP disconnect error: {e}")
            self._notify_state_change(TransportState.ERROR)
            return False
    
    def subscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """訂閱STOMP目的地"""
        try:
            if not self.is_connected():
                logger.error("Cannot subscribe: not connected")
                return False
            
            with self._lock:
                if subscription_id is None:
                    subscription_id = f"sub-{self.subscription_counter}"
                    self.subscription_counter += 1
                
                # 發送SUBSCRIBE幀
                subscribe_frame = (
                    f"SUBSCRIBE\n"
                    f"id:{subscription_id}\n"
                    f"destination:{destination}\n"
                    f"ack:auto\n"
                    f"\n\0"
                )
                
                self.sock.sendall(subscribe_frame.encode('utf-8'))
                self.subscriptions[destination] = subscription_id
                
                logger.success(f"Subscribed to {destination} (id: {subscription_id})", level=1)
                return True
                
        except Exception as e:
            logger.error(f"STOMP subscribe error: {e}")
            return False
    
    def unsubscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """取消訂閱"""
        try:
            with self._lock:
                if subscription_id is None:
                    subscription_id = self.subscriptions.get(destination)
                
                if not subscription_id:
                    logger.error(f"No subscription found for {destination}")
                    return False
                
                # 發送UNSUBSCRIBE幀
                unsubscribe_frame = (
                    f"UNSUBSCRIBE\n"
                    f"id:{subscription_id}\n"
                    f"\n\0"
                )
                
                self.sock.sendall(unsubscribe_frame.encode('utf-8'))
                
                if destination in self.subscriptions:
                    del self.subscriptions[destination]
                
                logger.info(f"Unsubscribed from {destination}", level=1)
                return True
                
        except Exception as e:
            logger.error(f"STOMP unsubscribe error: {e}")
            return False
    
    def send(self, destination: str, body: bytes, 
            headers: Optional[Dict[str, str]] = None) -> bool:
        """發送STOMP訊息"""
        try:
            if not self.is_connected():
                logger.error("Cannot send: not connected")
                return False
            
            # 構建SEND幀
            frame = f"SEND\n"
            frame += f"destination:{destination}\n"
            
            # 添加自定義標頭
            if headers:
                for key, value in headers.items():
                    frame += f"{key}:{value}\n"
            
            frame += f"content-length:{len(body)}\n"
            frame += "\n"
            
            # 發送幀和body
            frame_bytes = frame.encode('utf-8') + body + b'\0'
            self.sock.sendall(frame_bytes)
            
            logger.stomp_frame("send", {
                "command": "SEND",
                "destination": destination,
                "content-length": len(body)
            }, body)
            
            return True
            
        except Exception as e:
            logger.error(f"STOMP send error: {e}")
            return False
    
    def is_connected(self) -> bool:
        """檢查是否已連接"""
        return self.state == TransportState.CONNECTED and self.sock is not None
    
    def _recv_loop(self):
        """接收循環（在獨立線程中運行）"""
        buffer = b''
        
        while self.running and self.sock:
            try:
                # 使用select進行超時接收
                import select
                ready = select.select([self.sock], [], [], 1.0)
                
                if not ready[0]:
                    continue
                
                chunk = self.sock.recv(65536)
                if not chunk:
                    logger.error("STOMP connection closed by server")
                    self._notify_state_change(TransportState.ERROR)
                    break
                
                buffer += chunk
                
                # 處理緩衝區中的完整幀
                while b'\0' in buffer:
                    frame_bytes, buffer = buffer.split(b'\0', 1)
                    if frame_bytes:
                        self._process_frame(frame_bytes)
                        
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"STOMP receive error: {e}")
                    self._notify_state_change(TransportState.ERROR)
                break
        
        logger.info("STOMP receive loop stopped", level=2)
    
    def _process_frame(self, frame_bytes: bytes):
        """處理接收到的STOMP幀"""
        try:
            # 分離標頭和body
            if b'\n\n' in frame_bytes:
                header_part, body = frame_bytes.split(b'\n\n', 1)
            else:
                header_part = frame_bytes
                body = b''
            
            headers = {}
            header_lines = header_part.decode('utf-8', errors='ignore').split('\n')
            
            # 找到命令
            command = ""
            start_idx = 0
            for i, line in enumerate(header_lines):
                if line.strip():
                    command = line.strip()
                    start_idx = i + 1
                    break
            
            # 解析標頭
            for line in header_lines[start_idx:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            
            logger.stomp_frame("recv", headers, body if len(body) < 200 else body[:200])
            
            # 處理MESSAGE幀
            if command == "MESSAGE":
                self._handle_message(headers, body)
            elif command == "ERROR":
                error_msg = headers.get('message', 'Unknown error')
                logger.error(f"STOMP ERROR: {error_msg}")
                
        except Exception as e:
            logger.error(f"STOMP frame processing error: {e}")
    
    def _handle_message(self, headers: Dict[str, str], body: bytes):
        """處理MESSAGE幀"""
        try:
            # 提取sender（如果存在於USP Record中）
            sender = None  # 將由message_callback從USP Record中提取
            
            # 調用訊息回調
            if self.message_callback:
                self.message_callback(headers, body, sender)
                
        except Exception as e:
            logger.error(f"Message callback error: {e}")
    
    def get_subscriptions(self) -> Dict[str, str]:
        """獲取當前訂閱列表"""
        with self._lock:
            return self.subscriptions.copy()


# 註冊STOMP協議到工廠
TransportFactory.register('stomp', STOMPTransport)
