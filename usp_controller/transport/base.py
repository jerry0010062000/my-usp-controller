#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
傳輸層基礎抽象
定義所有傳輸協議的通用接口
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Callable, Any
from enum import Enum


class TransportState(Enum):
    """傳輸層狀態"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class TransportProtocol(ABC):
    """
    傳輸協議抽象基類
    
    所有傳輸協議（STOMP, MQTT, WebSocket等）都必須實現此接口
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        初始化傳輸協議
        
        Args:
            config: 協議特定的配置字典
        """
        self.config = config
        self.state = TransportState.DISCONNECTED
        self.message_callback: Optional[Callable] = None
        self.state_callback: Optional[Callable] = None
    
    @abstractmethod
    def connect(self) -> bool:
        """
        建立連接
        
        Returns:
            bool: 連接是否成功
        """
        pass
    
    @abstractmethod
    def disconnect(self) -> bool:
        """
        斷開連接
        
        Returns:
            bool: 斷開是否成功
        """
        pass
    
    @abstractmethod
    def subscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """
        訂閱目的地
        
        Args:
            destination: 訂閱的目的地（queue/topic）
            subscription_id: 訂閱ID（可選）
        
        Returns:
            bool: 訂閱是否成功
        """
        pass
    
    @abstractmethod
    def unsubscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """
        取消訂閱
        
        Args:
            destination: 取消訂閱的目的地
            subscription_id: 訂閱ID（可選）
        
        Returns:
            bool: 取消訂閱是否成功
        """
        pass
    
    @abstractmethod
    def send(self, destination: str, body: bytes, 
            headers: Optional[Dict[str, str]] = None) -> bool:
        """
        發送訊息
        
        Args:
            destination: 目的地
            body: 訊息體（二進制）
            headers: 額外的標頭
        
        Returns:
            bool: 發送是否成功
        """
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """
        檢查是否已連接
        
        Returns:
            bool: 是否已連接
        """
        pass
    
    def set_message_callback(self, callback: Callable[[Dict, bytes, Optional[str]], None]):
        """
        設置訊息接收回調
        
        Args:
            callback: 回調函數，參數為 (headers, body, sender_endpoint_id)
        """
        self.message_callback = callback
    
    def set_state_callback(self, callback: Callable[[TransportState], None]):
        """
        設置狀態變化回調
        
        Args:
            callback: 回調函數，參數為 (new_state)
        """
        self.state_callback = callback
    
    def _notify_state_change(self, new_state: TransportState):
        """通知狀態變化"""
        self.state = new_state
        if self.state_callback:
            try:
                self.state_callback(new_state)
            except Exception as e:
                print(f"[Transport] State callback error: {e}")
    
    def get_state(self) -> TransportState:
        """獲取當前狀態"""
        return self.state
    
    def get_protocol_name(self) -> str:
        """獲取協議名稱"""
        return self.__class__.__name__.replace('Transport', '').upper()


class TransportFactory:
    """傳輸協議工廠"""
    
    _protocols: Dict[str, type] = {}
    
    @classmethod
    def register(cls, protocol_name: str, protocol_class: type):
        """
        註冊傳輸協議
        
        Args:
            protocol_name: 協議名稱（例如 'stomp', 'mqtt'）
            protocol_class: 協議類別
        """
        cls._protocols[protocol_name.lower()] = protocol_class
    
    @classmethod
    def create(cls, protocol_name: str, config: Dict[str, Any]) -> TransportProtocol:
        """
        創建傳輸協議實例
        
        Args:
            protocol_name: 協議名稱
            config: 協議配置
        
        Returns:
            TransportProtocol: 傳輸協議實例
        
        Raises:
            ValueError: 如果協議未註冊
        """
        protocol_class = cls._protocols.get(protocol_name.lower())
        if not protocol_class:
            raise ValueError(f"Transport protocol '{protocol_name}' not registered. "
                           f"Available: {list(cls._protocols.keys())}")
        return protocol_class(config)
    
    @classmethod
    def list_protocols(cls) -> list:
        """列出所有已註冊的協議"""
        return list(cls._protocols.keys())

