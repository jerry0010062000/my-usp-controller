#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置管理模組
使用dataclass提供型別安全的配置管理
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
from pathlib import Path


def _create_config_from_example(filepath: str = 'config.json') -> bool:
    """Create config file from example template on first run."""
    target_path = Path(filepath)
    base_dir = target_path.parent if str(target_path.parent) else Path('.')

    candidates = [
        base_dir / 'config.v3.example.json',
        base_dir / 'config.example.json',
    ]

    for example_path in candidates:
        if example_path.exists():
            try:
                with open(example_path, 'r', encoding='utf-8') as src, open(target_path, 'w', encoding='utf-8') as dst:
                    dst.write(src.read())
                return True
            except Exception:
                return False

    return False


@dataclass
class TransportConfig:
    """傳輸層配置（支援多種協議）"""
    protocol: str = "stomp"  # stomp, mqtt, websocket, etc.
    host: str = "127.0.0.1"
    port: int = 61613
    username: str = "guest"
    password: str = "guest"
    # 協議特定配置
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IPCConfig:
    """IPC服務配置"""
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 6001
    timeout: float = 30.0


@dataclass
class DiscoveryConfig:
    """設備發現配置"""
    mdns_enabled: bool = True
    auto_register: bool = True
    scan_interval: int = 60  # seconds


@dataclass
class HeartbeatConfig:
    """心跳檢測配置"""
    enabled: bool = True
    interval: int = 60  # seconds
    timeout: int = 300  # seconds
    check_path: str = "Device.DeviceInfo.UpTime"


@dataclass
class ScriptingConfig:
    """智能腳本配置"""
    intelligence_level: int = 2  # 0=基本, 1=中等, 2=高級
    auto_discovery: bool = True  # 自動推斷參數路徑
    auto_retry: bool = True
    max_retries: int = 3
    scripts_dir: str = "scripts"


@dataclass
class ControllerConfig:
    """USP控制器主配置"""
    # 必要配置
    controller_endpoint_id: str
    receive_topic: str
    
    # 子配置
    transport: TransportConfig = field(default_factory=TransportConfig)
    ipc: IPCConfig = field(default_factory=IPCConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    heartbeat: HeartbeatConfig = field(default_factory=HeartbeatConfig)
    scripting: ScriptingConfig = field(default_factory=ScriptingConfig)
    
    # 其他配置
    devices_file: str = "devices.json"
    debug_level: int = 0  # 0=Agent Only, 1=Both Payloads, 2=Full Details
    reply_to_queue: Optional[str] = None
    
    def __post_init__(self):
        """初始化後處理"""
        # 自動生成 reply_to_queue
        if self.reply_to_queue is None:
            self.reply_to_queue = f'/queue/{self.controller_endpoint_id}'
    
    @classmethod
    def from_json(cls, filepath: str = 'config.json') -> 'ControllerConfig':
        """從JSON文件加載配置"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # 解析配置
            usp_config = data.get('usp_controller', {})
            
            # 驗證必要欄位
            if 'controller_endpoint_id' not in usp_config:
                raise ValueError("Missing required field: controller_endpoint_id")
            if 'receive_topic' not in usp_config:
                raise ValueError("Missing required field: receive_topic")
            
            # 構建TransportConfig
            transport_config = TransportConfig(
                protocol=usp_config.get('transport_protocol', 'stomp'),
                host=usp_config.get('broker_host', '127.0.0.1'),
                port=usp_config.get('broker_port', 61613),
                username=usp_config.get('username', 'guest'),
                password=usp_config.get('password', 'guest'),
                extra=usp_config.get('transport_extra', {})
            )
            
            # 構建IPCConfig
            ipc_data = data.get('ipc', {})
            ipc_config = IPCConfig(
                enabled=ipc_data.get('enabled', True),
                host=ipc_data.get('host', '127.0.0.1'),
                port=ipc_data.get('port', 6001),
                timeout=ipc_data.get('timeout', 30.0)
            )
            
            # 構建DiscoveryConfig
            discovery_config = DiscoveryConfig(
                mdns_enabled=usp_config.get('enable_mdns_discovery', True),
                auto_register=usp_config.get('auto_register_devices', True),
                scan_interval=usp_config.get('mdns_scan_interval', 60)
            )
            
            # 構建HeartbeatConfig
            heartbeat_config = HeartbeatConfig(
                enabled=usp_config.get('heartbeat_check_enabled', True),
                interval=usp_config.get('heartbeat_check_interval', 60),
                timeout=usp_config.get('device_timeout', 300),
                check_path=usp_config.get('heartbeat_check_path', 'Device.DeviceInfo.UpTime')
            )
            
            # 構建ScriptingConfig
            scripting_data = data.get('scripting', {})
            scripting_config = ScriptingConfig(
                intelligence_level=scripting_data.get('intelligence_level', 2),
                auto_discovery=scripting_data.get('auto_discovery', True),
                auto_retry=scripting_data.get('auto_retry', True),
                max_retries=scripting_data.get('max_retries', 3),
                scripts_dir=scripting_data.get('scripts_dir', 'scripts')
            )
            
            # 構建主配置
            return cls(
                controller_endpoint_id=usp_config['controller_endpoint_id'],
                receive_topic=usp_config['receive_topic'],
                transport=transport_config,
                ipc=ipc_config,
                discovery=discovery_config,
                heartbeat=heartbeat_config,
                scripting=scripting_config,
                devices_file=usp_config.get('devices_file', 'devices.json'),
                debug_level=usp_config.get('debug_level', 0),
                reply_to_queue=usp_config.get('reply_to_queue')
            )
            
        except FileNotFoundError:
            if _create_config_from_example(filepath):
                return cls.from_json(filepath)
            raise FileNotFoundError(f"Config file '{filepath}' not found. Please create it from config.v3.example.json or config.example.json")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")
    
    def to_json(self, filepath: str = 'config.json') -> None:
        """保存配置到JSON文件"""
        # 構建兼容的JSON結構
        data = {
            'usp_controller': {
                'transport_protocol': self.transport.protocol,
                'broker_host': self.transport.host,
                'broker_port': self.transport.port,
                'username': self.transport.username,
                'password': self.transport.password,
                'transport_extra': self.transport.extra,
                'controller_endpoint_id': self.controller_endpoint_id,
                'receive_topic': self.receive_topic,
                'reply_to_queue': self.reply_to_queue,
                'devices_file': self.devices_file,
                'debug_level': self.debug_level,
                'enable_mdns_discovery': self.discovery.mdns_enabled,
                'auto_register_devices': self.discovery.auto_register,
                'mdns_scan_interval': self.discovery.scan_interval,
                'heartbeat_check_enabled': self.heartbeat.enabled,
                'heartbeat_check_interval': self.heartbeat.interval,
                'device_timeout': self.heartbeat.timeout,
                'heartbeat_check_path': self.heartbeat.check_path,
            },
            'ipc': {
                'enabled': self.ipc.enabled,
                'host': self.ipc.host,
                'port': self.ipc.port,
                'timeout': self.ipc.timeout
            },
            'scripting': {
                'intelligence_level': self.scripting.intelligence_level,
                'auto_discovery': self.scripting.auto_discovery,
                'auto_retry': self.scripting.auto_retry,
                'max_retries': self.scripting.max_retries,
                'scripts_dir': self.scripting.scripts_dir
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def validate(self) -> bool:
        """驗證配置有效性"""
        if not self.controller_endpoint_id:
            raise ValueError("controller_endpoint_id cannot be empty")
        if not self.receive_topic:
            raise ValueError("receive_topic cannot be empty")
        if self.transport.port < 1 or self.transport.port > 65535:
            raise ValueError("Invalid transport port")
        if self.ipc.port < 1 or self.ipc.port > 65535:
            raise ValueError("Invalid IPC port")
        return True


def load_config(filepath: str = 'config.json') -> ControllerConfig:
    """便捷函數：加載配置"""
    return ControllerConfig.from_json(filepath)


def save_config(config: ControllerConfig, filepath: str = 'config.json') -> None:
    """便捷函數：保存配置"""
    config.to_json(filepath)
