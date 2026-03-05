#!/usr/bin/env python3
"""
USP Controller Core Module
Provides reusable controller components for GUI, CLI, and Daemon modes.
"""

import sys
import os
import json
from pathlib import Path

def _create_config_from_example(config_file='config.json'):
    """Create config file from example template on first run."""
    target_path = Path(config_file)
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
                print(f"[*] Created '{config_file}' from '{example_path.name}'")
                return True
            except Exception as e:
                print(f"[!] Failed to create '{config_file}' from '{example_path.name}': {e}")
                return False

    print("[!] No example config found (expected config.v3.example.json or config.example.json)")
    return False

# Configuration management functions
def load_config(config_file='config.json'):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"[!] Config file '{config_file}' not found. Creating from example...")
        if _create_config_from_example(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Failed to load newly created config file: {e}")
        print(f"[!] Falling back to in-memory defaults.")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing config file: {e}")
        return None

def save_config(config, config_file='config.json'):
    """Save configuration to JSON file"""
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[!] Error saving config file: {e}")
        return False

# Configuration defaults
DEFAULT_CONFIG = {
    'broker_host': '127.0.0.1',
    'broker_port': 61613,
    'username': 'guest',
    'password': 'guest',
    'devices_file': 'devices.json',
    'ipc_host': '127.0.0.1',
    'ipc_port': 6001,
    'debug_level': 0,
    'auto_subscribe_wildcard': True
}

def validate_config(config):
    """Validate required configuration fields"""
    if not config:
        print("[!] Error: config.json not found or invalid")
        return False
    
    if 'usp_controller' not in config:
        print("[!] Error: 'usp_controller' section missing in config.json")
        return False
    
    usp_config = config['usp_controller']
    required = ['controller_endpoint_id', 'receive_topic']
    
    for field in required:
        if field not in usp_config:
            print(f"[!] Error: Required field '{field}' missing in config.json")
            return False
    
    return True


class ControllerCore:
    """
    Core USP Controller for embedded use in GUI or standalone operation.
    Wraps STOMPManager and provides high-level API.
    """
    
    def __init__(self, config=None):
        """Initialize controller with configuration"""
        if config is None:
            config = load_config()
        
        self.config = config
        self.config_valid = validate_config(config)
        
        if not self.config_valid:
            # Use defaults for invalid config
            self.usp_config = {}
            self.broker_host = DEFAULT_CONFIG['broker_host']
            self.broker_port = DEFAULT_CONFIG['broker_port']
            self.username = DEFAULT_CONFIG['username']
            self.password = DEFAULT_CONFIG['password']
            self.controller_id = 'controller.default'
            self.receive_topic = '/topic/agent'
        else:
            usp_cfg = config['usp_controller']
            self.broker_host = usp_cfg.get('broker_host', DEFAULT_CONFIG['broker_host'])
            self.broker_port = usp_cfg.get('broker_port', DEFAULT_CONFIG['broker_port'])
            self.username = usp_cfg.get('username', DEFAULT_CONFIG['username'])
            self.password = usp_cfg.get('password', DEFAULT_CONFIG['password'])
            self.controller_id = usp_cfg.get('controller_endpoint_id', 'controller.default')
            self.receive_topic = usp_cfg.get('receive_topic', '/topic/agent')
            
            # Check mini-broker override
            mini_broker = config.get('mini_broker', {})
            if mini_broker.get('enable', False):
                self.broker_host = mini_broker.get('host', '127.0.0.1')
                self.broker_port = mini_broker.get('port', 61613)
        
        # Initialize STOMP manager (will be created when needed)
        self.stomp = None
        self.connected = False
    
    def connect(self):
        """Connect to STOMP broker"""
        if STOMPManager is None:
            raise ImportError("STOMPManager not available. Check usp_controller.py")
        
        # Create STOMP manager with current config
        # Note: This requires usp_controller global variables to be set
        # We'll handle this by setting them before creating STOMPManager
        
        # For now, return False if not connected
        # This will be implemented after usp_controller refactoring
        return False
    
    def disconnect(self):
        """Disconnect from STOMP broker"""
        if self.stomp and self.stomp.connected:
            self.stomp.sock.close()
            self.stomp.connected = False
            self.connected = False
    
    def reload_config(self):
        """Reload configuration from file"""
        self.config = load_config()
        self.config_valid = validate_config(self.config)
        self.__init__(self.config)  # Reinitialize
    
    def get_status(self):
        """Get controller status"""
        return {
            'config_valid': self.config_valid,
            'connected': self.connected,
            'broker': f"{self.broker_host}:{self.broker_port}",
            'controller_id': self.controller_id,
            'devices': len(self.stomp.devices) if self.stomp else 0
        }


__all__ = [
    'ControllerCore',
    'STOMPManager',
    'IPCServer',
    'load_config',
    'save_config',
    'validate_config',
    'DEFAULT_CONFIG'
]
