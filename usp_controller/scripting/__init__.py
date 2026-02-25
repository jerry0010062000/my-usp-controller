#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能腳本引擎
提供高級腳本解析和自動推斷功能
"""

import re
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass
from enum import Enum
from ..logger import get_logger

logger = get_logger()


class ScriptCommandType(Enum):
    """腳本命令類型"""
    GET = "get"
    SET = "set"
    ADD = "add"
    DELETE = "delete"
    OPERATE = "operate"
    DISCOVER = "discover"
    GET_INSTANCES = "get_instances"
    WAIT = "wait"
    COMMENT = "comment"
    VARIABLE = "variable"
    ASSERT = "assert"
    SPECIAL = "special"


@dataclass
class ScriptCommand:
    """腳本命令"""
    type: ScriptCommandType
    raw_line: str
    line_number: int
    params: Dict[str, Any]
    annotations: Dict[str, str]  # save_to, expect, verify_delta等


class SmartScriptEngine:
    """
    智能腳本引擎
    
    特性：
    1. 自動路徑推斷 - 從fuzzy描述推斷完整路徑
    2. 自動實例發現 - 自動查找對象實例
    3. 變量支持 - 保存和替換變量
    4. 智能重試 - 失敗自動重試
    5. 斷言驗證 - 自動驗證結果
    """
    
    def __init__(self, intelligence_level: int = 2, 
                 dm_cache: Optional[Dict] = None,
                 auto_discovery: bool = True):
        """
        初始化智能腳本引擎
        
        Args:
            intelligence_level: 智能級別 (0=基本, 1=中等, 2=高級)
            dm_cache: 數據模型緩存
            auto_discovery: 是否啟用自動發現
        """
        self.intelligence_level = intelligence_level
        self.dm_cache = dm_cache or {}
        self.auto_discovery = auto_discovery
        self.variables = {}
        self.path_resolver: Optional[Callable] = None
        self.instance_finder: Optional[Callable] = None
        
        logger.info(f"Smart script engine initialized (level: {intelligence_level})", level=1)
    
    def set_path_resolver(self, resolver: Callable[[str, str], Optional[str]]):
        """
        設置路徑解析器
        
        Args:
            resolver: 函數(endpoint, fuzzy_path) -> full_path
        """
        self.path_resolver = resolver
    
    def set_instance_finder(self, finder: Callable[[str, str], List[str]]):
        """
        設置實例查找器
        
        Args:
            finder: 函數(endpoint, object_path) -> instance_list
        """
        self.instance_finder = finder
    
    def parse_script(self, script_content: str) -> List[ScriptCommand]:
        """
        解析腳本內容
        
        Args:
            script_content: 腳本文本內容
        
        Returns:
            List[ScriptCommand]: 命令列表
        """
        commands = []
        lines = script_content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            cmd = self._parse_line(line, line_num)
            if cmd:
                commands.append(cmd)
        
        logger.success(f"Parsed {len(commands)} commands from script", level=1)
        return commands
    
    def _parse_line(self, line: str, line_num: int) -> Optional[ScriptCommand]:
        """解析單行腳本"""
        original_line = line
        line = line.strip()
        
        # 空行
        if not line:
            return None
        
        # 註釋
        if line.startswith('#'):
            return ScriptCommand(
                type=ScriptCommandType.COMMENT,
                raw_line=original_line,
                line_number=line_num,
                params={'text': line[1:].strip()},
                annotations={}
            )
        
        # 提取註解
        annotations = self._extract_annotations(line)
        if annotations:
            # 移除註解部分
            line = line.split('#')[0].strip()
        
        # 解析命令
        parts = line.split()
        if not parts:
            return None
        
        cmd_type = parts[0].lower()
        
        # GET命令
        if cmd_type == 'get':
            return self._parse_get(parts, line_num, original_line, annotations)
        
        # SET命令
        elif cmd_type == 'set':
            return self._parse_set(parts, line_num, original_line, annotations)
        
        # ADD命令
        elif cmd_type == 'add':
            return self._parse_add(parts, line_num, original_line, annotations)
        
        # DELETE命令
        elif cmd_type == 'delete' or cmd_type == 'del':
            return self._parse_delete(parts, line_num, original_line, annotations)
        
        # DISCOVER命令
        elif cmd_type == 'discover' or cmd_type == 'disc':
            return self._parse_discover(parts, line_num, original_line, annotations)
        
        # WAIT命令
        elif cmd_type == 'wait':
            return self._parse_wait(parts, line_num, original_line, annotations)
        
        # 特殊命令
        elif cmd_type in ['discover_bridge_port', 'wait_user', 'exec']:
            return ScriptCommand(
                type=ScriptCommandType.SPECIAL,
                raw_line=original_line,
                line_number=line_num,
                params={'special_cmd': cmd_type, 'args': parts[1:]},
                annotations=annotations
            )
        
        # 未知命令
        else:
            logger.error(f"Unknown command at line {line_num}: {cmd_type}")
            return None
    
    def _extract_annotations(self, line: str) -> Dict[str, str]:
        """提取註解標記"""
        annotations = {}
        
        # save_to: variable_name
        match = re.search(r'#\s*save_to:\s*(\w+)', line, re.IGNORECASE)
        if match:
            annotations['save_to'] = match.group(1)
        
        # expect: value
        match = re.search(r'#\s*expect:\s*(.+?)(?:\s*#|$)', line, re.IGNORECASE)
        if match:
            annotations['expect'] = match.group(1).strip()
        
        # verify_delta: max_diff
        match = re.search(r'#\s*verify_delta:\s*(\d+)', line, re.IGNORECASE)
        if match:
            annotations['verify_delta'] = match.group(1)
        
        return annotations
    
    def _parse_get(self, parts: List[str], line_num: int, 
                   raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析GET命令"""
        if len(parts) < 2:
            logger.error(f"Line {line_num}: GET requires path")
            return None
        
        path = parts[1]
        
        return ScriptCommand(
            type=ScriptCommandType.GET,
            raw_line=raw_line,
            line_number=line_num,
            params={'path': path},
            annotations=annotations
        )
    
    def _parse_set(self, parts: List[str], line_num: int, 
                   raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析SET命令"""
        if len(parts) < 3:
            logger.error(f"Line {line_num}: SET requires path and value")
            return None
        
        path = parts[1]
        value = ' '.join(parts[2:])
        
        return ScriptCommand(
            type=ScriptCommandType.SET,
            raw_line=raw_line,
            line_number=line_num,
            params={'path': path, 'value': value},
            annotations=annotations
        )
    
    def _parse_add(self, parts: List[str], line_num: int, 
                   raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析ADD命令"""
        if len(parts) < 2:
            logger.error(f"Line {line_num}: ADD requires object path")
            return None
        
        obj_path = parts[1]
        
        # 解析初始參數 key=value
        init_params = {}
        for part in parts[2:]:
            if '=' in part:
                k, v = part.split('=', 1)
                init_params[k] = v
        
        return ScriptCommand(
            type=ScriptCommandType.ADD,
            raw_line=raw_line,
            line_number=line_num,
            params={'obj_path': obj_path, 'init_params': init_params},
            annotations=annotations
        )
    
    def _parse_delete(self, parts: List[str], line_num: int, 
                     raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析DELETE命令"""
        if len(parts) < 2:
            logger.error(f"Line {line_num}: DELETE requires object path")
            return None
        
        obj_path = parts[1]
        
        return ScriptCommand(
            type=ScriptCommandType.DELETE,
            raw_line=raw_line,
            line_number=line_num,
            params={'obj_path': obj_path},
            annotations=annotations
        )
    
    def _parse_discover(self, parts: List[str], line_num: int, 
                       raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析DISCOVER命令"""
        obj_path = parts[1] if len(parts) > 1 else "Device."
        
        return ScriptCommand(
            type=ScriptCommandType.DISCOVER,
            raw_line=raw_line,
            line_number=line_num,
            params={'obj_path': obj_path},
            annotations=annotations
        )
    
    def _parse_wait(self, parts: List[str], line_num: int, 
                   raw_line: str, annotations: Dict) -> ScriptCommand:
        """解析WAIT命令"""
        duration = float(parts[1]) if len(parts) > 1 else 1.0
        
        return ScriptCommand(
            type=ScriptCommandType.WAIT,
            raw_line=raw_line,
            line_number=line_num,
            params={'duration': duration},
            annotations=annotations
        )
    
    def resolve_path(self, endpoint: str, fuzzy_path: str) -> str:
        """
        智能路徑解析
        
        Args:
            endpoint: 設備endpoint ID
            fuzzy_path: 模糊路徑（例如："wifi.enable"）
        
        Returns:
            str: 完整路徑（例如："Device.WiFi.Radio.1.Enable"）
        """
        # 如果已經是完整路徑，直接返回
        if fuzzy_path.startswith('Device.'):
            return fuzzy_path
        
        # 智能級別0：不做轉換
        if self.intelligence_level == 0:
            return fuzzy_path
        
        # 智能級別1+：簡單模糊匹配
        if self.intelligence_level >= 1:
            # 使用自定義resolver
            if self.path_resolver:
                resolved = self.path_resolver(endpoint, fuzzy_path)
                if resolved:
                    logger.info(f"Resolved '{fuzzy_path}' -> '{resolved}'", level=2)
                    return resolved
            
            # 基本轉換規則
            fuzzy_lower = fuzzy_path.lower()
            
            # 常見縮寫映射
            mappings = {
                'wifi': 'Device.WiFi.',
                'lan': 'Device.IP.Interface.',
                'dhcp': 'Device.DHCPv4.',
                'device': 'Device.DeviceInfo.',
            }
            
            for short, full in mappings.items():
                if fuzzy_lower.startswith(short):
                    return full + fuzzy_path[len(short):].lstrip('.')
        
        # 無法解析，返回原路徑
        logger.info(f"Could not resolve '{fuzzy_path}', using as-is", level=2)
        return fuzzy_path
    
    def find_instances(self, endpoint: str, object_path: str) -> List[str]:
        """
        自動查找對象實例
        
        Args:
            endpoint: 設備endpoint ID
            object_path: 對象路徑（例如："Device.WiFi.Radio."）
        
        Returns:
            List[str]: 實例路徑列表
        """
        if self.instance_finder and self.intelligence_level >= 1:
            instances = self.instance_finder(endpoint, object_path)
            logger.info(f"Found {len(instances)} instances of {object_path}", level=2)
            return instances
        
        return []
    
    def substitute_variables(self, text: str) -> str:
        """
        替換變量
        
        Args:
            text: 包含變量的文本（例如："set path $myvar"）
        
        Returns:
            str: 替換後的文本
        """
        # 替換 $variable 格式
        for var_name, var_value in self.variables.items():
            text = text.replace(f'${var_name}', str(var_value))
            text = text.replace(f'${{{var_name}}}', str(var_value))
        
        return text
    
    def save_variable(self, name: str, value: Any):
        """保存變量"""
        self.variables[name] = value
        logger.info(f"Variable saved: {name} = {value}", level=2)
    
    def get_variable(self, name: str) -> Optional[Any]:
        """獲取變量"""
        return self.variables.get(name)
