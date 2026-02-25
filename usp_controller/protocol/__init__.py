#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP協議層模組
處理USP Record和Message的編碼/解碼
"""

import uuid
from typing import Dict, Optional, Any, List
from ..logger import get_logger

logger = get_logger()

# 導入protobuf定義
try:
    import usp_record_1_4_pb2 as record_pb2
    import usp_msg_1_4_pb2 as msg_pb2
    PROTOBUF_AVAILABLE = True
except ImportError:
    logger.critical("Protobuf files not found. Please generate them from .proto files")
    PROTOBUF_AVAILABLE = False
    record_pb2 = None
    msg_pb2 = None


class USPMessage:
    """USP訊息構建器"""
    
    def __init__(self, controller_id: str):
        self.controller_id = controller_id
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("Protobuf not available")
    
    def create_get(self, endpoint_id: str, paths: List[str]) -> bytes:
        """
        創建GET請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            paths: 參數路徑列表
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        # 創建USP Message
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
        
        # 添加路徑
        for path in paths:
            usp_msg.body.request.get.param_paths.append(path)
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_set(self, endpoint_id: str, params: Dict[str, str], 
                   allow_partial: bool = False) -> bytes:
        """
        創建SET請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            params: 參數字典 {path: value}
            allow_partial: 是否允許部分成功
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.SET
        
        set_req = usp_msg.body.request.set
        set_req.allow_partial = allow_partial
        
        # 添加參數
        update_obj = set_req.update_objs.add()
        update_obj.obj_path = ""
        for path, value in params.items():
            param = update_obj.param_settings.add()
            param.param = path
            param.value = str(value)
            param.required = True
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_add(self, endpoint_id: str, obj_path: str, 
                  params: Optional[Dict[str, str]] = None) -> bytes:
        """
        創建ADD請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            obj_path: 對象路徑
            params: 初始參數（可選）
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.ADD
        
        add_req = usp_msg.body.request.add
        create_obj = add_req.create_objs.add()
        create_obj.obj_path = obj_path
        
        # 添加初始參數
        if params:
            for key, value in params.items():
                param = create_obj.param_settings.add()
                param.param = key
                param.value = str(value)
                param.required = False
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_delete(self, endpoint_id: str, obj_paths: List[str], 
                     allow_partial: bool = False) -> bytes:
        """
        創建DELETE請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            obj_paths: 對象路徑列表
            allow_partial: 是否允許部分成功
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.DELETE
        
        del_req = usp_msg.body.request.delete
        del_req.allow_partial = allow_partial
        
        for obj_path in obj_paths:
            del_req.obj_paths.append(obj_path)
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_operate(self, endpoint_id: str, command: str, 
                      args: Optional[Dict[str, str]] = None, 
                      send_resp: bool = True) -> bytes:
        """
        創建OPERATE請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            command: 命令路徑
            args: 命令參數
            send_resp: 是否需要響應
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.OPERATE
        
        op_req = usp_msg.body.request.operate
        op_req.command = command
        op_req.send_resp = send_resp
        
        if args:
            for key, value in args.items():
                arg = op_req.command_key.add()
                arg.key = key
                arg.value = str(value)
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_get_supported_dm(self, endpoint_id: str, obj_paths: List[str],
                               first_level_only: bool = False,
                               return_commands: bool = True,
                               return_events: bool = True,
                               return_params: bool = True) -> bytes:
        """
        創建GetSupportedDM請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            obj_paths: 對象路徑列表
            first_level_only: 是否只返回第一層
            return_commands: 是否返回命令
            return_events: 是否返回事件
            return_params: 是否返回參數
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_SUPPORTED_DM
        
        dm_req = usp_msg.body.request.get_supported_dm
        dm_req.first_level_only = first_level_only
        dm_req.return_commands = return_commands
        dm_req.return_events = return_events
        dm_req.return_params = return_params
        
        for obj_path in obj_paths:
            dm_req.obj_paths.append(obj_path)
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def create_get_instances(self, endpoint_id: str, obj_paths: List[str],
                            first_level_only: bool = False) -> bytes:
        """
        創建GetInstances請求
        
        Args:
            endpoint_id: 目標設備endpoint ID
            obj_paths: 對象路徑列表
            first_level_only: 是否只返回第一層
        
        Returns:
            bytes: 序列化的USP Record
        """
        msg_id = str(uuid.uuid4())
        
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_INSTANCES
        
        inst_req = usp_msg.body.request.get_instances
        inst_req.first_level_only = first_level_only
        
        for obj_path in obj_paths:
            inst_req.obj_paths.append(obj_path)
        
        return self._wrap_message(endpoint_id, usp_msg)
    
    def _wrap_message(self, endpoint_id: str, usp_msg) -> bytes:
        """
        將USP Message包裝到USP Record中
        
        Args:
            endpoint_id: 目標endpoint ID
            usp_msg: USP Message對象
        
        Returns:
            bytes: 序列化的USP Record
        """
        # 序列化Message
        msg_bytes = usp_msg.SerializeToString()
        
        # 創建Record
        usp_record = record_pb2.Record()
        usp_record.version = "1.4"
        usp_record.to_id = endpoint_id
        usp_record.from_id = self.controller_id
        usp_record.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
        usp_record.no_session_context.payload = msg_bytes
        
        return usp_record.SerializeToString()
    
    @staticmethod
    def parse_record(record_bytes: bytes) -> tuple:
        """
        解析USP Record
        
        Args:
            record_bytes: USP Record二進制數據
        
        Returns:
            tuple: (from_id, to_id, usp_msg) 或 (None, None, None)
        """
        if not PROTOBUF_AVAILABLE:
            return None, None, None
        
        try:
            record = record_pb2.Record()
            record.ParseFromString(record_bytes)
            
            from_id = record.from_id
            to_id = record.to_id
            
            # 提取payload
            payload = None
            if record.HasField('no_session_context'):
                payload = record.no_session_context.payload
            elif record.HasField('session_context'):
                payload = record.session_context.payload
            
            if payload:
                msg = msg_pb2.Msg()
                msg.ParseFromString(payload)
                return from_id, to_id, msg
            
            return from_id, to_id, None
            
        except Exception as e:
            logger.error(f"Failed to parse USP record: {e}")
            return None, None, None
