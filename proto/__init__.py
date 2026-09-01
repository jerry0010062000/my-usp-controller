# -*- coding: utf-8 -*-
"""
USP Protocol Buffers Package (TR-369)
Contains compiled protobuf Python modules and source .proto files.
"""

from . import usp_record_1_4_pb2 as record_pb2
from . import usp_msg_1_4_pb2 as msg_pb2

__all__ = ['record_pb2', 'msg_pb2']
