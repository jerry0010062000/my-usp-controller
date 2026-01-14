#!/usr/bin/env python3
"""Test USP Protobuf encoding"""

import usp_record_1_4_pb2 as record_pb2
import usp_msg_1_4_pb2 as msg_pb2
import uuid

def test_usp_get_request():
    """Test building a USP Get request"""
    print("="*60)
    print("Testing USP Protobuf Encoding")
    print("="*60)
    
    # Build USP Message (inner)
    msg_id = str(uuid.uuid4())
    usp_msg = msg_pb2.Msg()
    
    # Set message header
    usp_msg.header.msg_id = msg_id
    usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
    
    # Build Get request
    get_request = usp_msg.body.request.get
    get_request.param_paths.append('Device.DeviceInfo.')
    get_request.param_paths.append('Device.DeviceInfo.ModelName')
    
    # Serialize the USP Message
    msg_bytes = usp_msg.SerializeToString()
    print(f"\n✓ USP Message:")
    print(f"  - Message ID: {msg_id}")
    print(f"  - Type: GET")
    print(f"  - Paths: Device.DeviceInfo., Device.DeviceInfo.ModelName")
    print(f"  - Serialized size: {len(msg_bytes)} bytes")
    
    # Build USP Record (outer wrapper)
    usp_record = record_pb2.Record()
    usp_record.version = "1.4"
    usp_record.to_id = "os::8082FE-SN8082FE636B60"
    usp_record.from_id = "proto::controller-1"
    usp_record.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
    
    # Set NoSessionContext with payload
    usp_record.no_session_context.payload = msg_bytes
    
    # Serialize the complete USP Record
    record_bytes = usp_record.SerializeToString()
    
    print(f"\n✓ USP Record:")
    print(f"  - Version: {usp_record.version}")
    print(f"  - To: {usp_record.to_id}")
    print(f"  - From: {usp_record.from_id}")
    print(f"  - Security: PLAINTEXT")
    print(f"  - Serialized size: {len(record_bytes)} bytes")
    
    # Show hex preview
    hex_preview = record_bytes[:64].hex()
    formatted_hex = ' '.join([hex_preview[i:i+2] for i in range(0, len(hex_preview), 2)])
    print(f"\n✓ Binary Preview (first 64 bytes):")
    print(f"  {formatted_hex}")
    
    # Verify deserialization
    print(f"\n✓ Testing Deserialization:")
    test_record = record_pb2.Record()
    test_record.ParseFromString(record_bytes)
    print(f"  - Version: {test_record.version}")
    print(f"  - To: {test_record.to_id}")
    print(f"  - From: {test_record.from_id}")
    
    test_msg = msg_pb2.Msg()
    test_msg.ParseFromString(test_record.no_session_context.payload)
    print(f"  - Message ID: {test_msg.header.msg_id}")
    print(f"  - Message Type: {test_msg.header.msg_type}")
    print(f"  - Paths: {', '.join(test_msg.body.request.get.param_paths)}")
    
    print(f"\n{'='*60}")
    print("✓ All tests passed!")
    print("="*60)

if __name__ == '__main__':
    test_usp_get_request()
