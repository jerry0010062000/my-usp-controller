#!/usr/bin/env python3
import usp_record_1_4_pb2 as record_pb2
import sys

hex_data = "0a03312e33121370726f746f3a3a636f6e74726f6c6c65722d311a196f733a3a3830383246452d534e3830383246453633364236303a8b011288010a280a2430643662373639622d633964332d343762612d386531622d3139313465366635386239341002125c125a0a580a560a124465766963652e446576696365496e666f2e15721b"

try:
    data = bytes.fromhex(hex_data)
    print(f"Data length: {len(data)}")
    
    rec = record_pb2.Record()
    rec.ParseFromString(data)
    print("Parsed successfully!")
    print(rec)
except Exception as e:
    print(f"Parse error: {e}")
