
import socket
import time
import uuid
import sys
import json
import threading

# Import USP protobuf definitions
import usp_record_1_4_pb2 as record_pb2
import usp_msg_1_4_pb2 as msg_pb2

BROKER_HOST = '127.0.0.1'
BROKER_PORT = 61613
USERNAME = 'admin'
PASSWORD = 'password'
CONTROLLER_ENDPOINT_ID = 'proto::controller-temp' # Use a different ID to avoid conflict
REPLY_TO_QUEUE = f'/queue/{CONTROLLER_ENDPOINT_ID}'

AGENT_ENDPOINT_ID = 'os::8082FE-SN8082FE636B60' # Primary candidate

class STOMPCollector:
    def __init__(self):
        self.sock = None
        self.connected = False
        self.results = []
        self.finished = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((BROKER_HOST, BROKER_PORT))
        
        connect_frame = (
            f"CONNECT\n"
            f"accept-version:1.2\n"
            f"host:/\n"
            f"login:{USERNAME}\n"
            f"passcode:{PASSWORD}\n"
            f"heart-beat:0,0\n"
            f"\n\0"
        )
        self.sock.sendall(connect_frame.encode('utf-8'))
        
        resp = self._recv_frame()
        if b'CONNECTED' in resp:
            self.connected = True
            # Subscribe to reply queue
            sub_frame = (
                f"SUBSCRIBE\n"
                f"id:sub-0\n"
                f"destination:{REPLY_TO_QUEUE}\n"
                f"ack:auto\n"
                f"\n\0"
            )
            self.sock.sendall(sub_frame.encode('utf-8'))
            return True
        return False

    def _recv_frame(self):
        buffer = b''
        while True:
            chunk = self.sock.recv(4096)
            if not chunk: break
            buffer += chunk
            if b'\0' in buffer:
                break
        return buffer

    def send_get(self, endpoint, path):
        msg_id = str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = msg_id
        usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET
        usp_msg.body.request.get.param_paths.append(path)
        
        msg_bytes = usp_msg.SerializeToString()
        
        usp_rec = record_pb2.Record()
        usp_rec.version = "1.4"
        usp_rec.to_id = endpoint
        usp_rec.from_id = CONTROLLER_ENDPOINT_ID
        usp_rec.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
        usp_rec.no_session_context.payload = msg_bytes
        
        rec_bytes = usp_rec.SerializeToString()
        
        # We need to know where to send it. Usually /topic/agent or /queue/agent-id
        # From devices.json, os::8082FE-SN8082FE636B60 -> /topic/usp/endpoint/os::8082FE-SN8082FE636B60
        destination = f"/topic/usp/endpoint/{endpoint}"
        
        headers = [
            f"SEND",
            f"destination:{destination}",
            f"content-type:application/vnd.bbf.usp.msg",
            f"content-length:{len(rec_bytes)}",
            f"reply-to-dest:{REPLY_TO_QUEUE}"
        ]
        frame = '\n'.join(headers).encode('utf-8') + b'\n\n' + rec_bytes + b'\0'
        self.sock.sendall(frame)

    def listen(self, timeout=10):
        start_time = time.time()
        self.sock.settimeout(1.0)
        while time.time() - start_time < timeout:
            try:
                frame = self._recv_frame()
                if not frame: break
                if b'MESSAGE' in frame:
                    # Parse USP
                    if b'\n\n' in frame:
                        body = frame.split(b'\n\n', 1)[1].rstrip(b'\0')
                        rec = record_pb2.Record()
                        rec.ParseFromString(body)
                        if rec.HasField('no_session_context'):
                            msg = msg_pb2.Msg()
                            msg.ParseFromString(rec.no_session_context.payload)
                            if msg.body.HasField('response') and msg.body.response.HasField('get_resp'):
                                for r in msg.body.response.get_resp.req_path_results:
                                    for res in r.resolved_path_results:
                                        for p, v in res.result_params.items():
                                            self.results.append((res.resolved_path + p, v))
                                self.finished = True
                                return
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error: {e}")
                break

collector = STOMPCollector()
if collector.connect():
    print(f"Connected. Sending GET to {AGENT_ENDPOINT_ID}...")
    collector.send_get(AGENT_ENDPOINT_ID, "Device.")
    collector.listen(timeout=15)
    
    if not collector.results:
        # Try the other agent
        print("No results from first agent, trying proto::agent-id...")
        collector.send_get("proto::agent-id", "Device.")
        collector.listen(timeout=10)

    print(f"Total parameters found: {len(collector.results)}")
    for path, val in collector.results:
        print(f"{path} = {val}")
    
    print(f"\nSummary: Found {len(collector.results)} parameters.")
else:
    print("Failed to connect to STOMP broker")
