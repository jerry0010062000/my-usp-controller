import socket
import time
import uuid
import sys
import usp_record_1_4_pb2 as record_pb2
import usp_msg_1_4_pb2 as msg_pb2

BROKER_HOST = '127.0.0.1'
BROKER_PORT = 61613
USERNAME = 'admin'
PASSWORD = 'password'
MY_ID = 'proto::controller-1'
MY_QUEUE = f'/queue/{MY_ID}'

def run():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((BROKER_HOST, BROKER_PORT))
    
    # STOMP CONNECT
    connect_frame = f"CONNECT\naccept-version:1.2\nhost:/\nlogin:{USERNAME}\npasscode:{PASSWORD}\n\n\x00"
    sock.sendall(connect_frame.encode())
    
    resp = sock.recv(4096)
    if b'CONNECTED' not in resp:
        print("STOMP Connect Failed")
        return

    # SUBSCRIBE
    sub_frame = f"SUBSCRIBE\nid:sub-1\ndestination:{MY_QUEUE}\nack:auto\n\n\x00"
    sock.sendall(sub_frame.encode())
    
    # 針對 proto::agent-id (已知有回應)
    target_id = "proto::agent-id"
    target_dest = "/topic/agent-path"
    
    print(f"Targeting {target_id}...")
    
    # GetSupportedDM
    usp_msg = msg_pb2.Msg()
    usp_msg.header.msg_id = str(uuid.uuid4())
    usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_SUPPORTED_DM
    
    req = usp_msg.body.request.get_supported_dm
    req.obj_paths.append("Device.")
    req.first_level_only = False
    req.return_commands = True
    req.return_events = True
    req.return_params = True
    
    rec = record_pb2.Record()
    rec.version = "1.4"
    rec.to_id = target_id
    rec.from_id = MY_ID
    rec.no_session_context.payload = usp_msg.SerializeToString()
    
    body = rec.SerializeToString()
    headers = (
        f"SEND\n"
        f"destination:{target_dest}\n"
        f"content-type:application/vnd.bbf.usp.msg\n"
        f"content-length:{len(body)}\n"
        f"reply-to-dest:{MY_QUEUE}\n\n"
    )
    sock.sendall(headers.encode() + body + b'\x00')
    
    print(f"Waiting for response...")
    all_paths = set()
    
    start_wait = time.time()
    sock.settimeout(1.0)
    while time.time() - start_wait < 5:
        try:
            data = b''
            # 簡單的讀取迴圈，確保讀到 NULL
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                data += chunk
                if b'\x00' in data: break
            
            if b'MESSAGE' in data:
                parts = data.split(b'\n\n', 1)
                if len(parts) < 2: continue
                payload = parts[1].split(b'\x00')[0]
                
                resp_rec = record_pb2.Record()
                resp_rec.ParseFromString(payload)
                
                if resp_rec.HasField('no_session_context'):
                    resp_msg = msg_pb2.Msg()
                    resp_msg.ParseFromString(resp_rec.no_session_context.payload)
                    
                    if resp_msg.body.HasField('response') and resp_msg.body.response.HasField('get_supported_dm_resp'):
                        print(f"Received Response!")
                        for obj in resp_msg.body.response.get_supported_dm_resp.obj_results:
                            path = obj.data_model_path
                            all_paths.add(path)
                            for p in obj.supported_params:
                                all_paths.add(path + p.param_name)
                            for c in obj.supported_commands:
                                all_paths.add(path + c.command_name + "()")
                            for e in obj.supported_events:
                                all_paths.add(path + e.event_name + "!")
                        break # Got it
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error: {e}")
            break
            
    if all_paths:
        print("\n--- Data Model Summary ---")
        for p in sorted(list(all_paths)):
            print(p)
        print(f"\nTotal Data Model items: {len(all_paths)}")
    else:
        print("\nFailed to retrieve data model.")

if __name__ == "__main__":
    run()