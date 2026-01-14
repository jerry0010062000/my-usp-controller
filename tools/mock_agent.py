#!/usr/bin/env python3
import socket
import time
import sys
import uuid
import usp_record_1_4_pb2 as record_pb2
import usp_msg_1_4_pb2 as msg_pb2

# Configuration
BROKER_HOST = '127.0.0.1'
BROKER_PORT = 61613
CONTROLLER_TOPIC = '/queue/proto::controller-1' # Send TO controller
AGENTS = [
    {'id': 'proto::agent-001', 'queue': '/queue/proto::agent-001'},
    {'id': 'proto::agent-002', 'queue': '/queue/proto::agent-002'},
    {'id': 'os::home-gateway', 'queue': '/queue/os::home-gateway'}
]

def connect_stomp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((BROKER_HOST, BROKER_PORT))
    
    connect_frame = (
        "CONNECT\n"
        "accept-version:1.2\n"
        "host:/\n"
        "login:admin\n"
        "passcode:password\n"
        "\n\0"
    )
    sock.sendall(connect_frame.encode('utf-8'))
    
    response = sock.recv(4096)
    if b'CONNECTED' in response:
        return sock
    return None

def build_boot_msg(agent_id, controller_id='proto::controller-1'):
    # Build USP Message (Boot Notification)
    usp_msg = msg_pb2.Msg()
    usp_msg.header.msg_id = str(uuid.uuid4())
    usp_msg.header.msg_type = msg_pb2.Header.MsgType.NOTIFY
    
    # Simple Boot Notify
    notify = usp_msg.body.request.notify
    notify.send_resp = False
    notify.subscription_id = "boot-1"
    evt = notify.event
    evt.obj_path = "Device.Boot!"
    evt.event_name = "Boot"
    
    msg_bytes = usp_msg.SerializeToString()
    
    # Build Record
    usp_record = record_pb2.Record()
    usp_record.version = "1.4"
    usp_record.to_id = controller_id
    usp_record.from_id = agent_id
    usp_record.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
    usp_record.no_session_context.payload = msg_bytes
    
    return usp_record.SerializeToString()

def build_get_resp(msg_id, agent_id, controller_id):
    # Build USP Get Response
    usp_msg = msg_pb2.Msg()
    usp_msg.header.msg_id = msg_id
    usp_msg.header.msg_type = msg_pb2.Header.MsgType.GET_RESP
    
    get_resp = usp_msg.body.response.get_resp
    
    # Add fake data
    req_result = get_resp.req_path_results.add()
    req_result.requested_path = "Device."
    req_result.err_code = 0
    
    res_result = req_result.resolved_path_results.add()
    res_result.resolved_path = "Device.DeviceInfo."
    res_result.result_params["Manufacturer"] = "GeminiCorp"
    res_result.result_params["ModelName"] = "VirtualAgent-2000"
    res_result.result_params["SerialNumber"] = agent_id.split("::")[-1]
    
    msg_bytes = usp_msg.SerializeToString()
    
    # Build Record
    usp_record = record_pb2.Record()
    usp_record.version = "1.4"
    usp_record.to_id = controller_id
    usp_record.from_id = agent_id
    usp_record.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
    usp_record.no_session_context.payload = msg_bytes
    
    return usp_record.SerializeToString()

def main():
    sock = connect_stomp()
    if not sock:
        print("Failed to connect to broker")
        sys.exit(1)
        
    print("Connected to broker. Simulating agents...")
    
    # 1. Send Boot Notifications (Greeting)
    for agent in AGENTS:
        print(f"Agent {agent['id']} sending Boot Notification...")
        
        body_bytes = build_boot_msg(agent['id'])
        
        # Construct STOMP SEND frame with reply-to-dest
        # This matches what usp_controller looks for
        headers = (
            f"SEND\n"
            f"destination:{CONTROLLER_TOPIC}\n"
            f"content-type:application/vnd.bbf.usp.msg\n"
            f"content-length:{len(body_bytes)}\n"
            f"reply-to-dest:{agent['queue']}\n" 
            f"\n"
        )
        
        frame = headers.encode('utf-8') + body_bytes + b'\0'
        sock.sendall(frame)
        time.sleep(0.5)

    print("Boot notifications sent. Listening for Get requests...")
    
    # 2. Listen for GET requests and reply
    # Note: In a real scenario each agent would listen on its own socket/queue.
    # Here we simplify by using one socket subscribed to all agent queues.
    
    for agent in AGENTS:
        sub_frame = f"SUBSCRIBE\nid:{agent['id']}\ndestination:{agent['queue']}\nack:auto\n\n\0"
        sock.sendall(sub_frame.encode('utf-8'))
        
    start_time = time.time()
    while time.time() - start_time < 10: # Run for 10 seconds
        data = sock.recv(4096)
        if not data:
            break
            
        if b'SEND' in data or b'MESSAGE' in data:
            # Simple parsing to find which agent is targeted
            # (In reality we'd parse the protobuf)
            
            # Find destination header
            headers_part = data.split(b'\n\n')[0].decode('utf-8', errors='ignore')
            dest = ""
            for line in headers_part.split('\n'):
                if line.startswith('destination:'):
                    dest = line.split(':')[1].strip()
            
            # Find matching agent
            target_agent = next((a for a in AGENTS if a['queue'] == dest), None)
            
            if target_agent:
                print(f"Received request for {target_agent['id']}")
                
                # Extract msg_id from incoming request (very rough parsing for mock)
                # In real app, parse protobuf. Here, just generate a new response.
                
                resp_bytes = build_get_resp(str(uuid.uuid4()), target_agent['id'], "proto::controller-1")
                
                # Send Response back to Controller
                # Note: The controller replies to Reply-To, which is set to... wait, 
                # Controller sends TO agent. Agent replies TO Controller.
                # Controller listens on /queue/proto::controller-1
                
                resp_headers = (
                    f"SEND\n"
                    f"destination:{CONTROLLER_TOPIC}\n"
                    f"content-type:application/vnd.bbf.usp.msg\n"
                    f"content-length:{len(resp_bytes)}\n"
                    f"\n"
                )
                
                frame = resp_headers.encode('utf-8') + resp_bytes + b'\0'
                sock.sendall(frame)
                print(f"Sent response from {target_agent['id']}")

    sock.close()

if __name__ == "__main__":
    main()
