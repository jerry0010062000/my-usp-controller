#!/usr/bin/env python3
import socket
import sys
import json
import time

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

def send_cmd(cmd):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((IPC_HOST, IPC_PORT))
        sock.sendall(cmd.encode('utf-8'))
        response = sock.recv(4096).decode('utf-8')
        sock.close()
        return json.loads(response)
    except Exception as e:
        return {"status": "error", "msg": str(e)}

def main():
    if len(sys.argv) < 2:
        print("Usage: trigger <cmd> [args]")
        sys.exit(1)
        
    cmd = " ".join(sys.argv[1:])
    resp = send_cmd(cmd)
    print(json.dumps(resp, indent=2))

if __name__ == "__main__":
    main()
