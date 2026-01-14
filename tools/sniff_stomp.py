
import socket
import time

BROKER_HOST = '127.0.0.1'
BROKER_PORT = 61613
USERNAME = 'admin'
PASSWORD = 'password'

def sniff():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((BROKER_HOST, BROKER_PORT))
    
    connect_frame = (
        f"CONNECT\n"
        f"accept-version:1.2\n"
        f"host: /\n"
        f"login:{USERNAME}\n"
        f"passcode:{PASSWORD}\n"
        f"heart-beat:0,0\n"
        f"\n\0"
    )
    sock.sendall(connect_frame.encode('utf-8'))
    
    # Wait for CONNECTED
    buf = sock.recv(4096)
    if b'CONNECTED' not in buf:
        print("Failed to connect")
        return

    # Subscribe to wildcards
    for dest in ["/topic/>", "/queue/>"]:
        sub_frame = f"SUBSCRIBE\nid:{dest}\ndestination:{dest}\nack:auto\n\n\0"
        sock.sendall(sub_frame.encode('utf-8'))
    
    print("Sniffing for 5 seconds...")
    start = time.time()
    sock.settimeout(1.0)
    while time.time() - start < 5:
        try:
            data = sock.recv(4096)
            if data:
                print(f"Captured {len(data)} bytes")
                # Try to see if it's USP
                if b'MESSAGE' in data:
                    header = data.split(b'\n\n')[0].decode('utf-8', errors='ignore')
                    dest = "unknown"
                    for line in header.split('\n'):
                        if line.startswith('destination:'):
                            dest = line.split(':')[1].strip()
                    print(f"  Destination: {dest}")
        except socket.timeout:
            continue
    sock.close()

if __name__ == "__main__":
    sniff()
