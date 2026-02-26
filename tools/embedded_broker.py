#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Embedded Lightweight STOMP Broker
For development/testing only - Use ActiveMQ/RabbitMQ in production

Features:
- Simple STOMP 1.2 protocol support
- Topics and Queues support
- In-memory message storage
- Suitable for standalone testing

Usage:
    python tools/embedded_broker.py
    or
    from tools.embedded_broker import EmbeddedBroker
    broker = EmbeddedBroker(port=61613)
    broker.start()
"""

import socket
import threading
import time
import sys
from collections import defaultdict
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class StompFrame:
    """STOMP frame"""
    command: str
    headers: Dict[str, str]
    body: bytes


class Client:
    """Client connection"""
    def __init__(self, conn: socket.socket, addr):
        self.conn = conn
        self.addr = addr
        self.subscriptions: Dict[str, str] = {}  # subscription_id -> destination
        self.session_id = f"session-{id(self)}"
        self.connected = False
        
    def send_frame(self, frame: StompFrame):
        """Send STOMP frame"""
        try:
            lines = [frame.command]
            for key, value in frame.headers.items():
                lines.append(f"{key}:{value}")
            lines.append("")
            
            message = "\n".join(lines).encode() + frame.body + b"\x00"
            self.conn.sendall(message)
            return True
        except Exception as e:
            logger.error(f"Failed to send frame: {e}")
            return False


class EmbeddedBroker:
    """
    Embedded STOMP Broker
    
    WARNING: This is a simplified implementation for development/testing only!
    Use mature message brokers (ActiveMQ, RabbitMQ, etc.) in production
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 61613):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        
        # Storage
        self.clients: List[Client] = []
        self.destinations: Dict[str, List[bytes]] = defaultdict(list)  # Message queues
        self.subscribers: Dict[str, Set[Client]] = defaultdict(set)   # Subscribers
        
        # Thread safety
        self.lock = threading.RLock()
        
        logger.warning("WARNING: Using embedded Broker (for development/testing only)")
        logger.warning("WARNING: Use ActiveMQ or RabbitMQ in production")
    
    @staticmethod
    def is_port_available(port: int, host: str = "0.0.0.0") -> bool:
        """Check if port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                return True
        except OSError:
            return False
    
    @staticmethod
    def find_process_on_port(port: int) -> str:
        """Find process using the port (Windows)"""
        try:
            import subprocess
            result = subprocess.run(
                f'netstat -ano | findstr :{port}',
                shell=True,
                capture_output=True,
                text=True
            )
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                if lines:
                    # Extract PID
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        # Get process name
                        name_result = subprocess.run(
                            f'tasklist /FI "PID eq {pid}" /NH',
                            shell=True,
                            capture_output=True,
                            text=True
                        )
                        if name_result.stdout:
                            process_name = name_result.stdout.split()[0]
                            return f"PID {pid} ({process_name})"
            return "Unknown process"
        except Exception:
            return "Cannot detect"
    
    def start(self):
        """Start broker"""
        if self.running:
            logger.warning("Broker already running")
            return
        
        # Check if port is available
        if not self.is_port_available(self.port, self.host):
            process_info = self.find_process_on_port(self.port)
            error_msg = (
                f"ERROR: Port {self.port} is already in use!\n"
                f"Process using port: {process_info}\n\n"
                f"Solutions:\n"
                f"1. Kill the process using the port:\n"
                f"   netstat -ano | findstr :{self.port}\n"
                f"   taskkill /PID <PID> /F\n\n"
                f"2. Use a different port\n"
                f"3. Run as administrator\n"
            )
            logger.error(error_msg)
            raise OSError(f"Port {self.port} unavailable (possibly used by {process_info})")
        
        self.running = True
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Windows specific: Set SO_EXCLUSIVEADDRUSE to prevent other processes
            if sys.platform == 'win32':
                try:
                    # SO_EXCLUSIVEADDRUSE = 0x0004
                    self.server_socket.setsockopt(socket.SOL_SOCKET, 0x0004, 1)
                except:
                    pass  # Ignore if not supported
            
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
        
        except PermissionError as e:
            self.running = False
            error_msg = (
                f"ERROR: Permission denied (WinError 10013)\n\n"
                f"Reason: No permission to bind port {self.port}\n\n"
                f"Solutions:\n"
                f"1. Run as administrator\n"
                f"2. Use port > 1024 (current: {self.port})\n"
                f"3. Check firewall settings\n"
            )
            logger.error(error_msg)
            raise PermissionError(error_msg) from e
        
        except OSError as e:
            self.running = False
            if e.errno == 10013 or 'WinError 10013' in str(e):
                process_info = self.find_process_on_port(self.port)
                error_msg = (
                    f"ERROR: Port access denied (WinError 10013)\n\n"
                    f"Port {self.port} may be in use or restricted\n"
                    f"Process using port: {process_info}\n\n"
                    f"Solutions:\n"
                    f"1. Run as administrator\n"
                    f"2. Kill the process: taskkill /PID <PID> /F\n"
                    f"3. Use different port (e.g. 61614)\n"
                    f"4. Check firewall settings\n"
                )
                logger.error(error_msg)
                raise OSError(error_msg) from e
            else:
                logger.error(f"Failed to start broker: {e}")
                raise
        
        logger.info(f"✅ Embedded STOMP Broker started on {self.host}:{self.port}")
        logger.info(f"📌 Clients can connect to: stomp://{self.host}:{self.port}")
        
        # Start accept connection thread
        accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
        accept_thread.start()
    
    def stop(self):
        """stop broker"""
        logger.info("Stopping broker...")
        self.running = False
        
        # Close all clients
        with self.lock:
            for client in self.clients:
                try:
                    client.conn.close()
                except:
                    pass
        
        # Close server
        if self.server_socket:
            self.server_socket.close()
        
        logger.info("✅ Broker stopped")
    
    def _accept_connections(self):
        """Accept client connections"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                logger.info(f"📥 New connection from {addr}")
                
                client = Client(conn, addr)
                
                with self.lock:
                    self.clients.append(client)
                
                # Create handler thread for each client
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client,),
                    daemon=True
                )
                client_thread.start()
                
            except Exception as e:
                if self.running:
                    logger.error(f"Error accepting connection: {e}")
    
    def _handle_client(self, client: Client):
        """Handle client messages"""
        buffer = b""
        
        try:
            while self.running and client.connected or not client.connected:
                data = client.conn.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Parse frame（with \x00 terminator）
                while b"\x00" in buffer:
                    frame_data, buffer = buffer.split(b"\x00", 1)
                    
                    frame = self._parse_frame(frame_data)
                    if frame:
                        self._process_frame(client, frame)
        
        except Exception as e:
            logger.error(f"Error handling client {client.addr}: {e}")
        
        finally:
            self._disconnect_client(client)
    
    def _parse_frame(self, data: bytes) -> Optional[StompFrame]:
        """Parse STOMP frame"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\n')
            
            if not lines:
                return None
            
            command = lines[0].strip()
            headers = {}
            body_start = 1
            
            # Parse headers
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Parse body
            body = '\n'.join(lines[body_start:]).encode()
            
            return StompFrame(command, headers, body)
        
        except Exception as e:
            logger.error(f"Failed to parse frame: {e}")
            return None
    
    def _process_frame(self, client: Client, frame: StompFrame):
        """Handle STOMP frame"""
        command = frame.command.upper()
        
        if command == "CONNECT" or command == "STOMP":
            self._handle_connect(client, frame)
        elif command == "SUBSCRIBE":
            self._handle_subscribe(client, frame)
        elif command == "UNSUBSCRIBE":
            self._handle_unsubscribe(client, frame)
        elif command == "SEND":
            self._handle_send(client, frame)
        elif command == "DISCONNECT":
            self._handle_disconnect(client)
        else:
            logger.warning(f"Unknown command: {command}")
    
    def _handle_connect(self, client: Client, frame: StompFrame):
        """Handle CONNECT"""
        client.connected = True
        
        response = StompFrame(
            "CONNECTED",
            {
                "version": "1.2",
                "session": client.session_id,
                "server": "EmbeddedBroker/1.0"
            },
            b""
        )
        
        client.send_frame(response)
        logger.info(f"✅ Client {client.addr} connected (session: {client.session_id})")
    
    def _handle_subscribe(self, client: Client, frame: StompFrame):
        """Handle SUBSCRIBE"""
        destination = frame.headers.get("destination")
        sub_id = frame.headers.get("id", str(id(client)))
        
        if not destination:
            logger.warning("SUBSCRIBE without destination")
            return
        
        with self.lock:
            client.subscriptions[sub_id] = destination
            self.subscribers[destination].add(client)
        
        logger.info(f"📬 Client {client.addr} subscribed to {destination}")
        
        # Send queued messages（if any）
        self._deliver_queued_messages(destination, client)
    
    def _handle_unsubscribe(self, client: Client, frame: StompFrame):
        """Handle UNSUBSCRIBE"""
        sub_id = frame.headers.get("id")
        
        if sub_id and sub_id in client.subscriptions:
            destination = client.subscriptions.pop(sub_id)
            
            with self.lock:
                if client in self.subscribers[destination]:
                    self.subscribers[destination].remove(client)
            
            logger.info(f"📭 Client {client.addr} unsubscribed from {destination}")
    
    def _handle_send(self, client: Client, frame: StompFrame):
        """Handle SEND"""
        destination = frame.headers.get("destination")
        
        if not destination:
            logger.warning("SEND without destination")
            return
        
        logger.info(f"📤 Message to {destination} from {client.addr}")
        
        # Distribute message to subscribers
        with self.lock:
            subscribers = list(self.subscribers.get(destination, []))
            
            if subscribers:
                # has subscribers，send directly
                for subscriber in subscribers:
                    self._send_message_to_client(subscriber, destination, frame.body)
            else:
                # no subscribers，Store message（Queue mode）
                self.destinations[destination].append(frame.body)
                logger.debug(f"📦 Message queued for {destination}")
    
    def _send_message_to_client(self, client: Client, destination: str, body: bytes):
        """Send message to client"""
        message_frame = StompFrame(
            "MESSAGE",
            {
                "destination": destination,
                "message-id": str(time.time()),
                "subscription": list(client.subscriptions.keys())[0] if client.subscriptions else "0"
            },
            body
        )
        
        client.send_frame(message_frame)
    
    def _deliver_queued_messages(self, destination: str, client: Client):
        """Deliver queued messages"""
        with self.lock:
            messages = self.destinations.get(destination, [])
            
            for message in messages:
                self._send_message_to_client(client, destination, message)
            
            # clear queue
            if destination in self.destinations:
                self.destinations[destination].clear()
    
    def _handle_disconnect(self, client: Client):
        """Handle DISCONNECT"""
        self._disconnect_client(client)
    
    def _disconnect_client(self, client: Client):
        """Disconnect client"""
        logger.info(f"👋 Client {client.addr} disconnected")
        
        with self.lock:
            # Remove subscription
            for destination in client.subscriptions.values():
                if client in self.subscribers[destination]:
                    self.subscribers[destination].remove(client)
            
            # Remove client
            if client in self.clients:
                self.clients.remove(client)
        
        try:
            client.conn.close()
        except:
            pass


def main():
    """Command-line startup"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Embedded STOMP Broker (for development/testing)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=61613, help="Listen port")
    
    args = parser.parse_args()
    
    broker = EmbeddedBroker(host=args.host, port=args.port)
    broker.start()
    
    try:
        print("\n" + "="*60)
        print("  Embedded STOMP Broker Started")
        print("  WARNING: For development/testing only - Use professional broker in production")
        print("="*60)
        print(f"\nConnection: stomp://{args.host}:{args.port}")
        print("Press Ctrl+C to stop\n")
        
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\nStopping Broker...")
        broker.stop()


if __name__ == "__main__":
    main()
