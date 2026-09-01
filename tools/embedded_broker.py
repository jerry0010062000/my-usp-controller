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
import io
import os
from collections import defaultdict
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass
import logging

# Force UTF-8 encoding on Windows to avoid CP950 UnicodeEncodeError
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

def _safe_print(text: str = ""):
    """Safe print with CP950 encoding fallback"""
    try:
        print(text)
    except (UnicodeEncodeError, Exception):
        try:
            cleaned = text.encode('ascii', errors='replace').decode('ascii')
            print(cleaned)
        except Exception:
            pass

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
            header_lines = [frame.command]
            for key, value in frame.headers.items():
                header_lines.append(f"{key}:{value}")

            # STOMP frame format requires a blank line between headers and body.
            # Use explicit "\n\n" separator for strict clients (e.g., obuspa).
            header_blob = "\n".join(header_lines) + "\n\n"
            message = header_blob.encode('utf-8') + frame.body + b"\x00"
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
    
    def __init__(self, host: str = "0.0.0.0", port: int = 61613, log_callback: Optional[Callable[[str], None]] = None):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.log_callback = log_callback
        
        # Storage
        self.clients: List[Client] = []
        self.destinations: Dict[str, List[StompFrame]] = defaultdict(list)  # Queued STOMP frames by destination
        self.subscribers: Dict[str, Set[Client]] = defaultdict(set)   # Subscribers
        
        # Thread safety
        self.lock = threading.RLock()
        
        logger.warning("WARNING: Using embedded Broker (for development/testing only)")
        logger.warning("WARNING: Use ActiveMQ or RabbitMQ in production")

    def _emit_debug(self, message: str):
        """Emit broker debug message to logger and optional GUI callback."""
        try:
            logger.info(message)
        except Exception:
            pass

        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass
    
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

    @staticmethod
    def kill_process_on_port(port: int, exclude_pid: Optional[int] = None) -> bool:

        """Terminate any processes holding the specified port on Windows."""
        try:
            import subprocess
            res = subprocess.run(f'netstat -ano | findstr :{port}', shell=True, capture_output=True, text=True)
            killed = False
            if res.stdout:
                for line in res.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 5 and ('LISTENING' in line or 'ESTABLISHED' in line):
                        pid_str = parts[-1]
                        if pid_str.isdigit():
                            pid = int(pid_str)
                            if exclude_pid is None or pid != exclude_pid:
                                subprocess.run(f'taskkill /F /PID {pid}', shell=True, capture_output=True)
                                killed = True
            return killed
        except Exception:
            return False

    def start(self, started_callback=None):
        """Start broker"""
        if self.running:
            logger.warning("Broker already running")
            if started_callback:
                started_callback()
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
            raise OSError(f"Port {self.port} unavailable (currently used by {process_info})")
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True

            if started_callback:
                try:
                    started_callback()
                except Exception:
                    pass
        
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
            process_info = self.find_process_on_port(self.port)
            error_msg = f"Port {self.port} bind failed: {e} (Process on port: {process_info})"
            logger.error(error_msg)
            raise OSError(error_msg) from e
        
        logger.info(f"[OK] Embedded STOMP Broker started on {self.host}:{self.port}")
        logger.info(f"[INFO] Clients can connect to: stomp://{self.host}:{self.port}")

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

        logger.info("[OK] Broker stopped")

    def _accept_connections(self):
        """Accept client connections"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                logger.info(f"[CONN] New connection from {addr}")
                self._emit_debug(f"[CONN] New TCP client {addr}")

                
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

                self._emit_debug(f"[RX] {client.addr} {len(data)} bytes")
                
                buffer += data
                
                # Parse complete STOMP frames from buffer
                while True:
                    frame_data, consumed = self._extract_frame_from_buffer(buffer)
                    if frame_data is None:
                        break

                    buffer = buffer[consumed:]
                    frame = self._parse_frame(frame_data)
                    if frame:
                        self._emit_debug(f"[FRAME] {client.addr} -> {frame.command} headers={len(frame.headers)} body={len(frame.body)}")
                        self._process_frame(client, frame)
        
        except Exception as e:
            logger.error(f"Error handling client {client.addr}: {e}")
        
        finally:
            self._disconnect_client(client)
    
    def _parse_frame(self, data: bytes) -> Optional[StompFrame]:
        """Parse STOMP frame supporting both CRLF and LF header separators"""
        try:
            if not data:
                return None

            header_end_crlf = data.find(b'\r\n\r\n')
            header_end_lf = data.find(b'\n\n')

            if header_end_crlf >= 0 and (header_end_lf < 0 or header_end_crlf < header_end_lf):
                header_blob = data[:header_end_crlf]
                body = data[header_end_crlf + 4:]
            elif header_end_lf >= 0:
                header_blob = data[:header_end_lf]
                body = data[header_end_lf + 2:]
            else:
                # Heartbeat or malformed frame without body separator
                header_blob = data
                body = b''

            header_lines = header_blob.split(b'\n')
            if not header_lines:
                return None

            command = header_lines[0].decode('utf-8', errors='ignore').strip().rstrip('\r')
            if not command:
                return None

            headers = {}
            for raw_line in header_lines[1:]:
                line = raw_line.decode('utf-8', errors='ignore').rstrip('\r')
                if not line.strip():
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            return StompFrame(command, headers, body)
        
        except Exception as e:
            logger.error(f"Failed to parse frame: {e}")
            return None

    def _extract_frame_from_buffer(self, buffer: bytes):
        """Extract one complete STOMP frame from buffer supporting both CRLF and LF.

        Returns (frame_bytes_without_null, consumed_bytes) or (None, 0) if incomplete.
        """
        if not buffer:
            return None, 0

        # Discard leading heartbeat newlines or null bytes
        stripped_idx = 0
        while stripped_idx < len(buffer) and buffer[stripped_idx] in (10, 13, 0):
            stripped_idx += 1
        if stripped_idx > 0:
            buffer = buffer[stripped_idx:]
            if not buffer:
                return None, stripped_idx

        header_end_crlf = buffer.find(b'\r\n\r\n')
        header_end_lf = buffer.find(b'\n\n')

        if header_end_crlf >= 0 and (header_end_lf < 0 or header_end_crlf < header_end_lf):
            header_end = header_end_crlf
            body_start = header_end + 4
        elif header_end_lf >= 0:
            header_end = header_end_lf
            body_start = header_end + 2
        else:
            return None, stripped_idx

        header_bytes = buffer[:header_end]
        header_text = header_bytes.decode('utf-8', errors='ignore')

        content_length = None
        for line in header_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                if key.strip().lower() == 'content-length':
                    try:
                        content_length = int(value.strip())
                    except Exception:
                        content_length = None
                    break

        if content_length is not None and content_length >= 0:
            required = body_start + content_length + 1  # include trailing NULL
            if len(buffer) < required:
                return None, stripped_idx

            if buffer[required - 1] != 0:
                # malformed frame or no null; accept body as-is if null is right after
                frame_bytes = buffer[:body_start + content_length]
                return frame_bytes, stripped_idx + body_start + content_length + (1 if len(buffer) > body_start + content_length and buffer[body_start + content_length] == 0 else 0)

            frame_bytes = buffer[:required - 1]  # exclude trailing NULL
            return frame_bytes, stripped_idx + required

        # No content-length: use NULL terminator
        null_pos = buffer.find(b'\x00', body_start)
        if null_pos < 0:
            return None, stripped_idx

        frame_bytes = buffer[:null_pos]
        return frame_bytes, stripped_idx + null_pos + 1
    
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
            self._emit_debug(f"[WARN] Unknown command from {client.addr}: {command}")
    
    def _handle_connect(self, client: Client, frame: StompFrame):
        """Handle CONNECT"""
        login = frame.headers.get("login", "")
        passcode = frame.headers.get("passcode", "")
        accept_version = frame.headers.get("accept-version", "")
        heartbeat = frame.headers.get("heart-beat", "")

        masked_passcode = "***" if passcode else ""
        self._emit_debug(
            f"[HANDSHAKE] CONNECT from {client.addr} "
            f"login={login!r} passcode={masked_passcode!r} "
            f"accept-version={accept_version!r} heart-beat={heartbeat!r}"
        )

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
        
        if client.send_frame(response):
            logger.info(f"[OK] Client {client.addr} connected (session: {client.session_id})")
            self._emit_debug(f"[HANDSHAKE] CONNECTED sent to {client.addr} session={client.session_id}")
        else:
            self._emit_debug(f"[HANDSHAKE] Failed sending CONNECTED to {client.addr}")

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

        logger.info(f"[SUB] Client {client.addr} subscribed to {destination}")

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

            logger.info(f"[UNSUB] Client {client.addr} unsubscribed from {destination}")

    def _handle_send(self, client: Client, frame: StompFrame):
        """Handle SEND"""
        destination = frame.headers.get("destination")

        if not destination:
            logger.warning("SEND without destination")
            return

        logger.info(f"[TX] Message to {destination} from {client.addr}")


        # Preserve sender-provided headers when relaying to subscribers.
        # Remove destination because MESSAGE destination is set explicitly.
        relay_headers = {}
        for key, value in frame.headers.items():
            lower_key = key.lower()
            if lower_key == "destination":
                continue
            relay_headers[key] = value

        # obuspa rejects MESSAGE frames without content-type.
        if not any(k.lower() == 'content-type' for k in relay_headers.keys()):
            relay_headers['content-type'] = 'application/vnd.bbf.usp.msg'

        relay_frame = StompFrame(
            command="SEND",
            headers=relay_headers,
            body=frame.body
        )
        
        # Distribute message to subscribers
        with self.lock:
            subscribers = list(self.subscribers.get(destination, []))
            
            if subscribers:
                # has subscribers，send directly
                for subscriber in subscribers:
                    self._send_message_to_client(subscriber, destination, relay_frame)
            else:
                # no subscribers，Store message（Queue mode）
                self.destinations[destination].append(relay_frame)
                logger.debug(f"📦 Message queued for {destination}")
    
    def _send_message_to_client(self, client: Client, destination: str, relay_frame: StompFrame):
        """Send message to client"""
        headers = {
            "destination": destination,
            "message-id": str(time.time()),
            "subscription": list(client.subscriptions.keys())[0] if client.subscriptions else "0"
        }

        # Forward relevant SEND headers (content-type, reply-to-dest, etc.)
        # while preserving MESSAGE-required fields above.
        for key, value in relay_frame.headers.items():
            if key not in headers:
                headers[key] = value

        if 'content-type' not in {k.lower(): v for k, v in headers.items()}:
            headers['content-type'] = 'application/vnd.bbf.usp.msg'

        message_frame = StompFrame(
            "MESSAGE",
            headers,
            relay_frame.body
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
        except Exception:
            pass


def kill_process_on_port(port: int, exclude_pid: Optional[int] = None) -> bool:
    """Terminate any processes holding the specified port on Windows."""
    return EmbeddedBroker.kill_process_on_port(port, exclude_pid)


def start_embedded_broker_thread(host: str = "0.0.0.0", port: int = 61614) -> EmbeddedBroker:
    """Start embedded STOMP broker in a background daemon thread with startup sync & error check."""
    broker = EmbeddedBroker(host=host, port=port)
    started_event = threading.Event()
    errors = []

    def run():
        try:
            broker.start(started_callback=lambda: started_event.set())
        except Exception as e:
            errors.append(e)
            started_event.set()

    t = threading.Thread(target=run, daemon=True, name="EmbeddedBroker-Thread")
    t.start()
    started_event.wait(timeout=2.5)

    if errors:
        raise errors[0]
    if not broker.running:
        raise RuntimeError(f"Embedded STOMP Broker failed to bind and start on {host}:{port}")

    return broker




def main():
    """Command-line standalone STOMP Broker startup"""
    import argparse

    parser = argparse.ArgumentParser(description="Standalone STOMP Message Broker (for USP TR-369)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=61614, help="Listen port (default: 61614)")
    args = parser.parse_args()

    broker = EmbeddedBroker(host=args.host, port=args.port)
    try:
        broker.start()
    except Exception as e:
        _safe_print(f"\n[!] 啟動 Broker 失敗: 通訊埠 {args.port} 可能已被佔用或權限不足: {e}")
        _safe_print(f"[!] 請先嘗試執行 'kill_process_on_port({args.port})' 或關閉佔用該 Port 的程式。\n")
        sys.exit(1)

    _safe_print("\n" + "=" * 70)
    _safe_print("  \033[96m[+] STOMP MESSAGE BROKER (Standalone Console Window)\033[0m")
    _safe_print("=" * 70)
    _safe_print(f"  * Process PID:     \033[93m{os.getpid()}\033[0m")
    _safe_print(f"  * STOMP Endpoint:  \033[92mstomp://{args.host}:{args.port}\033[0m")
    _safe_print(f"  * Listen Port:     \033[92m{args.port} (LISTENING)\033[0m")
    _safe_print(f"  * Status:          \033[92mONLINE / READY FOR CONNECTIONS\033[0m")
    _safe_print("=" * 70)
    _safe_print("  \033[90mPress Ctrl+C in this console window to gracefully stop the Broker.\033[0m")
    _safe_print("=" * 70 + "\n")

    try:
        while broker.running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        _safe_print("\n[!] Ctrl+C received, shutting down STOMP Broker...")
    finally:
        broker.stop()
        _safe_print("[OK] STOMP Broker stopped successfully.")



if __name__ == "__main__":
    main()


