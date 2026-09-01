#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STOMP 1.2 Transport Protocol Implementation
Production-ready, thread-safe, and binary-safe framing for USP messages.
"""

import socket
import select
import threading
import time
from typing import Dict, Optional, Any
from .base import TransportProtocol, TransportState, TransportFactory
from ..logger import get_logger

logger = get_logger()


class STOMPTransport(TransportProtocol):
    """
    Robust STOMP 1.2 Transport Implementation
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = str(config.get('host', '127.0.0.1')).strip()
        self.port = int(config.get('port', 61613))
        self.username = config.get('username', 'guest')
        self.password = config.get('password', 'guest')
        self.heartbeat = config.get('heartbeat', '0,0')

        self._normalize_host_port()

        self.sock: Optional[socket.socket] = None
        self.recv_thread: Optional[threading.Thread] = None
        self.running = False
        self.subscriptions: Dict[str, str] = {}  # destination -> subscription_id
        self.subscription_counter = 0
        self._send_lock = threading.Lock()
        self._sub_lock = threading.Lock()

    def _normalize_host_port(self):
        """Normalize URL prefixes and localhost target addresses"""
        if self.host.startswith('stomp://'):
            self.host = self.host[len('stomp://'):]
        elif self.host.startswith('tcp://'):
            self.host = self.host[len('tcp://'):]

        if self.host in ('0.0.0.0', '::', ''):
            self.host = '127.0.0.1'

        if ':' in self.host and self.host.count(':') == 1:
            h, p = self.host.split(':', 1)
            if p.isdigit():
                self.host = h.strip() or '127.0.0.1'
                self.port = int(p)

    def connect(self) -> bool:
        """Establish STOMP connection"""
        try:
            self._notify_state_change(TransportState.CONNECTING)

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))

            # Send CONNECT frame
            connect_frame = (
                f"CONNECT\n"
                f"accept-version:1.2\n"
                f"host:/\n"
                f"login:{self.username}\n"
                f"passcode:{self.password}\n"
                f"heart-beat:{self.heartbeat}\n"
                f"\n\0"
            )

            with self._send_lock:
                self.sock.sendall(connect_frame.encode('utf-8'))

            logger.stomp_frame("send", {
                "command": "CONNECT",
                "accept-version": "1.2",
                "login": self.username
            })

            # Wait for CONNECTED response
            self.sock.settimeout(5)
            response = self.sock.recv(2048)
            if not response or b'CONNECTED' not in response:
                logger.error(f"STOMP connection failed: {response}")
                self._notify_state_change(TransportState.ERROR)
                self.disconnect()
                return False

            logger.success(f"STOMP connected to {self.host}:{self.port}", level=0)

            # Start receiver thread
            self.running = True
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()

            self._notify_state_change(TransportState.CONNECTED)
            return True

        except Exception as e:
            logger.error(f"STOMP connection error: {e}")
            self._notify_state_change(TransportState.ERROR)
            self.disconnect()
            return False

    def disconnect(self) -> bool:
        """Disconnect from STOMP broker"""
        try:
            prev_state = self.state
            self._notify_state_change(TransportState.DISCONNECTING)
            self.running = False

            if self.sock:
                if prev_state == TransportState.CONNECTED:
                    try:
                        with self._send_lock:
                            self.sock.sendall(b"DISCONNECT\n\n\0")
                        time.sleep(0.02)
                    except Exception:
                        pass

                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None

            if self.recv_thread and self.recv_thread.is_alive():
                if threading.current_thread() != self.recv_thread:
                    self.recv_thread.join(timeout=0.5)

            with self._sub_lock:
                self.subscriptions.clear()

            logger.info("STOMP disconnected", level=1)
            self._notify_state_change(TransportState.DISCONNECTED)
            return True

        except Exception as e:
            logger.error(f"STOMP disconnect error: {e}")
            self._notify_state_change(TransportState.ERROR)
            return False


    def subscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """Subscribe to a destination topic/queue"""
        try:
            if not self.is_connected():
                logger.error("Cannot subscribe: not connected")
                return False

            with self._sub_lock:
                if subscription_id is None:
                    subscription_id = f"sub-{self.subscription_counter}"
                    self.subscription_counter += 1

                frame = (
                    f"SUBSCRIBE\n"
                    f"id:{subscription_id}\n"
                    f"destination:{destination}\n"
                    f"ack:auto\n"
                    f"\n\0"
                )

                with self._send_lock:
                    if not self.sock:
                        return False
                    self.sock.sendall(frame.encode('utf-8'))

                self.subscriptions[destination] = subscription_id
                logger.success(f"Subscribed to {destination} (id: {subscription_id})", level=1)
                return True

        except Exception as e:
            logger.error(f"STOMP subscribe error ({destination}): {e}")
            return False

    def unsubscribe(self, destination: str, subscription_id: Optional[str] = None) -> bool:
        """Unsubscribe from a destination"""
        try:
            with self._sub_lock:
                if subscription_id is None:
                    subscription_id = self.subscriptions.get(destination)

                if not subscription_id:
                    logger.error(f"No subscription found for {destination}")
                    return False

                frame = f"UNSUBSCRIBE\nid:{subscription_id}\n\n\0"

                with self._send_lock:
                    if self.sock:
                        self.sock.sendall(frame.encode('utf-8'))

                if destination in self.subscriptions:
                    del self.subscriptions[destination]

                logger.info(f"Unsubscribed from {destination}", level=1)
                return True

        except Exception as e:
            logger.error(f"STOMP unsubscribe error: {e}")
            return False

    def send(self, destination: str, body: bytes,
             headers: Optional[Dict[str, str]] = None) -> bool:
        """Send STOMP frame with binary payload and content-length header"""
        try:
            if not self.is_connected():
                logger.error("Cannot send: not connected")
                return False

            hdrs = {
                "destination": destination,
                "content-type": "application/vnd.bbf.usp.msg",
                "content-length": str(len(body))
            }
            if headers:
                hdrs.update(headers)

            frame_lines = ["SEND"]
            for k, v in hdrs.items():
                frame_lines.append(f"{k}:{v}")
            frame_lines.append("\n")

            header_bytes = "\n".join(frame_lines).encode('utf-8')
            full_frame = header_bytes + body + b'\0'

            with self._send_lock:
                if not self.sock:
                    return False
                self.sock.sendall(full_frame)

            logger.stomp_frame("send", hdrs, body)
            return True

        except Exception as e:
            logger.error(f"STOMP send error: {e}")
            return False

    def is_connected(self) -> bool:
        """Check if transport is connected"""
        return self.state == TransportState.CONNECTED and self.sock is not None

    def _recv_loop(self):
        """Binary-safe receiving loop with Content-Length support"""
        buffer = b''

        while self.running and self.sock:
            try:
                ready = select.select([self.sock], [], [], 0.5)
                if not ready[0]:
                    continue

                chunk = self.sock.recv(65536)
                if not chunk:
                    logger.error("STOMP connection closed by broker")
                    self._notify_state_change(TransportState.ERROR)
                    break

                buffer += chunk

                # Process all complete frames in the buffer
                while buffer:
                    # Look for end of headers
                    if b'\n\n' not in buffer:
                        break

                    header_end = buffer.find(b'\n\n')
                    header_bytes = buffer[:header_end]

                    # Parse content-length
                    content_length = -1
                    header_text = header_bytes.decode('utf-8', errors='ignore')
                    for line in header_text.split('\n'):
                        if 'content-length:' in line.lower():
                            try:
                                content_length = int(line.split(':', 1)[1].strip())
                            except Exception:
                                pass
                            break

                    body_start = header_end + 2

                    if content_length >= 0:
                        required_len = body_start + content_length + 1  # body + trailing NULL
                        if len(buffer) < required_len:
                            break  # Wait for more data

                        frame_data = buffer[:required_len - 1]  # exclude NULL
                        buffer = buffer[required_len:]
                        self._process_frame(frame_data)
                    else:
                        # No content-length, scan for NULL
                        if b'\0' not in buffer[body_start:]:
                            break

                        null_pos = buffer.find(b'\0', body_start)
                        frame_data = buffer[:null_pos]
                        buffer = buffer[null_pos + 1:]
                        self._process_frame(frame_data)

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"STOMP receive error: {e}")
                    self._notify_state_change(TransportState.ERROR)
                break

        self.running = False
        logger.info("STOMP receive loop stopped", level=2)

    def _process_frame(self, frame_bytes: bytes):
        """Parse received STOMP frame into headers and body"""
        try:
            if b'\n\n' in frame_bytes:
                header_part, body = frame_bytes.split(b'\n\n', 1)
            else:
                header_part = frame_bytes
                body = b''

            headers: Dict[str, str] = {}
            header_lines = header_part.decode('utf-8', errors='ignore').split('\n')

            command = ""
            start_idx = 0
            for i, line in enumerate(header_lines):
                if line.strip():
                    command = line.strip()
                    start_idx = i + 1
                    break

            for line in header_lines[start_idx:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()

            logger.stomp_frame("recv", headers, body if len(body) < 100 else body[:100])

            if command == "MESSAGE":
                if self.message_callback:
                    self.message_callback(headers, body, None)
            elif command == "ERROR":
                err_msg = headers.get('message', 'Unknown STOMP error')
                logger.error(f"STOMP Server Error: {err_msg}")

        except Exception as e:
            logger.error(f"STOMP frame processing error: {e}")

    def get_subscriptions(self) -> Dict[str, str]:
        """Get copy of active subscriptions"""
        with self._sub_lock:
            return self.subscriptions.copy()


# Register STOMP in the factory
TransportFactory.register('stomp', STOMPTransport)
