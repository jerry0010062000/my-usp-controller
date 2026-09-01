#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller & Broker Dedicated Console Daemon
Runs as an independent background / console process maintaining
STOMP connection, device states, and IPC API server.
"""

import sys
import io
import os
import time
import signal
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Force UTF-8 encoding on Windows safely
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
        # Enable Windows ANSI VT100
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from usp_controller.config import ConfigManager
from usp_controller.logger import get_logger, set_debug_level
from usp_controller.core import USPControllerCore
from usp_controller.interface.command_handler import CommandHandler
from usp_controller.ipc import IPCServer
from tools.embedded_broker import start_embedded_broker_thread

logger = get_logger()


class USPControllerDaemon:
    """
    Dedicated Console Daemon for USP Controller (Decoupled from Broker)
    """

    def __init__(self, config_path: str = "config.json", debug_level: int = 1,
                 broker_host: Optional[str] = None, broker_port: Optional[int] = None,
                 broker_user: Optional[str] = None, broker_pass: Optional[str] = None,
                 ipc_port: Optional[int] = None):
        self.config_path = config_path
        self.debug_level = debug_level
        self.config = ConfigManager.load_config(config_path)

        # Apply overrides if provided
        if broker_host:
            self.config.transport.host = broker_host
        if broker_port:
            self.config.transport.port = broker_port
        if broker_user:
            self.config.transport.username = broker_user
        if broker_pass:
            self.config.transport.password = broker_pass
        if ipc_port:
            if hasattr(self.config, 'ipc') and self.config.ipc:
                self.config.ipc.port = ipc_port

        self.controller = None
        self.command_handler = None
        self.ipc_server = None
        self.running = False

    def start(self):
        """Start Controller Daemon services"""
        set_debug_level(self.debug_level)
        self.running = True

        # 1. Start USP Controller Core
        self.controller = USPControllerCore(config=self.config)
        self.command_handler = CommandHandler(controller=self.controller)

        # 2. Connect Controller to STOMP Broker
        connected = self.controller.connect()
        if not connected:
            b_host = self.config.transport.host
            b_port = self.config.transport.port
            logger.info(f"STOMP Broker ({b_host}:{b_port}) is offline. Controller will automatically connect when Broker is started.", level=0)

        # 3. Start IPC Server
        ipc_cfg = getattr(self.config, 'ipc', None)
        ipc_host = getattr(ipc_cfg, 'host', '127.0.0.1') if ipc_cfg else '127.0.0.1'
        ipc_port = getattr(ipc_cfg, 'port', 6001) if ipc_cfg else 6001

        self.ipc_server = IPCServer(
            controller=self.controller,
            command_handler=self.command_handler,
            host=ipc_host,
            port=ipc_port
        )
        self.ipc_server.start()

        # 4. Print Console Banner
        self._print_banner(connected, ipc_host, ipc_port)

        # 5. Main loop
        self._run_loop()

    def _print_banner(self, connected: bool, ipc_host: str, ipc_port: int):
        conn_str = "\033[92mCONNECTED\033[0m" if connected else "\033[93mWAITING FOR BROKER\033[0m"
        b_host = self.config.transport.host
        b_port = self.config.transport.port

        print("\n" + "=" * 70)
        print("  \033[96m[+] USP CONTROLLER DAEMON (Standalone Console Window)\033[0m")
        print("=" * 70)
        print(f"  * Process PID:     \033[93m{os.getpid()}\033[0m")
        print(f"  * STOMP Broker:    \033[97m{b_host}:{b_port}\033[0m ({conn_str})")
        print(f"  * IPC Server:      \033[92m{ipc_host}:{ipc_port}\033[0m (Ready for GUI / CLI commands)")
        print(f"  * Controller ID:   \033[95m{self.config.controller_endpoint_id}\033[0m")
        print(f"  * Receive Topic:   {self.config.receive_topic}")
        print("=" * 70)
        print("  \033[90mPress Ctrl+C in this console window to gracefully stop the Controller.\033[0m")
        print("=" * 70 + "\n")



    def _run_loop(self):
        """Keep main process alive and monitor health"""
        try:
            while self.running:
                time.sleep(1.0)
                # Auto-reconnect STOMP if disconnected
                if self.controller and not self.controller.is_connected():
                    logger.info("Reconnecting STOMP transport...", level=1)
                    self.controller.connect()
        except KeyboardInterrupt:
            print("\n[!] Ctrl+C received, shutting down Daemon...")
        finally:
            self.stop()

    def stop(self):
        """Stop all daemon services"""
        self.running = False
        if self.ipc_server:
            try:
                self.ipc_server.stop()
            except Exception:
                pass
            self.ipc_server = None

        if self.controller:
            try:
                self.controller.disconnect()
            except Exception:
                pass
            self.controller = None

        logger.info("USP Controller Daemon stopped successfully.", level=0)


def main():
    parser = argparse.ArgumentParser(description="USP Controller Dedicated Console Daemon")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--broker-host", default=None, help="STOMP Broker IP / Hostname override (e.g. 192.168.1.100)")
    parser.add_argument("--broker-port", type=int, default=None, help="STOMP Broker Port override (e.g. 61613)")
    parser.add_argument("--broker-user", default=None, help="STOMP Username override")
    parser.add_argument("--broker-pass", default=None, help="STOMP Password override")
    parser.add_argument("--ipc-port", type=int, default=None, help="IPC Server Port override (default: 6001)")
    parser.add_argument("--debug", type=int, default=1, help="Console debug level (0, 1, 2)")
    args = parser.parse_args()

    daemon = USPControllerDaemon(
        config_path=args.config,
        debug_level=args.debug,
        broker_host=args.broker_host,
        broker_port=args.broker_port,
        broker_user=args.broker_user,
        broker_pass=args.broker_pass,
        ipc_port=args.ipc_port
    )

    def sig_handler(signum, frame):
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, sig_handler)

    daemon.start()
    return 0




if __name__ == "__main__":
    sys.exit(main())
