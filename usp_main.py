#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller - Primary CLI Entry Point
Supports both IPC Client mode (when Daemon is running) and Standalone mode.
"""

import sys
import io
import argparse
from pathlib import Path

# Force UTF-8 encoding on Windows
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True)
    except Exception:
        pass

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from usp_controller.config import ConfigManager
from usp_controller.logger import get_logger, set_debug_level
from usp_controller.core import USPControllerCore
from usp_controller.interface.command_handler import CommandHandler
from usp_controller.interface.cli import CLIInterface
from usp_controller.interface.formatter import OutputFormat, get_formatter
from usp_controller.ipc import IPCClient
from tools.embedded_broker import start_embedded_broker_thread

logger = get_logger()


def main():
    parser = argparse.ArgumentParser(
        description="USP Controller (TR-369) - CLI & Command Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # One-shot USP commands (via Daemon if running, or standalone):
  python usp_main.py get Device.DeviceInfo.
  python usp_main.py set Device.WiFi.SSID.1.SSID "MyWiFi"
  python usp_main.py add Device.DHCPv4.Server.Pool.
  python usp_main.py delete Device.DHCPv4.Server.Pool.2.
  python usp_main.py status
  python usp_main.py devices
  python usp_main.py script scripts/test_dhcpv4_pool.txt

  # Start interactive REPL:
  python usp_main.py
  python usp_main.py --standalone
  python usp_main.py --broker
        """
    )

    parser.add_argument('command_args', nargs='*', help='直接執行的 USP 命令 (例如: get Device.DeviceInfo.)')
    parser.add_argument('-c', '--config', default='config.json', help='設定檔路徑 (預設: config.json)')
    parser.add_argument('-d', '--debug', type=int, default=None, choices=[0, 1, 2], help='日誌調試級別 (0=簡潔, 1=標準, 2=除錯)')
    parser.add_argument('-f', '--format', choices=['colored', 'text', 'table', 'json'], default='colored', help='終端機輸出格式')
    parser.add_argument('--standalone', action='store_true', help='強制獨立模式 (不經 Daemon IPC 直接以 Controller STOMP Client 連線)')
    parser.add_argument('--broker-host', default=None, help='STOMP Broker IP / 主機名稱覆蓋 (例如: 192.168.1.100)')
    parser.add_argument('--broker-port', type=int, default=None, help='STOMP Broker 通訊埠覆蓋 (例如: 61613)')
    parser.add_argument('--daemon', action='store_true', help='作為後台守護進程 (Daemon) 啟動')

    args = parser.parse_args()

    # Delegate to Daemon if --daemon requested
    if args.daemon:
        from tools.usp_daemon import USPControllerDaemon
        d = USPControllerDaemon(
            config_path=args.config,
            debug_level=args.debug if args.debug is not None else 1,
            broker_host=args.broker_host,
            broker_port=args.broker_port
        )
        return d.start()

    # Load configuration
    config = ConfigManager.load_config(args.config)
    if args.broker_host:
        config.transport.host = args.broker_host
    if args.broker_port:
        config.transport.port = args.broker_port
    if args.debug is not None:
        set_debug_level(args.debug)


    fmt_enum = {
        'colored': OutputFormat.COLORED,
        'text': OutputFormat.TEXT,
        'table': OutputFormat.TABLE,
        'json': OutputFormat.JSON
    }.get(args.format, OutputFormat.COLORED)
    formatter = get_formatter(fmt_enum)

    # 1. Check if Daemon is alive on IPC Port (unless --standalone is forced)
    ipc_cfg = getattr(config, 'ipc', None)
    ipc_host = getattr(ipc_cfg, 'host', '127.0.0.1') if ipc_cfg else '127.0.0.1'
    ipc_port = getattr(ipc_cfg, 'port', 6001) if ipc_cfg else 6001

    ipc_client = IPCClient(host=ipc_host, port=ipc_port)
    use_ipc = (not args.standalone) and ipc_client.is_daemon_alive(timeout=0.3)


    if use_ipc:
        # IPC Mode: send commands directly to the running Daemon
        if args.command_args:
            cmd_line = " ".join(args.command_args)
            res = ipc_client.exec_cmd(cmd_line)
            if not res.success:
                print(formatter.format_error(res.error or "Command failed on Daemon"))
                return 1
            if res.message:
                print(res.message)
            if res.data is not None:
                formatted = formatter.format_result(res.data)
                if formatted:
                    print(formatted)
            return 0
        else:
            # Interactive REPL in IPC Client Mode
            return _run_ipc_interactive_repl(ipc_client, formatter)

    # 2. Standalone Mode: Direct STOMP connection
    controller = USPControllerCore(config=config)
    
    # Try connecting to broker (non-fatal for informational commands like help or dut_config)
    cmd_first = args.command_args[0].lower() if args.command_args else ""
    is_offline_cmd = cmd_first in ['help', 'h', '?', 'dut_config', 'dut_guide', 'gen_dut', 'dut', 'clear', 'cls', 'quit', 'exit']
    
    if not is_offline_cmd:
        if not controller.connect():
            logger.info("Note: STOMP broker is offline. Start Broker using 'run_broker.bat' or GUI.", level=0)
    else:
        # Silently attempt quick connect for offline commands
        try:
            controller.connect()
        except Exception:
            pass

    handler = CommandHandler(controller=controller)
    cli = CLIInterface(prompt="usp> ", formatter=formatter, command_handler=handler)


    if args.command_args:
        cmd_line = " ".join(args.command_args)
        result = cli.execute_single(cmd_line)
        controller.disconnect()
        return 0 if result.success else 1
    else:
        cli.initialize()
        try:
            cli.run()
        finally:
            cli.shutdown()
            controller.disconnect()
        return 0


def _run_ipc_interactive_repl(ipc_client: IPCClient, formatter) -> int:
    """Interactive REPL connected to running Daemon via IPC"""
    print("\n" + "=" * 65)
    print("  \033[96mUSP Controller CLI v3.1.002 (Connected to Daemon)\033[0m")
    print(f"  IPC Daemon: \033[92m{ipc_client.host}:{ipc_client.port}\033[0m")
    print("  Type 'help' for commands, 'devices' for agents, 'quit' to exit")
    print("=" * 65 + "\n")

    while True:
        try:
            # Fetch active target
            _, active = ipc_client.get_devices()
            target_str = f"[{active}]" if active else ""
            prompt_str = f"usp {target_str}> " if target_str else "usp> "

            cmd_line = input(prompt_str).strip()
            if not cmd_line:
                continue

            if cmd_line.lower() in ('quit', 'exit', 'q'):
                print("Exiting CLI...")
                break

            if cmd_line.lower() in ('cls', 'clear'):
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                continue

            res = ipc_client.exec_cmd(cmd_line)
            if not res.success:
                print(formatter.format_error(res.error or "Command failed"))
            else:
                if res.message:
                    print(res.message)
                if res.data is not None:
                    formatted = formatter.format_result(res.data)
                    if formatted:
                        print(formatted)

        except (KeyboardInterrupt, EOFError):
            print("\nExiting CLI...")
            break
        except Exception as e:
            print(formatter.format_error(str(e)))

    return 0


if __name__ == "__main__":
    sys.exit(main())
