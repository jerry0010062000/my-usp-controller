#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Controller Development Environment Launcher

Features:
1. Auto-start Mini-Broker (STOMP)
2. Auto-start USP Controller Daemon
3. Auto-start GUI
4. Manage all processes

Usage:
    python start_dev.py              # Start full environment (Mini-Broker + Daemon + GUI)
    python start_dev.py --no-broker  # Use external Broker (Daemon + GUI only)
"""

import sys
import os
import time
import subprocess
import threading
import argparse
import signal
import json
from pathlib import Path

# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent / "tools"))

try:
    from embedded_broker import EmbeddedBroker
    BROKER_AVAILABLE = True
except ImportError:
    BROKER_AVAILABLE = False
    print("WARNING: Mini-Broker module not available")


class DevEnvironment:
    """Development environment manager"""
    
    def __init__(self, use_broker: bool = True):
        self.use_broker = use_broker
        self.broker_host = "0.0.0.0"
        self.broker_port = 61613
        
        self.broker = None
        self.daemon_process = None
        self.gui_process = None
        self.running = True
        
        self._load_config()
    
    def _load_config(self):
        """Load mini-broker config from config.json"""
        config_file = Path(__file__).parent / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    mini_broker = config.get('mini_broker', {})
                    self.broker_host = mini_broker.get('host', '0.0.0.0')
                    self.broker_port = mini_broker.get('port', 61613)
            except Exception as e:
                print(f"WARNING: Failed to load config: {e}, using defaults")
    
    def start_broker(self):
        """Start Mini-Broker"""
        if not self.use_broker:
            return True
        
        if not BROKER_AVAILABLE:
            print("ERROR: Mini-Broker module not available")
            return False
        
        print(f"[1/3] Starting Mini-Broker ({self.broker_host}:{self.broker_port})...")
        
        try:
            self.broker = EmbeddedBroker(host=self.broker_host, port=self.broker_port)
            
            # Track broker start status
            broker_started = [False]
            broker_error = [None]
            
            # Start broker in background thread
            def run_broker():
                try:
                    self.broker.start()
                    broker_started[0] = True
                except Exception as e:
                    broker_error[0] = str(e)
                    print(f"ERROR: Broker failed to start: {e}")
            
            broker_thread = threading.Thread(target=run_broker, daemon=True)
            broker_thread.start()
            
            # Wait for broker to start
            time.sleep(2)
            
            # Check if broker started successfully
            if broker_error[0]:
                print(f"ERROR: Mini-Broker failed to start")
                print(f"Reason: {broker_error[0]}")
                if "61613" in str(broker_error[0]) or "occupied" in str(broker_error[0]).lower():
                    print("\nDIAGNOSTICS:")
                    print("  Port 61613 is occupied (probably by RabbitMQ/ActiveMQ)")
                    print("\nSOLUTIONS:")
                    print("  1. Stop RabbitMQ/ActiveMQ:")
                    print("     net stop RabbitMQ")
                    print("  2. Or use external broker:")
                    print("     python start_dev.py --no-broker")
                    print("  3. Or change port in config.json:")
                    print('     "mini_broker": {"port": 61614}')
                return False
            
            print(f"OK: Mini-Broker started successfully")
            return True
            
        except Exception as e:
            print(f"ERROR: Failed to start Mini-Broker: {e}")
            return False
    
    def start_daemon(self):
        """Start USP Controller Daemon"""
        print("[2/3] Starting USP Controller Daemon...")
        
        try:
            # Start daemon process in new console window
            self.daemon_process = subprocess.Popen(
                [sys.executable, "usp_controller.py", "--daemon", "--force"],
                cwd=Path(__file__).parent,
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
            )
            
            # Wait for daemon to start
            time.sleep(3)
            
            # Check if process is still running
            if self.daemon_process.poll() is None:
                print(f"OK: Daemon started (PID: {self.daemon_process.pid})")
                return True
            else:
                exit_code = self.daemon_process.poll()
                print(f"ERROR: Daemon failed to start (exit code: {exit_code})")
                print("\nDIAGNOSTICS:")
                print("  Common reasons:")
                print("    1. Broker not running (if Mini-Broker failed to start)")
                print("    2. Port 6001 (IPC) already in use")
                print("    3. Invalid config.json")
                print("\nSOLUTIONS:")
                print("    - Check the Daemon console window for error details")
                print("    - Verify broker is running before starting Daemon")
                print("    - Check config.json configuration")
                return False
                
        except Exception as e:
            print(f"ERROR: Failed to start Daemon: {e}")
            return False
    
    def start_gui(self):
        """Start GUI"""
        print("[3/3] Starting USP Controller GUI...")
        
        try:
            # Use pythonw to start GUI (no console window)
            python_exe = sys.executable
            if sys.platform == 'win32':
                # Try to use pythonw.exe
                pythonw_exe = python_exe.replace('python.exe', 'pythonw.exe')
                if Path(pythonw_exe).exists():
                    python_exe = pythonw_exe
            
            self.gui_process = subprocess.Popen(
                [python_exe, "usp_gui.py"],
                cwd=Path(__file__).parent
            )
            
            time.sleep(1)
            print(f"OK: GUI started (PID: {self.gui_process.pid})")
            return True
            
        except Exception as e:
            print(f"ERROR: Failed to start GUI: {e}")
            return False
    
    def run(self):
        """Run development environment"""
        print("\n" + "="*60)
        print("  USP Controller Development Environment")
        print("="*60 + "\n")
        
        try:
            # 1. Start Mini-Broker (if needed)
            if self.use_broker:
                if not self.start_broker():
                    print("\nERROR: Mini-Broker failed to start, aborting")
                    print("\nTIP: Use --no-broker to skip Mini-Broker")
                    print("     Example: python start_dev.py --no-broker")
                    return
            else:
                print("INFO: [1/3] Skipping Mini-Broker (using external Broker)")
            
            # 2. Start Daemon
            if not self.start_daemon():
                print("\nERROR: Daemon failed to start, aborting")
                self.cleanup()
                return
            
            # 3. Start GUI
            if not self.start_gui():
                print("\nERROR: GUI failed to start, aborting")
                self.cleanup()
                return
            
            # 4. Display status
            print("\n" + "="*60)
            print("  SUCCESS: Development environment started")
            print("="*60)
            if self.use_broker:
                print(f"  Mini-Broker: {self.broker_host}:{self.broker_port}")
            else:
                print(f"  Broker: External Broker")
            print(f"  Daemon PID: {self.daemon_process.pid}")
            print(f"  GUI PID: {self.gui_process.pid}")
            print("="*60)
            print("\nTIPS:")
            print("  - Close GUI window to stop all services")
            print("  - Or press Ctrl+C in this terminal")
            print("="*60 + "\n")
            
            # 5. Monitor processes
            while self.running:
                # Check if GUI exited
                if self.gui_process and self.gui_process.poll() is not None:
                    print("\n[INFO] GUI closed, stopping all services...")
                    break
                
                # Check if Daemon crashed
                if self.daemon_process and self.daemon_process.poll() is not None:
                    print(f"\nWARNING: Daemon exited unexpectedly (code: {self.daemon_process.poll()})")
                    break
                
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\nINFO: Stop signal received...")
        
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        print("\nCleaning up...")
        
        # Stop GUI
        if self.gui_process:
            try:
                print("  Stopping GUI...")
                self.gui_process.terminate()
                self.gui_process.wait(timeout=3)
                print("  OK: GUI stopped")
            except:
                self.gui_process.kill()
                print("  WARNING: GUI force killed")
        
        # Stop Daemon
        if self.daemon_process:
            try:
                print("  Stopping Daemon...")
                self.daemon_process.terminate()
                self.daemon_process.wait(timeout=5)
                print("  OK: Daemon stopped")
            except:
                self.daemon_process.kill()
                print("  WARNING: Daemon force killed")
        
        # Stop Mini-Broker
        if self.broker:
            try:
                print("  Stopping Mini-Broker...")
                self.broker.stop()
                print("  OK: Mini-Broker stopped")
            except:
                print("  WARNING: Error stopping Mini-Broker")
        
        print("\nDevelopment environment closed\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="USP Controller Development Environment Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python start_dev.py              # Full environment (Mini-Broker + Daemon + GUI)
  python start_dev.py --no-broker  # Use external Broker (Daemon + GUI only)
  
Notes:
  - Mini-Broker config is read from config.json (mini_broker section)
  - Closing GUI window will stop all services automatically
        """
    )
    
    parser.add_argument(
        "--no-broker",
        action="store_true",
        help="Skip Mini-Broker (use external Broker like RabbitMQ/ActiveMQ)"
    )
    
    args = parser.parse_args()
    
    # 创建开发环境
    env = DevEnvironment(use_broker=not args.no_broker)
    
    # 信号处理
    def signal_handler(sig, frame):
        env.running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # 运行
    env.run()


if __name__ == "__main__":
    main()
