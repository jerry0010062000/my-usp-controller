#!/usr/bin/env python3
"""
USP Test Script Runner
Executes test scripts by sending commands to the controller daemon via IPC
"""

import socket
import json
import time
import sys
import argparse
import os
from pathlib import Path

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

class TestRunner:
    def __init__(self, host=IPC_HOST, port=IPC_PORT, delay=0.5, endpoint=None):
        self.host = host
        self.port = port
        self.delay = delay  # Delay between commands in seconds
        self.endpoint = endpoint  # Target endpoint ID
        self.variables = {}  # Store variables for substitution
        
    def send_command(self, cmd):
        """Send command to controller daemon"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((self.host, self.port))
                s.sendall(cmd.encode('utf-8'))
                
                # Receive response
                data_chunks = []
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data_chunks.append(chunk)
                    if chunk.endswith(b'}'):
                        break
                
                if not data_chunks:
                    return None
                    
                data = b''.join(data_chunks).decode('utf-8')
                return json.loads(data)
        except Exception as e:
            print(f"[ERROR] Failed to send command: {e}")
            return None
    
    def parse_script_line(self, line):
        """Parse a single script line into command and arguments"""
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return None
        
        # Check for expected value assertion
        expected_value = None
        if '# expect:' in line or '# EXPECT:' in line:
            # Split on the expect marker
            parts_split = line.split('#')
            line = parts_split[0].strip()
            expect_part = parts_split[1].strip()
            if expect_part.lower().startswith('expect:'):
                expected_value = expect_part[7:].strip()
        
        # Replace endpoint variable with actual value
        if self.endpoint:
            line = line.replace('{ENDPOINT}', self.endpoint)
        
        # Replace other variables
        for var_name, var_value in self.variables.items():
            line = line.replace(f'{{{var_name}}}', str(var_value))
        
        # Parse command format: <cmd> <endpoint> <path> [value]
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            return None
        
        cmd = parts[0].lower()
        endpoint = parts[1]
        path = parts[2]
        value = parts[3] if len(parts) > 3 else ""
        
        # Build IPC command string
        if cmd in ['get', 'get_supported', 'get_instances']:
            return (f"{cmd} {endpoint} {path}", expected_value)
        elif cmd == 'set':
            # SET command requires a value
            if len(parts) < 4 or not value.strip():
                print(f"    [WARNING] SET command missing value: {line}")
                return None
            return (f"{cmd} {endpoint} {path} {value}", expected_value)
        elif cmd == 'add':
            return (f"{cmd} {endpoint} {path}", expected_value)
        elif cmd == 'delete':
            return (f"{cmd} {endpoint} {path}", expected_value)
        else:
            print(f"    [WARNING] Unknown command: {cmd}")
            return None
    
    def extract_instance_number(self, response_msg, path):
        """Extract instance number from add/get_instances response"""
        # For ADD responses, look for "created instance X"
        if 'instance' in response_msg.lower():
            import re
            match = re.search(r'instance[:\s]+(\d+)', response_msg, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # For GetInstances response dict
        if isinstance(response_msg, dict) and 'instances' in response_msg:
            instances = response_msg.get('instances', [])
            if instances:
                # Return the last instance (usually the most recently created)
                return instances[-1]
        
        # Extract from response text containing paths
        # Example: "Device.DHCPv4.Server.Pool.2." -> extract "2"
        import re
        if path.endswith('.'):
            base_obj = path.rstrip('.')
            pattern = re.escape(base_obj) + r'\.(\d+)\.'
            match = re.search(pattern, str(response_msg))
            if match:
                return match.group(1)
        
        return None
    
    def run_script(self, script_file, interactive=False, stop_on_error=False):
        """Execute a test script"""
        script_path = Path(script_file)
        if not script_path.exists():
            print(f"[ERROR] Script file not found: {script_file}")
            return False
        
        print(f"[INFO] Running test script: {script_file}")
        print(f"[INFO] Delay between commands: {self.delay}s")
        print("=" * 60)
        
        with open(script_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        executed = 0
        skipped = 0
        failed = 0
        
        for i, line in enumerate(lines, 1):
            # Print comments and section headers
            if line.strip().startswith('#'):
                print(f"\n{line.rstrip()}")
                continue
            
            # Skip empty lines
            if not line.strip():
                continue
            
            # Parse command
            result = self.parse_script_line(line)
            if not result:
                skipped += 1
                continue
            
            # Unpack command and expected value
            if isinstance(result, tuple):
                cmd, expected_value = result
            else:
                cmd = result
                expected_value = None
            
            print(f"\n[{i}] Command: {cmd}")
            if expected_value:
                print(f"    Expected: {expected_value}")
            
            # Interactive mode: wait for user confirmation
            if interactive:
                response = input("    Execute? [Y/n/q]: ").strip().lower()
                if response == 'q':
                    print("[INFO] User aborted")
                    break
                elif response == 'n':
                    print("    [SKIPPED]")
                    skipped += 1
                    continue
            
            # Send command
            resp = self.send_command(cmd)
            
            if resp and resp.get('status') == 'ok':
                actual_value = resp.get('msg', 'OK')
                print(f"    [SUCCESS] {actual_value}")
                
                # Try to extract instance number for ADD or GetInstances commands
                if 'add' in cmd.lower() or 'get_instances' in cmd.lower():
                    # Extract path from command
                    cmd_parts = cmd.split()
                    if len(cmd_parts) >= 3:
                        path = cmd_parts[2]
                        # Try to extract from response dict first
                        instance_num = self.extract_instance_number(resp, path)
                        if instance_num:
                            self.variables['INSTANCE'] = instance_num
                            print(f"    → Saved INSTANCE={instance_num}")
                
                # Check expected value if specified
                if expected_value:
                    # Extract actual value from response (handle different response formats)
                    actual_str = str(actual_value).strip()
                    expected_str = expected_value.strip()
                    
                    # Check if values match
                    if expected_str.lower() in actual_str.lower():
                        print(f"    ✓ ASSERTION PASSED")
                        executed += 1
                    else:
                        print(f"    ✗ ASSERTION FAILED")
                        print(f"      Expected: {expected_str}")
                        print(f"      Got: {actual_str}")
                        failed += 1
                        if stop_on_error:
                            print("[ERROR] Stopping due to assertion failure")
                            break
                else:
                    executed += 1
            else:
                error_msg = resp.get('msg', 'Unknown error') if resp else 'No response'
                print(f"    [FAILED] {error_msg}")
                failed += 1
                
                if stop_on_error:
                    print("[ERROR] Stopping due to error")
                    break
            
            # Delay before next command
            if self.delay > 0:
                time.sleep(self.delay)
        
        # Summary
        print("\n" + "=" * 60)
        print("[SUMMARY]")
        print(f"  Executed: {executed}")
        print(f"  Failed:   {failed}")
        print(f"  Skipped:  {skipped}")
        print("=" * 60)
        
        return failed == 0

def load_devices():
    """Load available devices from devices.json"""
    devices_file = Path(__file__).parent.parent / 'devices.json'
    if not devices_file.exists():
        return []
    
    try:
        with open(devices_file, 'r', encoding='utf-8') as f:
            devices = json.load(f)
        return list(devices.keys())
    except Exception as e:
        print(f"[WARNING] Failed to load devices.json: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(
        description="USP Test Script Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run script with default settings
  python run_test.py test_dhcpv4_pool.txt
  
  # Interactive mode (confirm each command)
  python run_test.py test_dhcpv4_pool.txt -i
  
  # Stop on first error
  python run_test.py test_dhcpv4_pool.txt -s
  
  # Custom delay between commands
  python run_test.py test_dhcpv4_pool.txt -d 1.0
        """
    )
    
    parser.add_argument('script', nargs='?', help='Path to test script file')
    parser.add_argument('-e', '--endpoint', 
                        help='Target endpoint ID (uses first device from devices.json if not specified)')
    parser.add_argument('-l', '--list-devices', action='store_true',
                        help='List available devices from devices.json')
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Interactive mode (confirm each command)')
    parser.add_argument('-s', '--stop-on-error', action='store_true',
                        help='Stop execution on first error')
    parser.add_argument('-d', '--delay', type=float, default=0.5,
                        help='Delay between commands in seconds (default: 0.5)')
    parser.add_argument('--host', default=IPC_HOST,
                        help=f'IPC host (default: {IPC_HOST})')
    parser.add_argument('--port', type=int, default=IPC_PORT,
                        help=f'IPC port (default: {IPC_PORT})')
    
    args = parser.parse_args()
    
    # Handle list-devices command
    if args.list_devices:
        devices = load_devices()
        if devices:
            print("Available devices in devices.json:")
            for i, dev in enumerate(devices, 1):
                print(f"  {i}. {dev}")
        else:
            print("No devices found in devices.json")
        sys.exit(0)
    
    # Require script file
    if not args.script:
        parser.error('script argument is required (unless using --list-devices)')
    
    # Determine endpoint
    endpoint = args.endpoint
    if not endpoint:
        devices = load_devices()
        if devices:
            endpoint = devices[0]
            print(f"[INFO] Using first available device: {endpoint}")
        else:
            print("[ERROR] No endpoint specified and no devices found in devices.json")
            print("        Use -e/--endpoint to specify an endpoint or add devices to devices.json")
            sys.exit(1)
    
    runner = TestRunner(args.host, args.port, args.delay, endpoint)
    success = runner.run_script(args.script, args.interactive, args.stop_on_error)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
