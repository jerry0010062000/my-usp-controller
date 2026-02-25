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
        
        # Check for save_to annotation
        save_to_var = None
        if '# save_to:' in line or '# SAVE_TO:' in line:
            parts_split = line.split('#')
            line = parts_split[0].strip()
            save_part = parts_split[1].strip()
            if save_part.lower().startswith('save_to:'):
                save_to_var = save_part[8:].strip()
        
        # Check for verify_delta annotation
        verify_delta = None
        if '# verify_delta:' in line or '# VERIFY_DELTA:' in line:
            parts_split = line.split('#')
            line = parts_split[0].strip()
            delta_part = parts_split[1].strip()
            if delta_part.lower().startswith('verify_delta:'):
                verify_delta = delta_part[13:].strip()
        
        # Check for expected value assertion
        expected_value = None
        if '# expect:' in line or '# EXPECT:' in line:
            # Split on the expect marker
            parts_split = line.split('#')
            line = parts_split[0].strip()
            expect_part = parts_split[1].strip()
            if expect_part.lower().startswith('expect:'):
                expected_value = expect_part[7:].strip()
        
        # Check for special commands
        if line.startswith('discover_bridge_port'):
            return ('DISCOVER_BRIDGE_PORT', line, None)
        
        if line.startswith('wait_user'):
            message = line[9:].strip() if len(line) > 9 else "Press Enter to continue..."
            return ('WAIT_USER', message, None)
        
        if line.startswith('exec'):
            shell_cmd = line[4:].strip() if len(line) > 4 else ""
            return ('EXEC', shell_cmd, None)
        
        if line.startswith('verify_delta'):
            condition = line[12:].strip() if len(line) > 12 else ""
            return ('VERIFY_DELTA', condition, None)        
        # Replace endpoint variable with actual value
        if self.endpoint:
            line = line.replace('{ENDPOINT}', self.endpoint)
        
        # Replace other variables
        for var_name, var_value in self.variables.items():
            line = line.replace(f'{{{var_name}}}', str(var_value))
        
        # Check for new cache-based test commands (these have different formats)
        parts = line.split(maxsplit=1)
        if len(parts) >= 1:
            cmd = parts[0].lower()
            
            # Commands that work directly with the full line
            if cmd in ['list_writable', 'clear_cache', 'test_set', 'test_set_all', 'export_cache']:
                # These commands are passed directly to IPC
                return (line, expected_value, save_to_var, verify_delta)
            
            # Check if command has special parameters (-- flags or multiple boolean args)
            if cmd in ['get', 'get_instances'] and '--timeout' in line:
                # Pass the full line to preserve parameters
                return (line, expected_value, save_to_var, verify_delta)
            
            # Check if get_supported has boolean parameters
            if cmd == 'get_supported' and ('false' in line.lower() or 'true' in line.lower()):
                # Pass the full line to preserve boolean parameters
                return (line, expected_value, save_to_var, verify_delta)
        
        # Parse standard command format: <cmd> <endpoint> <path> [value]
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            return None
        
        cmd = parts[0].lower()
        endpoint = parts[1]
        path = parts[2]
        value = parts[3] if len(parts) > 3 else ""
        
        # Build IPC command string with annotations
        if cmd in ['get', 'get_supported', 'get_instances']:
            return (f"{cmd} {endpoint} {path}", expected_value, save_to_var, verify_delta)
        elif cmd == 'set':
            # SET command requires a value
            if len(parts) < 4 or not value.strip():
                print(f"    [WARNING] SET command missing value: {line}")
                return None
            return (f"{cmd} {endpoint} {path} {value}", expected_value, None, None)
        elif cmd == 'add':
            return (f"{cmd} {endpoint} {path}", expected_value, None, None)
        elif cmd == 'delete':
            return (f"{cmd} {endpoint} {path}", expected_value, None, None)
        else:
            print(f"    [WARNING] Unknown command: {cmd}")
            return None
    
    def extract_numeric_value(self, response_msg):
        """Extract numeric value from response message"""
        import re
        
        if not isinstance(response_msg, str):
            return None
        
        # Try to extract pattern: ParamName=12345
        match = re.search(r'=(\d+)(?:\s|$)', response_msg)
        if match:
            return int(match.group(1))
        
        # Try standalone number
        match = re.search(r'^\s*(\d+)\s*$', response_msg)
        if match:
            return int(match.group(1))
        
        return None
    
    def verify_delta_condition(self, condition_str):
        """Verify delta condition like: VAR_AFTER - VAR_BEFORE > 500"""
        import re
        
        # Parse: VAR1 - VAR2 > 500 or VAR1 - VAR2 >= 500
        match = re.match(r'(\w+)\s*-\s*(\w+)\s*([><]=?)\s*(\d+)', condition_str)
        if not match:
            print(f"    [WARNING] Invalid delta condition: {condition_str}")
            return False
        
        var1_name, var2_name, operator, threshold = match.groups()
        threshold = int(threshold)
        
        if var1_name not in self.variables or var2_name not in self.variables:
            print(f"    [ERROR] Variables not found: {var1_name}={self.variables.get(var1_name)}, {var2_name}={self.variables.get(var2_name)}")
            return False
        
        val1 = self.variables[var1_name]
        val2 = self.variables[var2_name]
        
        try:
            val1 = int(val1)
            val2 = int(val2)
        except ValueError:
            print(f"    [ERROR] Non-numeric values: {var1_name}={val1}, {var2_name}={val2}")
            return False
        
        delta = val1 - val2
        print(f"    → Delta calculation: {var1_name}({val1}) - {var2_name}({val2}) = {delta}")
        
        if operator == '>':
            result = delta > threshold
        elif operator == '>=':
            result = delta >= threshold
        elif operator == '<':
            result = delta < threshold
        elif operator == '<=':
            result = delta <= threshold
        else:
            print(f"    [ERROR] Unknown operator: {operator}")
            return False
        
        print(f"    → Condition: {delta} {operator} {threshold} = {result}")
        return result
    
    def extract_instance_number(self, response, path):
        """Extract instance number from add/get_instances response"""
        response_msg = response.get('msg', '') if isinstance(response, dict) else response
        
        # For ADD responses, look for "created instance X"
        if isinstance(response_msg, str) and 'instance' in response_msg.lower():
            import re
            match = re.search(r'instance[:\s]+(\d+)', response_msg, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # For GetInstances response dict
        if isinstance(response, dict) and 'instances' in response:
            instances = response.get('instances', [])
            if instances:
                # Return the first instance
                return instances[0]
        
        # Extract from response text containing paths
        # Example: "Device.Bridging.Bridge.1.\nDevice.Bridging.Bridge.2." -> extract "1"
        # For get_instances, extract the FIRST instance from first line
        import re
        if path.endswith('.') and isinstance(response_msg, str):
            # Split response into lines and process first valid line
            lines = response_msg.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith(path.rstrip('.')):
                    # Extract instance from this line
                    base_obj = path.rstrip('.')
                    pattern = re.escape(base_obj) + r'\.(\d+)\.'
                    match = re.search(pattern, line)
                    if match:
                        return match.group(1)
        
        return None
    
    def discover_bridge_port(self, bridge_alias, port_alias):
        """Discover Bridge/Port instances by Alias and save to variables"""
        import re
        
        if not self.endpoint:
            print("    [ERROR] No endpoint specified for discovery")
            return False
        
        print(f"    [DISCOVER] Finding Bridge (Alias='{bridge_alias}') and Port (Alias='{port_alias}')...")
        
        # Find Bridge
        bridge_inst = self._find_bridge_by_alias(bridge_alias)
        if not bridge_inst:
            print(f"    [FAILED] Could not find Bridge with Alias='{bridge_alias}'")
            return False
        
        # Find Port
        port_inst = self._find_port_by_alias(bridge_inst, port_alias)
        if not port_inst:
            print(f"    [FAILED] Could not find Port with Alias='{port_alias}'")
            return False
        
        # Save to variables
        self.variables['BRIDGE_INST'] = bridge_inst
        self.variables['PORT_INST'] = port_inst
        
        print(f"    [SUCCESS] Discovery completed:")
        print(f"      BRIDGE_INST = {bridge_inst}")
        print(f"      PORT_INST = {port_inst}")
        print(f"      Full path: Device.Bridging.Bridge.{bridge_inst}.Port.{port_inst}.")
        
        return True
    
    def _find_bridge_by_alias(self, target_alias):
        """Find Bridge instance by Alias"""
        import re
        
        # Try Search Path first
        cmd = f'get {self.endpoint} Device.Bridging.Bridge.[Alias="{target_alias}"].'
        resp = self.send_command(cmd)
        if resp and resp.get('status') == 'ok' and resp.get('msg'):
            msg = resp.get('msg', '')
            match = re.search(r'Device\.Bridging\.Bridge\.(\d+)\.', msg)
            if match:
                return match.group(1)
        
        # Fallback: Get all instances and check each
        cmd = f'get_instances {self.endpoint} Device.Bridging.Bridge.'
        resp = self.send_command(cmd)
        if not resp or resp.get('status') != 'ok':
            return None
        
        instances = re.findall(r'Device\.Bridging\.Bridge\.(\d+)\.', resp.get('msg', ''))
        
        for inst in instances:
            cmd = f'get {self.endpoint} Device.Bridging.Bridge.{inst}.Alias'
            resp = self.send_command(cmd)
            if resp and resp.get('status') == 'ok':
                msg = resp.get('msg', '')
                if f'={target_alias}' in msg or f'= {target_alias}' in msg:
                    return inst
        
        return None
    
    def _find_port_by_alias(self, bridge_inst, target_alias):
        """Find Port instance by Alias"""
        import re
        
        # Try Search Path first
        cmd = f'get {self.endpoint} Device.Bridging.Bridge.{bridge_inst}.Port.[Alias="{target_alias}"].'
        resp = self.send_command(cmd)
        if resp and resp.get('status') == 'ok' and resp.get('msg'):
            msg = resp.get('msg', '')
            match = re.search(r'\.Port\.(\d+)\.', msg)
            if match:
                return match.group(1)
        
        # Fallback: Get all instances and check each
        cmd = f'get_instances {self.endpoint} Device.Bridging.Bridge.{bridge_inst}.Port.'
        resp = self.send_command(cmd)
        if not resp or resp.get('status') != 'ok':
            return None
        
        instances = re.findall(r'\.Port\.(\d+)\.', resp.get('msg', ''))
        
        for inst in instances:
            cmd = f'get {self.endpoint} Device.Bridging.Bridge.{bridge_inst}.Port.{inst}.Alias'
            resp = self.send_command(cmd)
            if resp and resp.get('status') == 'ok':
                msg = resp.get('msg', '')
                if f'={target_alias}' in msg or f'= {target_alias}' in msg:
                    return inst
        
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
            
            # Unpack command and annotations
            if isinstance(result, tuple):
                cmd_type = result[0]
                
                # Handle special discover command
                if cmd_type == 'DISCOVER_BRIDGE_PORT':
                    full_line = result[1]
                    parts = full_line.split()
                    if len(parts) >= 3:
                        bridge_alias = parts[1]
                        port_alias = parts[2]
                        print(f"\n[{i}] Special Command: discover_bridge_port {bridge_alias} {port_alias}")
                        success = self.discover_bridge_port(bridge_alias, port_alias)
                        if success:
                            executed += 1
                        else:
                            failed += 1
                            if stop_on_error:
                                print("[ERROR] Stopping due to discovery failure")
                                break
                    else:
                        print(f"\n[{i}] [ERROR] Invalid discover_bridge_port syntax")
                        print("    Usage: discover_bridge_port <bridge_alias> <port_alias>")
                        failed += 1
                        if stop_on_error:
                            break
                    time.sleep(self.delay)
                    continue
                
                # Handle wait_user command
                if cmd_type == 'WAIT_USER':
                    message = result[1]
                    print(f"\n[{i}] Wait Command: {message}")
                    input("    Press Enter to continue...")
                    executed += 1
                    time.sleep(self.delay)
                    continue
                
                # Handle exec command
                if cmd_type == 'EXEC':
                    shell_cmd = result[1]
                    print(f"\\n[{i}] Execute: {shell_cmd}")
                    try:
                        import subprocess
                        process_result = subprocess.run(shell_cmd, shell=True, capture_output=True, text=True, timeout=30)
                        if process_result.stdout:
                            print(f"    Output: {process_result.stdout.strip()[:200]}")
                        if process_result.returncode == 0:
                            print(f"    [SUCCESS] Command executed")
                            executed += 1
                        else:
                            print(f"    [WARNING] Exit code: {process_result.returncode}")
                            if process_result.stderr:
                                print(f"    Error: {process_result.stderr.strip()[:200]}")
                            executed += 1
                    except subprocess.TimeoutExpired:
                        print(f"    [WARNING] Command timeout after 30 seconds")
                        executed += 1
                    except Exception as e:
                        print(f"    [ERROR] Execution failed: {e}")
                        failed += 1
                        if stop_on_error:
                            print("[ERROR] Stopping due to exec failure")
                            break
                    time.sleep(self.delay)
                    continue
                
                # Handle verify_delta command
                if cmd_type == 'VERIFY_DELTA':
                    condition = result[1]
                    print(f"\n[{i}] Verify Delta: {condition}")
                    if self.verify_delta_condition(condition):
                        print(f"    ✓ DELTA VERIFICATION PASSED")
                        executed += 1
                    else:
                        print(f"    ✗ DELTA VERIFICATION FAILED")
                        failed += 1
                        if stop_on_error:
                            print("[ERROR] Stopping due to delta verification failure")
                            break
                    time.sleep(self.delay)
                    continue
                
                # Regular command with annotations
                cmd = result[0]
                expected_value = result[1] if len(result) > 1 else None
                save_to_var = result[2] if len(result) > 2 else None
                verify_delta = result[3] if len(result) > 3 else None
            else:
                cmd = result
                expected_value = None
                save_to_var = None
                verify_delta = None
            
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
                
                # Special handling for export_cache command (async)
                if 'export_cache' in cmd.lower():
                    print(f"    [SUCCESS] {actual_value}")
                    if resp.get('async'):
                        print(f"       ⏳ Export running in background - check daemon logs for completion")
                        print(f"       📊 {resp.get('writable_count', 0)} writable templates, {resp.get('values_count', 0)} values")
                    else:
                        files = resp.get('files', [])
                        if files:
                            print(f"\n    📁 Exported Files:")
                            for f in files:
                                print(f"       • {f}")
                            print()
                else:
                    print(f"    [SUCCESS] {actual_value}")
                
                # Save to variable if requested
                if save_to_var:
                    numeric_value = self.extract_numeric_value(str(actual_value))
                    if numeric_value is not None:
                        self.variables[save_to_var] = numeric_value
                        print(f"    → Saved {save_to_var}={numeric_value}")
                    else:
                        self.variables[save_to_var] = actual_value
                        print(f"    → Saved {save_to_var}={actual_value}")
                
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
                            
                            # Also save named variables based on path
                            if 'Bridge.' in path and 'Port' not in path:
                                self.variables['BRIDGE_INST'] = instance_num
                                print(f"    → Saved BRIDGE_INST={instance_num}")
                            elif 'Port.' in path:
                                self.variables['PORT_INST'] = instance_num
                                print(f"    → Saved PORT_INST={instance_num}")
                
                # Verify delta condition if specified
                if verify_delta:
                    if self.verify_delta_condition(verify_delta):
                        print(f"    ✓ DELTA VERIFICATION PASSED")
                        executed += 1
                    else:
                        print(f"    ✗ DELTA VERIFICATION FAILED")
                        failed += 1
                        if stop_on_error:
                            print("[ERROR] Stopping due to delta verification failure")
                            break
                    time.sleep(self.delay)
                    continue
                
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
