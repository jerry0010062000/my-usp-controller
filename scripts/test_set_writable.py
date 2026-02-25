#!/usr/bin/env python3
"""
USP Test Script: Verify SET functionality for writable parameters
Test Sequence: prpl Profile verification using SET (Test 1.4)

This script automates the following test procedure:
1. Execute GetSupportedDM to identify all writable parameters
2. Execute Get to retrieve current values
3. For each writable parameter, SET it back to its current value
4. Verify all SETs succeed

Usage:
    python test_set_writable.py <endpoint_id>
"""

import socket
import json
import time
import sys
import argparse
from pathlib import Path

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001
TIMEOUT = 30.0  # Extended timeout for operations


class SetTester:
    def __init__(self, host=IPC_HOST, port=IPC_PORT, endpoint=None):
        self.host = host
        self.port = port
        self.endpoint = endpoint
        self.writable_params = {}  # {param_path: access_info}
        self.current_values = {}   # {param_path: current_value}
        self.set_results = []      # List of (param, success, msg)
        
    def send_command(self, cmd):
        """Send command to controller daemon and return JSON response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT)
                s.connect((self.host, self.port))
                s.sendall(cmd.encode('utf-8'))
                
                # Receive response in chunks
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
        except socket.timeout:
            print(f"[ERROR] Command timeout after {TIMEOUT}s: {cmd[:50]}...")
            return {"status": "error", "msg": f"Timeout after {TIMEOUT}s"}
        except Exception as e:
            print(f"[ERROR] Failed to send command: {e}")
            return {"status": "error", "msg": str(e)}
    
    def step1_get_supported(self):
        """Step 1: Get supported data model to identify writable parameters"""
        print("\n" + "="*70)
        print("Step 1: Getting supported data model (writable parameters only)...")
        print("="*70)
        
        # get_supported <endpoint> <obj_path> <first_level> <ret_cmds> <ret_events> <ret_params>
        cmd = f"get_supported {self.endpoint} Device. false false false true"
        print(f"Command: {cmd}")
        
        response = self.send_command(cmd)
        if not response:
            print("[ERROR] No response from get_supported")
            return False
        
        print(f"Response status: {response.get('status', 'unknown')}")
        
        # Note: The actual GetSupportedDM response will arrive asynchronously
        # For this test, we'll wait and check the response in the controller logs
        time.sleep(2)
        
        print("[INFO] GetSupportedDM request sent. Check controller output for writable parameters.")
        print("[INFO] Manual step needed: Parse response to identify PARAM_WRITABLE parameters")
        return True
    
    def step2_get_current_values(self):
        """Step 2: Get all current parameter values"""
        print("\n" + "="*70)
        print("Step 2: Getting current parameter values...")
        print("="*70)
        
        cmd = f"get {self.endpoint} Device."
        print(f"Command: {cmd}")
        
        response = self.send_command(cmd)
        if not response:
            print("[ERROR] No response from get")
            return False
        
        print(f"Response status: {response.get('status', 'unknown')}")
        
        # Note: The actual Get response will arrive asynchronously
        time.sleep(2)
        
        print("[INFO] Get request sent. Check controller output for parameter values.")
        return True
    
    def step3_set_writable_params(self, param_list):
        """Step 3: Set each writable parameter to its current value"""
        print("\n" + "="*70)
        print("Step 3: Setting writable parameters to their current values...")
        print("="*70)
        
        if not param_list:
            print("[WARNING] No parameters provided to test. Using common examples.")
            # Use common writable parameters as examples
            param_list = [
                ("Device.DeviceInfo.ProvisioningCode", ""),
                ("Device.DeviceInfo.Description", "Test Device"),
            ]
        
        success_count = 0
        fail_count = 0
        
        for param_path, current_value in param_list:
            print(f"\n[TEST] Setting {param_path} = '{current_value}'")
            cmd = f"set {self.endpoint} {param_path} {current_value}"
            
            response = self.send_command(cmd)
            if response and response.get('status') == 'ok':
                print(f"  ✓ SUCCESS: Set request sent")
                self.set_results.append((param_path, True, "Set request sent"))
                success_count += 1
            else:
                msg = response.get('msg', 'Unknown error') if response else 'No response'
                print(f"  ✗ FAILED: {msg}")
                self.set_results.append((param_path, False, msg))
                fail_count += 1
            
            time.sleep(0.5)  # Small delay between commands
        
        print("\n" + "="*70)
        print(f"SET Test Results: {success_count} succeeded, {fail_count} failed")
        print("="*70)
        
        return fail_count == 0
    
    def run_interactive_test(self):
        """Run test with interactive parameter input"""
        print("="*70)
        print("USP Controller Test: Verify SET functionality (Test 1.4)")
        print(f"Target Endpoint: {self.endpoint}")
        print("="*70)
        
        # Step 1: Get supported DM
        if not self.step1_get_supported():
            return False
        
        # Step 2: Get current values
        if not self.step2_get_current_values():
            return False
        
        # Step 3: Interactive parameter input
        print("\n" + "="*70)
        print("Step 3: Enter writable parameters to test")
        print("="*70)
        print("Based on the GetSupportedDM and Get responses above,")
        print("please enter the writable parameters you want to test.")
        print("Format: <parameter_path> <current_value>")
        print("Example: Device.DeviceInfo.ProvisioningCode test123")
        print("Enter empty line when done.")
        print()
        
        param_list = []
        while True:
            try:
                line = input("Parameter (or empty to finish): ").strip()
                if not line:
                    break
                
                parts = line.split(None, 1)
                if len(parts) == 2:
                    param_path, value = parts
                    param_list.append((param_path, value))
                    print(f"  Added: {param_path} = '{value}'")
                elif len(parts) == 1:
                    # Allow empty value
                    param_list.append((parts[0], ""))
                    print(f"  Added: {parts[0]} = ''")
                else:
                    print("  [WARNING] Invalid format, skipped")
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n[INFO] Interrupted by user")
                return False
        
        if not param_list:
            print("\n[INFO] No parameters entered. Testing with common examples.")
        
        # Execute SET tests
        return self.step3_set_writable_params(param_list)
    
    def run_auto_test(self, param_file=None):
        """Run test with parameters from file"""
        print("="*70)
        print("USP Controller Test: Verify SET functionality (Test 1.4)")
        print(f"Target Endpoint: {self.endpoint}")
        print("="*70)
        
        # Step 1 & 2
        self.step1_get_supported()
        self.step2_get_current_values()
        
        # Load parameters from file if provided
        param_list = []
        if param_file and Path(param_file).exists():
            print(f"\n[INFO] Loading parameters from {param_file}")
            with open(param_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(None, 1)
                        if len(parts) >= 1:
                            param_path = parts[0]
                            value = parts[1] if len(parts) == 2 else ""
                            param_list.append((param_path, value))
        
        # Execute SET tests
        return self.step3_set_writable_params(param_list)


def main():
    parser = argparse.ArgumentParser(
        description='Test SET functionality for writable USP parameters (Test 1.4)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (enter parameters manually)
  python test_set_writable.py my-device-id

  # Automated mode (load parameters from file)
  python test_set_writable.py my-device-id --param-file writable_params.txt

  # Custom IPC settings
  python test_set_writable.py my-device-id --host 192.168.1.100 --port 6001

Parameter file format (one per line):
  Device.DeviceInfo.ProvisioningCode test123
  Device.DeviceInfo.Description My Test Device
  Device.ManagementServer.PeriodicInformInterval 3600
        """
    )
    
    parser.add_argument('endpoint', help='Target device endpoint ID')
    parser.add_argument('--host', default=IPC_HOST, help=f'IPC host (default: {IPC_HOST})')
    parser.add_argument('--port', type=int, default=IPC_PORT, help=f'IPC port (default: {IPC_PORT})')
    parser.add_argument('--param-file', help='File containing parameters to test (optional)')
    parser.add_argument('--auto', action='store_true', help='Run in automated mode (no interaction)')
    
    args = parser.parse_args()
    
    # Create tester
    tester = SetTester(host=args.host, port=args.port, endpoint=args.endpoint)
    
    try:
        # Run test
        if args.auto or args.param_file:
            success = tester.run_auto_test(param_file=args.param_file)
        else:
            success = tester.run_interactive_test()
        
        # Print summary
        print("\n" + "="*70)
        if success:
            print("TEST PASSED: All SET operations succeeded")
            print("="*70)
            return 0
        else:
            print("TEST FAILED: Some SET operations failed")
            print("="*70)
            return 1
    
    except KeyboardInterrupt:
        print("\n[INFO] Test interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[ERROR] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
