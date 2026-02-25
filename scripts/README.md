# USP Controller Test Scripts

This directory contains automated test scripts for the USP Controller.

## Quick Reference

### Auto-Discovery Command (⭐ New!)

在腳本中聲明需要發現的實例，框架自動執行：

```bash
# 在腳本開頭添加
discover_bridge_port lan lan

# 後續使用變數
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.Stats.BytesSent
```

**優勢**：
- ✅ UI 不需要修改 - 完全通用
- ✅ 跨環境自動適配 - 無需手動調整
- ✅ 可擴展模式 - 容易添加其他元件發現
- ✅ 清晰可讀 - 腳本明確聲明依賴

### Standard Commands

- `get {ENDPOINT} <path>` - 獲取參數值
- `set {ENDPOINT} <path> <value>` - 設置參數值
- `add {ENDPOINT} <path>` - 添加對象實例
- `delete {ENDPOINT} <path>` - 刪除對象實例
- `get_instances {ENDPOINT} <path>` - 獲取對象實例

## Quick Start

1. **Start the controller daemon:**
   ```bash
   python usp_controller.py --daemon --force
   ```

2. **List available devices:**
   ```bash
   cd scripts
   python run_test.py --list-devices
   ```

3. **Run a test script:**
   ```bash
   python run_test.py test_dhcpv4_pool.txt
   ```
   
   The script will automatically use the first device from devices.json. To specify a different device:
   ```bash
   python run_test.py test_dhcpv4_pool.txt -e proto::agent-id
   ```

## Test Script Format

Test scripts use a simple text format with one command per line:

```
<command> <endpoint> <path> [value]
```

**Variable Substitution:**
- Use `{ENDPOINT}` as a placeholder for the target endpoint ID
- The endpoint will be automatically replaced at runtime based on the `-e` parameter or the first device in devices.json
- Use `{INSTANCE}` to reference the last created or queried instance number
- Use `{BRIDGE_INST}` to reference Bridge instance (auto-detected from get_instances or discover_bridge_port)
- Use `{PORT_INST}` to reference Port instance (auto-detected from get_instances or discover_bridge_port)
- After `add` or `get_instances` commands, instance numbers are automatically saved

**Auto-Discovery Command:**
- Use `discover_bridge_port <bridge_alias> <port_alias>` to automatically find Bridge/Port instances
- This command sets `{BRIDGE_INST}` and `{PORT_INST}` variables automatically
- Works with both UI and command-line execution
- Handles agents that don't support Search Path syntax
- Example: `discover_bridge_port lan lan`

**Value Assertions:**
- Add `# expect: value` at the end of any command line to verify the response
- The test will fail if the actual response doesn't contain the expected value
- Example: `get {ENDPOINT} Device.DHCPv4.Server.Pool.1.Enable # expect: true`

### Supported Commands

- `get <endpoint> <path>` - Get parameter values
- `set <endpoint> <path> <value>` - Set parameter value
- `add <endpoint> <path>` - Add object instance
- `delete <endpoint> <path>` - Delete object instance
- `get_supported <endpoint> <path>` - Get supported data model
- `get_instances <endpoint> <path>` - Get object instances
- `discover_bridge_port <bridge_alias> <port_alias>` - Auto-discover Bridge/Port instances (special command)

### Script Example

```
# Get current pool configuration and verify
get {ENDPOINT} Device.DHCPv4.Server.Pool.1.Enable # expect: true

# Modify pool range
set {ENDPOINT} Device.DHCPv4.Server.Pool.1.MinAddress 192.168.1.5
set {ENDPOINT} Device.DHCPv4.Server.Pool.1.MaxAddress 192.168.1.7

# Verify the change
get {ENDPOINT} Device.DHCPv4.Server.Pool.1.MinAddress # expect: 192.168.1.5

# Add new pool (instance number saved to {INSTANCE})
add {ENDPOINT} Device.DHCPv4.Server.Pool.

# Get instances to confirm (updates {INSTANCE} variable)
get_instances {ENDPOINT} Device.DHCPv4.Server.Pool.

# Configure the new pool using {INSTANCE}
set {ENDPOINT} Device.DHCPv4.Server.Pool.{INSTANCE}.Enable true
set {ENDPOINT} Device.DHCPv4.Server.Pool.{INSTANCE}.MinAddress 192.168.1.10

# Delete the instance
delete {ENDPOINT} Device.DHCPv4.Server.Pool.{INSTANCE}.
```

### Dynamic Instance Discovery Example

**Recommended: Using Auto-Discovery Command ⭐**

The `discover_bridge_port` command automatically finds Bridge/Port instances by Alias, handling agents that don't support Search Path:

```
# Auto-discover and set BRIDGE_INST and PORT_INST variables
discover_bridge_port lan lan

# Use the discovered instances
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.Stats.BytesSent
```

**Benefits:**
- ✅ Works across different environments automatically
- ✅ No manual path adjustment needed
- ✅ Handles agents without Search Path support
- ✅ UI and command-line compatible
- ✅ Extensible pattern for other components

**Alternative: Manual get_instances Method**

For maximum portability across different environments, use manual instance discovery:

```
# Find Bridge instances (saves first instance to {BRIDGE_INST})
get_instances {ENDPOINT} Device.Bridging.Bridge.

# Find Port instances under the Bridge (saves first instance to {PORT_INST})
get_instances {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.

# Access the Port using discovered instances
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.LastChange
```

Note: This approach may have limitations with some agents' get_instances behavior.

## Test Runner Options

```bash
python run_test.py <script> [options]
```

### Options

- `-e, --endpoint <id>` - Target endpoint ID (uses first device from devices.json if not specified)
- `-l, --list-devices` - List available devices from devices.json
- `-i, --interactive` - Interactive mode (confirm each command)
- `-s, --stop-on-error` - Stop execution on first error
- `-d, --delay <seconds>` - Delay between commands (default: 0.5)
- `--host <host>` - IPC server host (default: 127.0.0.1)
- `--port <port>` - IPC server port (default: 6001)

### Examples

**List available devices:**
```bash
python run_test.py --list-devices
```

**Run test with auto-selected device (first in devices.json):**
```bash
python run_test.py test_dhcpv4_pool.txt
```

**Run test with specific endpoint:**
```bash
python run_test.py test_dhcpv4_pool.txt -e proto::agent-id
```

**Interactive mode (confirm each step):**
```bash
python run_test.py test_dhcpv4_pool.txt -i
```

**Stop on first error:**
```bash
python run_test.py test_dhcpv4_pool.txt -s
```

**Custom delay (1 second between commands):**
```bash
python run_test.py test_dhcpv4_pool.txt -d 1.0
```

## Converting ba-cli Scripts

To convert ba-cli format scripts to USP Controller format:

### ba-cli to USP Controller Mapping

| ba-cli Syntax | USP Controller Command |
|---------------|------------------------|
| `Path?` | `get <endpoint> Path` |
| `Path?0` | `get <endpoint> Path` |
| `Path=value` | `set <endpoint> Path value` |
| `Path.{Param1=val1, Param2=val2}` | Multiple `set` commands |
| `Path.+{params}` | `add` + multiple `set` |
| `Path.-` | `delete <endpoint> Path` |
| `Path.[Filter].` | Get instances first, then use specific path |

### Example Conversion

**ba-cli:**
```
Device.DHCPv4.Server.Pool.1.{MinAddress="192.168.1.5", MaxAddress="192.168.1.7"}
```

**USP Controller:**
```
set {ENDPOINT} Device.DHCPv4.Server.Pool.1.MinAddress 192.168.1.5
set {ENDPOINT} Device.DHCPv4.Server.Pool.1.MaxAddress 192.168.1.7
```

## Available Test Scripts

### General Tests
- `test_dhcpv4_pool.txt` - DHCPv4 Pool configuration test

### Bridge/Port Tests (prplos.1.1.*.txt)

Bridge and Port statistics verification tests using **unified auto-discovery format**.

**All 11 scripts now use** `discover_bridge_port` **for zero-configuration operation across any environment.**

**Script Structure:**
```bash
# 0. Auto-discover Bridge and Port instances
discover_bridge_port lan lan

# 1. Get Port parameters from the data model
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.

# 2. Get specific statistic
get {ENDPOINT} Device.Bridging.Bridge.{BRIDGE_INST}.Port.{PORT_INST}.Stats.XXX
```

**Available Scripts:**
- `prplos.1.1.3.txt` - Verify Port LastChange parameter
- `prplos.1.1.4.txt` - Verify Port BytesSent statistics
- `prplos.1.1.5.txt` - Verify Port BytesReceived statistics
- `prplos.1.1.6.txt` - Verify Port PacketsSent statistics
- `prplos.1.1.7.txt` - Verify Port PacketsReceived statistics
- `prplos.1.1.8.txt` - Verify Port UnicastPacketsSent statistics
- `prplos.1.1.9.txt` - Verify Port UnicastPacketsReceived statistics
- `prplos.1.1.10.txt` - Verify Port MulticastPacketsSent statistics
- `prplos.1.1.11.txt` - Verify Port MulticastPacketsReceived statistics
- `prplos.1.1.12.txt` - Verify Port BroadcastPacketsSent statistics
- `prplos.1.1.13.txt` - Verify Port BroadcastPacketsReceived statistics

**Advantages:**
- ✅ **Zero configuration** - No path adjustment needed for different environments
- ✅ **Universal** - Works with any instance numbers (Bridge.X.Port.Y)
- ✅ **Smart fallback** - Tries Search Path first, gracefully falls back to iterative discovery
- ✅ **UI & CLI compatible** - Works seamlessly in both execution modes
- ✅ **Self-contained** - Each script is independent and complete
- ✅ **Extensible pattern** - Template for other components (WiFi, Ethernet, DHCPv4, etc.)

**Usage:**
```bash
# Command-line
python run_test.py prplos.1.1.4.txt -e proto::agent-id

# Via UI: Select and run - auto-discovery happens automatically!
```

**For Custom Alias Values:**
Edit the script and change the discover command:
```bash
discover_bridge_port <your_bridge_alias> <your_port_alias>
```

### HL-API Certification Tests (prpl_hl-api-cert.*.txt)
High-Level API certification test sequences for prplOS compliance.

**Test Scripts:**
- `prpl_hl-api-cert.1.1.txt` - GetSupportedDM from top level (complete data model)
- `prpl_hl-api-cert.1.2.txt` - Parameter Write requirement verification
- `prpl_hl-api-cert.1.3.txt` - Profile verification using GET
- `prpl_hl-api-cert.1.4.txt` - Profile verification using SET
- `prpl_hl-api-cert.1.5.txt` - Add and Delete verification

**Test 1.4 - SET Verification (Multiple Testing Approaches):**

The controller now includes a **caching system** that stores writable parameters and their values, enabling step-by-step SET testing.

#### Method 1: Interactive Step-by-Step Testing (⭐ Recommended)

Cache data and test parameters one by one:

```bash
# Step 1: Cache writable parameters
get_supported proto::agent-id Device. false false false true

# Step 2: Cache current values
get proto::agent-id Device.

# Step 3: List what's ready to test
list_writable proto::agent-id

# Step 4a: Test parameters individually
test_set proto::agent-id Device.DeviceInfo.ProvisioningCode
test_set proto::agent-id Device.DeviceInfo.Description

# Step 4b: Or test all at once
test_set_all proto::agent-id --delay 0.5

# Step 5: Clear cache when done
clear_cache proto::agent-id
```

**New Commands:**
- `list_writable [endpoint]` - List cached writable parameters with values
- `test_set <endpoint> <param_path>` - Test SET on specific parameter
- `test_set_all <endpoint> [--delay seconds]` - Test SET on all cached parameters
- `clear_cache [endpoint]` - Clear cached data

**Benefits:**
- ✅ Fine-grained control over testing
- ✅ See immediate result for each parameter
- ✅ No manual parsing of responses
- ✅ Cache persists across commands
- ✅ Easy to verify individual SET operations

See [SET_TESTING_CACHE.md](SET_TESTING_CACHE.md) for complete documentation.

#### Method 2: Automated Python Script

For fully automated testing with parameter files:

```bash
# Interactive mode - enter parameters manually
python test_set_writable.py <endpoint_id>

# Automated mode - load parameters from file
python test_set_writable.py <endpoint_id> --param-file test_set_params.txt
```

**What it does:**
1. Execute `get_supported` to identify all writable parameters
2. Execute `get` to retrieve current values
3. For each writable parameter, SET it back to its current value
4. Verify all SET operations succeed

**Parameter file format** (see `test_set_params_example.txt`):
```
# Format: <parameter_path> <value>
Device.DeviceInfo.ProvisioningCode test123
Device.DeviceInfo.Description My Test Device
Device.ManagementServer.PeriodicInformInterval 3600
```

**Usage examples:**
```bash
# Interactive mode (manual parameter entry)
python test_set_writable.py proto::agent-id

# With parameter file
python test_set_writable.py proto::agent-id --param-file my_params.txt

# Custom IPC settings
python test_set_writable.py proto::agent-id --host 192.168.1.100 --port 6001
```

## Utility Tools

### Auto-Discovery Pattern (Extensible) ⭐

The `discover_bridge_port` command is an example of the extensible discovery pattern. You can create similar discovery commands for other components:

**Current implementation:**
- `discover_bridge_port <bridge_alias> <port_alias>` - Discover Bridge/Port

**Potential extensions** (can be added to run_test.py):
- `discover_wifi_ssid <ssid_name>` - Discover WiFi.SSID by SSID name
- `discover_ethernet_interface <interface_name>` - Discover Ethernet.Interface
- `discover_dhcp_pool <pool_name>` - Discover DHCPv4.Server.Pool

**Pattern structure:**
1. Define discovery command in script
2. run_test.py/UI recognizes command
3. Executes smart discovery (Search Path → fallback)
4. Sets variables for use in subsequent commands
5. Script continues with discovered instances

**Benefits for complex testing:**
- No UI complexity - logic stays in test framework
- Scales to any number of components
- Each test script declares its own dependencies
- Clear, readable test scripts

### find_bridge_port.py
Smart tool to locate Bridge/Port by Alias from command line.

**Usage:**
```bash
# Find Bridge and Port with Alias "lan"
python find_bridge_port.py proto::agent-id lan lan

# Find with specific Alias values
python find_bridge_port.py proto::agent-id <bridge_alias> <port_alias>
```

**Output:**
- Shows the actual instance paths (e.g., `Device.Bridging.Bridge.1.Port.1.`)
- Displays key Port parameters (Status, Enable, LastChange, statistics)
- Provides ready-to-use commands for scripts

**Note:** For automated testing, use `discover_bridge_port` command in scripts instead.

## Notes

- **Endpoint Variable**: Use `{ENDPOINT}` in scripts for automatic endpoint substitution
- **Auto-selection**: If no endpoint is specified, the first device from devices.json will be used
- **Instance Numbers**: After using `add`, check the new instance number with `get_instances`
- **Search Paths**: Many agents don't support USP Search Path syntax like `[Alias=="value"]`. Use `get_instances` to find instance numbers, then use direct paths like `Device.Bridging.Bridge.1.Port.1.`
- **Batch Operations**: ba-cli batch set `{Param1, Param2}` must be split into separate commands

## Troubleshooting

**Connection refused:**
- Ensure the controller daemon is running (`python usp_controller.py --daemon`)
- Check IPC port is not in use (default: 6001)

**Command timeout:**
- Increase delay between commands with `-d` option
- Check agent is responding

**Invalid endpoint:**
- Verify agent endpoint ID in devices.json
- Use correct endpoint ID in script
