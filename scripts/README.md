# USP Controller Test Scripts

This directory contains automated test scripts for the USP Controller.

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
- After `add` or `get_instances` commands, the instance number is automatically saved to `{INSTANCE}`

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

- `test_dhcpv4_pool.txt` - DHCPv4 Pool configuration test

## Notes

- **Endpoint Variable**: Use `{ENDPOINT}` in scripts for automatic endpoint substitution
- **Auto-selection**: If no endpoint is specified, the first device from devices.json will be used
- **Instance Numbers**: After using `add`, check the new instance number with `get_instances`
- **Search Paths**: ba-cli search paths like `[Filter]` need to be resolved manually
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
