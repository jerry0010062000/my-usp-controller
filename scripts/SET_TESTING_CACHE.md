# SET Testing Cache System - Quick Reference

## Overview

The controller now includes a caching system that stores:
1. **Writable parameters** from `get_supported` responses
2. **Parameter values** from `get` responses

This allows step-by-step testing of SET operations without manual parsing.

## New Commands

### `list_writable [endpoint]`
List cached writable parameters for an endpoint

**Usage:**
```bash
# List writable params for specific endpoint
list_writable proto::agent-id

# List all endpoints with cached data
list_writable
```

**Response includes:**
- Total writable parameters
- Parameters with cached values (ready to test)
- Parameters without values (need GET first)

### `test_set <endpoint> <param_path>`
Test setting a specific writable parameter to its cached value

**Usage:**
```bash
test_set proto::agent-id Device.DeviceInfo.ProvisioningCode
test_set proto::agent-id Device.DeviceInfo.Description
```

**Requirements:**
- Parameter must be in writable cache (run get_supported first)
- Parameter value must be cached (run get first)

### `test_set_all <endpoint> [--delay seconds]`
Test setting all writable parameters with cached values

**Usage:**
```bash
# Test all with 0.5s delay (default)
test_set_all proto::agent-id

# Test all with 1.0s delay between SETs
test_set_all proto::agent-id --delay 1.0

# Test all with no delay
test_set_all proto::agent-id --delay 0
```

**Behavior:**
- Runs in background (non-blocking)
- Tests only parameters with cached values
- Reports success/failure for each parameter

### `clear_cache [endpoint]`
Clear cached data

**Usage:**
```bash
# Clear cache for specific endpoint
clear_cache proto::agent-id

# Clear all caches
clear_cache
```

## Typical Workflow

### For Large Devices (1000+ writable parameters)

See [LARGE_PARAMETER_TESTING.md](../LARGE_PARAMETER_TESTING.md) for detailed guidance on handling devices with 10,000+ total parameters.

**Quick tips:**
- Use `--timeout` for GET: `get proto::agent-id Device. --timeout 120`
- Adjust delay: `test_set_all proto::agent-id --delay 0.1`
- Monitor progress: `--batch-size 50` for regular updates
- Expect 5-15 minutes for 1000-2000 writable parameters

### Standard Workflow

### Step 1: Cache writable parameters
```bash
get_supported proto::agent-id Device. false false false true
```
This command:
- Queries the data model
- Automatically caches all writable parameters
- Shows parameter count in logs

### Step 2: Cache current values
```bash
get proto::agent-id Device.
```
This command:
- Retrieves all parameter values
- Automatically caches values
- Shows parameter count in logs

### Step 3: List what's ready to test
```bash
list_writable proto::agent-id
```
Response shows:
```json
{
  "status": "ok",
  "endpoint": "proto::agent-id",
  "total": 45,
  "with_values": 42,
  "without_values": 3,
  "params_ready": [
    {
      "path": "Device.DeviceInfo.ProvisioningCode",
      "access": "PARAM_READ_WRITE",
      "type": "PARAM_STRING",
      "value": "test123"
    },
    ...
  ],
  "params_need_get": [...]
}
```

### Step 4a: Test parameters one by one
```bash
# Test specific parameters individually
test_set proto::agent-id Device.DeviceInfo.ProvisioningCode
test_set proto::agent-id Device.DeviceInfo.Description
test_set proto::agent-id Device.ManagementServer.PeriodicInformInterval
```

**Benefits:**
- Fine-grained control
- See immediate result per parameter
- Easy to verify each SET operation

### Step 4b: Test all at once
```bash
# Test all writable parameters in batch
test_set_all proto::agent-id --delay 0.5
```

**Benefits:**
- Quick comprehensive test
- Automatic delay between operations
- Background execution (non-blocking)

### Step 5: Clear cache when done
```bash
clear_cache proto::agent-id
```

## Integration with Test Scripts

### In test script (prpl_hl-api-cert.1.4.txt):
```bash
# Cache writable params and values
get_supported {ENDPOINT} Device. false false false true
get {ENDPOINT} Device.

# List what's available
list_writable {ENDPOINT}

# Test individually or in batch
test_set {ENDPOINT} Device.DeviceInfo.ProvisioningCode
# or
test_set_all {ENDPOINT}

# Clean up
clear_cache {ENDPOINT}
```

### Via Python (test_set_writable.py):
Still available for fully automated testing:
```bash
python scripts/test_set_writable.py proto::agent-id --param-file params.txt
```

## Advantages

1. **No manual parsing**: Controller automatically identifies and stores writable parameters
2. **Step-by-step testing**: Test parameters individually for detailed verification
3. **Batch testing**: Or test all at once for quick comprehensive check
4. **Value validation**: Ensures SET uses actual current values from device
5. **Persistent across commands**: Cache persists in daemon, can test parameters anytime
6. **Clear visibility**: `list_writable` shows exactly what's ready to test

## Error Handling

**No cached writable parameters:**
```bash
$ test_set proto::agent-id Device.Some.Param
Error: No cached writable parameters for proto::agent-id. 
Run 'get_supported proto::agent-id Device.' first.
```

**No cached value:**
```bash
$ test_set proto::agent-id Device.Some.Param
Error: No cached value for Device.Some.Param. 
Run 'get proto::agent-id Device.Some.Param' first.
```

**Parameter not writable:**
```bash
$ test_set proto::agent-id Device.DeviceInfo.SerialNumber
Error: Parameter Device.DeviceInfo.SerialNumber not found in writable cache. 
It may not be writable.
```

## Cache Lifecycle

- **Created**: When `get_supported` or `get` responses are received
- **Updated**: Each `get_supported` or `get` adds to cache (doesn't replace)
- **Cleared**: When `clear_cache` is called or daemon restarts
- **Persists**: Across multiple IPC commands (while daemon is running)

## Notes

- Cache is per-endpoint, allowing testing multiple devices simultaneously
- Writable parameters include both READ_WRITE and WRITE_ONLY access
- Cache updates automatically on every `get` and `get_supported` response
- Batch testing (`test_set_all`) runs in background to avoid blocking
- All SET operations use the exact cached value (ensures no data modification)
