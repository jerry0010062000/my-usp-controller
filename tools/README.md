# Tools Directory

This directory contains test scripts and utilities for USP Controller development.

## 🚀 Development Tools

### Embedded Broker

**NEW**: Lightweight STOMP broker for development and testing.

- `embedded_broker.py` - Embedded STOMP broker (development/test only)
- `test_embedded_broker.py` - Test suite for embedded broker

⚠️ **Warning**: For development/testing only. Use ActiveMQ/RabbitMQ in production.

**Quick Start:**
```bash
# Start standalone broker
python tools/embedded_broker.py

# Test broker functionality
python tools/test_embedded_broker.py
```

## 🧪 Test Scripts

- `mock_agent.py` - Mock USP Agent for testing
- `test_protobuf.py` - Protobuf encoding/decoding tests
- `debug_proto.py` - Debug USP protocol messages
- `test_embedded_broker.py` - Test embedded broker

## 🔧 Utility Scripts

- `collect_dm.py` - Collect data model from agent
- `get_all_dm.py` - Get all supported data models
- `sniff_stomp.py` - STOMP traffic sniffer
- `trigger_discovery.py` - Trigger device discovery

## 📦 Legacy Tools

- `usp_daemon.py` - Old daemon implementation (replaced by `usp_controller.py --daemon`)
- `fix-stomp` - STOMP protocol proxy (deprecated)

## 💡 Usage

These scripts are for development and testing purposes only. For normal operation, use:

```bash
# Development (with embedded broker)
python start_dev.py

# Production (with external broker)
python usp_controller.py
```
