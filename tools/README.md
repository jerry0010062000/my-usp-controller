# Tools Directory

This directory contains test scripts and utilities for USP Controller development.

## Test Scripts

- `mock_agent.py` - Mock USP Agent for testing
- `test_protobuf.py` - Protobuf encoding/decoding tests
- `debug_proto.py` - Debug USP protocol messages

## Utility Scripts

- `collect_dm.py` - Collect data model from agent
- `get_all_dm.py` - Get all supported data models
- `sniff_stomp.py` - STOMP traffic sniffer
- `trigger_discovery.py` - Trigger device discovery

## Legacy

- `usp_daemon.py` - Old daemon implementation (replaced by `usp_controller.py --daemon`)
- `fix-stomp` - STOMP protocol proxy (deprecated)

## Usage

These scripts are for development and testing purposes only. For normal operation, use the main `usp_controller.py` in the root directory.
