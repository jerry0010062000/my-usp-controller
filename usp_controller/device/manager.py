#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Device Manager Implementation
Manages USP agent devices, endpoints, reply destinations, status, and persistence.
"""

import os
import json
import threading
from datetime import datetime
from typing import Dict, Optional, Any, List
from pathlib import Path
from ..logger import get_logger

logger = get_logger()

# Optional zeroconf for mDNS
try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceListener, ServiceInfo
    MDNS_AVAILABLE = True
except ImportError:
    MDNS_AVAILABLE = False
    ServiceListener = object


class DeviceManager:
    """
    Device Manager for USP Controller
    """

    def __init__(self, devices_file: str = "devices.json", device_timeout: int = 300):
        self.devices_file = devices_file
        self.device_timeout = device_timeout
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.active_device: Optional[str] = None
        self._lock = threading.RLock()

        # mDNS discovery
        self.mdns_zeroconf = None
        self.mdns_browser = None

        self.load_devices()


    def set_active_device(self, endpoint_id: Optional[str]) -> bool:
        """Set the active default target device"""
        with self._lock:
            if endpoint_id is None or endpoint_id in self.devices:
                self.active_device = endpoint_id
                return True
            # Allow setting an endpoint even if not yet discovered
            self.active_device = endpoint_id
            return True

    def get_active_device(self) -> Optional[str]:
        """Get the active target device endpoint ID"""
        with self._lock:
            if self.active_device:
                return self.active_device
            # If none selected, return the first known device if available
            if self.devices:
                return next(iter(self.devices.keys()))
            return None

    def register_or_update(self, endpoint_id: str, reply_to: Optional[str] = None,
                           discovered_via: str = "message",
                           extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Register or update an agent device in the registry"""
        if not endpoint_id or endpoint_id == "unknown":
            return {}

        with self._lock:
            now_iso = datetime.now().isoformat()
            if endpoint_id not in self.devices:
                # Default reply-to queue if none provided
                if not reply_to:
                    suffix = endpoint_id.split('::')[-1] if '::' in endpoint_id else endpoint_id
                    reply_to = f"/queue/usp.agent.{suffix}"

                self.devices[endpoint_id] = {
                    'reply_to': reply_to,
                    'last_seen': now_iso,
                    'discovered_via': discovered_via,
                    'first_seen': now_iso,
                    **(extra or {})
                }
                logger.success(f"Registered new device: {endpoint_id} -> {reply_to}", level=0)
                # Auto switch active target to newly discovered device if old one is offline or none selected
                if not self.active_device or self.get_device_status(self.active_device) == "offline":
                    self.active_device = endpoint_id
            else:
                dev = self.devices[endpoint_id]
                dev['last_seen'] = now_iso
                if reply_to:
                    dev['reply_to'] = reply_to
                if extra:
                    dev.update(extra)

            self.save_devices()
            return self.devices[endpoint_id].copy()

    def get_device(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Get device information by endpoint ID"""
        with self._lock:
            return self.devices.get(endpoint_id, {}).copy() if endpoint_id in self.devices else None

    def get_reply_destination(self, endpoint_id: str) -> str:
        """Resolve the reply destination for an endpoint ID"""
        with self._lock:
            dev = self.devices.get(endpoint_id)
            if dev and dev.get('reply_to'):
                return dev['reply_to']
            suffix = endpoint_id.split('::')[-1] if '::' in endpoint_id else endpoint_id
            return f"/queue/usp.agent.{suffix}"

    def get_device_status(self, endpoint_id: str) -> str:
        """Get online / offline / unknown status for a device"""
        with self._lock:
            if endpoint_id not in self.devices:
                return "unknown"

            last_seen_str = self.devices[endpoint_id].get('last_seen')
            if not last_seen_str:
                return "unknown"

            try:
                last_seen = datetime.fromisoformat(last_seen_str)
                elapsed = (datetime.now() - last_seen).total_seconds()
                return "online" if elapsed < self.device_timeout else "offline"
            except Exception:
                return "unknown"

    def list_devices(self) -> List[Dict[str, Any]]:
        """List all known devices with status and active marker"""
        with self._lock:
            result = []
            active = self.active_device
            for ep_id, info in self.devices.items():
                last_seen_str = info.get('last_seen', 'N/A')
                status = "unknown"
                if last_seen_str != 'N/A':
                    try:
                        elapsed = (datetime.now() - datetime.fromisoformat(last_seen_str)).total_seconds()
                        status = "online" if elapsed < self.device_timeout else "offline"
                    except Exception:
                        pass

                result.append({
                    'endpoint_id': ep_id,
                    'reply_to': info.get('reply_to', 'N/A'),
                    'last_seen': last_seen_str,
                    'status': status,
                    'is_active': (ep_id == active),
                    'discovered_via': info.get('discovered_via', 'unknown')
                })
            return result

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Alias for list_devices"""
        return self.list_devices()

    def remove_device(self, endpoint_id: str) -> bool:
        """Remove a device from registry"""
        with self._lock:
            if endpoint_id in self.devices:
                del self.devices[endpoint_id]
                if self.active_device == endpoint_id:
                    self.active_device = next(iter(self.devices.keys())) if self.devices else None
                self.save_devices()
                return True
            return False

    def clear_offline_devices(self) -> int:
        """Remove all offline devices from registry"""
        with self._lock:
            offline = [ep for ep in self.devices if self.get_device_status(ep) == "offline"]
            for ep in offline:
                del self.devices[ep]
            if self.active_device not in self.devices:
                self.active_device = next(iter(self.devices.keys())) if self.devices else None
            self.save_devices()
            return len(offline)


    def load_devices(self) -> bool:
        """Load devices from devices.json"""
        try:
            p = Path(self.devices_file)
            if not p.is_absolute():
                p = Path(os.getcwd()) / p

            if p.exists() and p.stat().st_size > 0:
                with open(p, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        with self._lock:
                            self.devices = data
                            if self.devices and not self.active_device:
                                self.active_device = next(iter(self.devices.keys()))
                        logger.info(f"Loaded {len(self.devices)} device(s) from {p.name}", level=1)
                        return True
            return False

        except Exception as e:
            logger.error(f"Failed to load devices: {e}")
            return False

    def save_devices(self) -> bool:
        """Save devices to devices.json"""
        try:
            p = Path(self.devices_file)
            if not p.is_absolute():
                p = Path(os.getcwd()) / p

            with open(p, 'w', encoding='utf-8') as f:
                with self._lock:
                    json.dump(self.devices, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Failed to save devices: {e}")
            return False

    def scan_mdns(self, timeout: float = 2.5) -> List[Dict[str, Any]]:
        """Active mDNS scan for USP agents"""
        if not MDNS_AVAILABLE:
            logger.info("mDNS scanning unavailable (zeroconf not installed)", level=0)
            return []

        logger.info(f"Starting mDNS agent scan (timeout {timeout}s)...", level=0)
        found_agents = []

        try:
            scan_zc = Zeroconf()

            class ScanListener(ServiceListener):
                def __init__(self):
                    self.items = []

                def add_service(self, zc, type_, name):
                    info = zc.get_service_info(type_, name)
                    if info:
                        self.items.append(info)

                def update_service(self, zc, type_, name):
                    pass

                def remove_service(self, zc, type_, name):
                    pass

            listener = ScanListener()
            browser = ServiceBrowser(scan_zc, "_usp-agent._tcp.local.", listener)
            import time
            time.sleep(timeout)

            for info in listener.items:
                try:
                    props = {}
                    for k, v in info.properties.items():
                        try:
                            props[k.decode('utf-8')] = v.decode('utf-8')
                        except Exception:
                            props[str(k)] = str(v)

                    ep_id = props.get('endpoint', props.get('id', 'unknown'))
                    if ep_id != 'unknown':
                        addr = '.'.join(str(b) for b in info.addresses[0]) if info.addresses else 'unknown'
                        port = info.port
                        registered = self.register_or_update(
                            ep_id,
                            discovered_via="mdns_scan",
                            extra={'address': f"{addr}:{port}", 'service_name': info.name}
                        )
                        found_agents.append(registered)
                except Exception as e:
                    logger.error(f"mDNS scan parse error: {e}")

            scan_zc.close()
            logger.success(f"mDNS scan completed, found {len(found_agents)} agent(s)", level=0)
            return found_agents

        except Exception as e:
            logger.error(f"mDNS scan error: {e}")
            return []
