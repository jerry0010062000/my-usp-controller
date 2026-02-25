#!/usr/bin/env python3
"""
Smart Bridge/Port Finder
智能 Bridge/Port 查找工具 - 適配不支持 Search Path 的 Agent
"""

import sys
import socket
import json
import re

IPC_HOST = '127.0.0.1'
IPC_PORT = 6001

def send_ipc_command(cmd, endpoint, path):
    """Send command via IPC and return result"""
    full_cmd = f"{cmd} {endpoint} {path}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((IPC_HOST, IPC_PORT))
        sock.sendall(full_cmd.encode('utf-8'))
        response = sock.recv(8192).decode('utf-8')
        sock.close()
        return json.loads(response)
    except Exception as e:
        return {"status": "error", "msg": str(e)}

def find_bridge_by_alias(endpoint, target_alias):
    """
    查找具有指定 Alias 的 Bridge
    返回: bridge_instance_number 或 None
    """
    print(f"🔍 查找 Alias='{target_alias}' 的 Bridge...")
    
    # 先嘗試 Search Path（如果 Agent 支持）
    search_result = send_ipc_command("get", endpoint, 
                                     f'Device.Bridging.Bridge.[Alias=="{target_alias}"].')
    if search_result.get("status") == "ok" and search_result.get("msg"):
        print(f"  ✓ Search Path 成功")
        # Extract instance from returned path
        msg = search_result.get("msg", "")
        match = re.search(r'Device\.Bridging\.Bridge\.(\d+)\.', msg)
        if match:
            return match.group(1)
    
    print(f"  ⚠ Search Path 不支援，使用逐一查詢...")
    
    # Fallback: 獲取所有實例並逐一檢查
    instances_result = send_ipc_command("get_instances", endpoint, "Device.Bridging.Bridge.")
    if instances_result.get("status") != "ok":
        print(f"  ✗ 無法獲取 Bridge 實例")
        return None
    
    instances = re.findall(r'Device\.Bridging\.Bridge\.(\d+)\.', instances_result.get("msg", ""))
    
    for inst in instances:
        # 獲取該實例的 Alias
        result = send_ipc_command("get", endpoint, f"Device.Bridging.Bridge.{inst}.Alias")
        if result.get("status") == "ok":
            msg = result.get("msg", "")
            # Extract Alias value
            if f"={target_alias}" in msg or f"= {target_alias}" in msg:
                print(f"  ✓ 找到: Bridge.{inst} (Alias={target_alias})")
                return inst
    
    print(f"  ✗ 未找到 Alias='{target_alias}' 的 Bridge")
    return None

def find_port_by_alias(endpoint, bridge_inst, target_alias):
    """
    查找指定 Bridge 下具有指定 Alias 的 Port
    返回: port_instance_number 或 None
    """
    print(f"🔍 查找 Bridge.{bridge_inst} 下 Alias='{target_alias}' 的 Port...")
    
    # 先嘗試 Search Path
    search_result = send_ipc_command("get", endpoint,
                                     f'Device.Bridging.Bridge.{bridge_inst}.Port.[Alias=="{target_alias}"].')
    if search_result.get("status") == "ok" and search_result.get("msg"):
        print(f"  ✓ Search Path 成功")
        msg = search_result.get("msg", "")
        match = re.search(r'\.Port\.(\d+)\.', msg)
        if match:
            return match.group(1)
    
    print(f"  ⚠ Search Path 不支援，使用逐一查詢...")
    
    # Fallback: 獲取所有 Port 實例並逐一檢查
    instances_result = send_ipc_command("get_instances", endpoint,
                                        f"Device.Bridging.Bridge.{bridge_inst}.Port.")
    if instances_result.get("status") != "ok":
        print(f"  ✗ 無法獲取 Port 實例")
        return None
    
    instances = re.findall(r'\.Port\.(\d+)\.', instances_result.get("msg", ""))
    
    for inst in instances:
        # 獲取該實例的 Alias
        result = send_ipc_command("get", endpoint, 
                                  f"Device.Bridging.Bridge.{bridge_inst}.Port.{inst}.Alias")
        if result.get("status") == "ok":
            msg = result.get("msg", "")
            if f"={target_alias}" in msg or f"= {target_alias}" in msg:
                print(f"  ✓ 找到: Port.{inst} (Alias={target_alias})")
                return inst
    
    print(f"  ✗ 未找到 Alias='{target_alias}' 的 Port")
    return None

def get_parameter(endpoint, path, param_name=""):
    """獲取參數值"""
    full_path = path + param_name
    result = send_ipc_command("get", endpoint, full_path)
    
    if result.get("status") == "ok":
        return result.get("msg", "").strip()
    else:
        return f"ERROR: {result.get('msg', 'Unknown error')}"

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python find_bridge_port.py <endpoint> [bridge_alias] [port_alias]")
        print("")
        print("Examples:")
        print("  python find_bridge_port.py proto::agent-id lan lan")
        print("  python find_bridge_port.py proto::agent-id ETH2 ETH1")
        sys.exit(1)
    
    endpoint = sys.argv[1]
    bridge_alias = sys.argv[2] if len(sys.argv) > 2 else "lan"
    port_alias = sys.argv[3] if len(sys.argv) > 3 else "lan"
    
    print("=" * 70)
    print("Smart Bridge/Port Finder")
    print("=" * 70)
    print(f"Endpoint: {endpoint}")
    print(f"Target Bridge Alias: '{bridge_alias}'")
    print(f"Target Port Alias: '{port_alias}'")
    print()
    
    # 查找 Bridge
    bridge_inst = find_bridge_by_alias(endpoint, bridge_alias)
    if not bridge_inst:
        print("\n✗ 失敗：無法找到指定的 Bridge")
        print("\n建議：")
        print("1. 檢查 Agent 是否有配置 Bridge")
        print("2. 確認 Bridge Alias 設定是否正確")
        print("3. 使用調試工具: python scripts/debug_bridge_searchpath.py <endpoint>")
        sys.exit(1)
    
    print()
    
    # 查找 Port
    port_inst = find_port_by_alias(endpoint, bridge_inst, port_alias)
    if not port_inst:
        print("\n✗ 失敗：無法找到指定的 Port")
        print("\n建議：")
        print(f"1. 檢查 Bridge.{bridge_inst} 是否有配置 Port")
        print("2. 確認 Port Alias 設定是否正確")
        sys.exit(1)
    
    print()
    print("=" * 70)
    print("✓ 成功找到目標")
    print("=" * 70)
    
    bridge_path = f"Device.Bridging.Bridge.{bridge_inst}."
    port_path = f"Device.Bridging.Bridge.{bridge_inst}.Port.{port_inst}."
    
    print(f"Bridge 路徑: {bridge_path}")
    print(f"Port 路徑:   {port_path}")
    print()
    
    # 獲取一些常用參數
    print("=" * 70)
    print("Port 資訊")
    print("=" * 70)
    
    params = [
        "Enable",
        "Status",
        "LastChange",
        "Stats.BytesSent",
        "Stats.BytesReceived",
        "Stats.PacketsSent",
        "Stats.PacketsReceived"
    ]
    
    for param in params:
        value = get_parameter(endpoint, port_path, param)
        print(f"{param:25s} = {value}")
    
    print()
    print("=" * 70)
    print("可用的完整路徑（用於腳本）")
    print("=" * 70)
    print(f"get {{ENDPOINT}} {port_path}")
    print(f"get {{ENDPOINT}} {port_path}LastChange")
    print(f"get {{ENDPOINT}} {port_path}Stats.BytesSent")
    print("=" * 70)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n中斷執行")
    except Exception as e:
        print(f"\n✗ 錯誤: {e}")
        import traceback
        traceback.print_exc()
