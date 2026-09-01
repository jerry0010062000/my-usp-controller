#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DUT USP Data Model Configuration Generator
Generates accurate TR-181 (Device:2) and platform-specific configuration guides
(OB-USP-Agent / OpenWrt UCI / Shell Scripts / JSON Profiles) to help engineers
set up their Device Under Test (DUT / Agent) to connect to this Controller.
"""

import socket
from typing import Dict, Any, Optional
from ..config import ControllerConfig


def get_host_lan_ip() -> str:
    """
    Get the primary local LAN IP address of this machine (reachable by external devices on LAN).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "192.168.1.100"


class DUTConfigGenerator:
    """
    DUT USP Data Model 方向指南與參數建議生成器
    提供測試工程師快速了解 DUT (Agent) 應設定哪些 DataModel 參數值以連上當前 Controller 與 Broker。
    """

    @staticmethod
    def _extract_params(config: Optional[ControllerConfig] = None,
                        dut_endpoint_id: Optional[str] = None,
                        broker_host: Optional[str] = None,
                        broker_port: Optional[int] = None) -> Dict[str, Any]:
        """Extract and normalize connection parameters, ensuring external reachable IP for DUT"""
        dut_id = dut_endpoint_id or "proto::agent.001"
        ctrl_id = getattr(config, "controller_endpoint_id", "proto::controller.default") if config else "proto::controller.default"
        rx_topic = getattr(config, "receive_topic", "/queue/usp.controller.default") if config else "/queue/usp.controller.default"

        transport = getattr(config, "transport", None)
        raw_b_host = broker_host or (getattr(transport, "host", "127.0.0.1") if transport else "127.0.0.1")
        b_port = broker_port or (getattr(transport, "port", 61614) if transport else 61614)
        b_user = getattr(transport, "username", "guest") if transport else "guest"
        b_pass = getattr(transport, "password", "guest") if transport else "guest"
        proto = getattr(transport, "protocol", "stomp").upper() if transport else "STOMP"

        # If the broker host is localhost/loopback (127.0.0.1, localhost, 0.0.0.0),
        # an external DUT cannot connect using 127.0.0.1. Automatically resolve to host LAN IP!
        lan_ip = get_host_lan_ip()
        if raw_b_host in ["127.0.0.1", "localhost", "0.0.0.0", "::1", ""]:
            b_host = lan_ip
        else:
            b_host = raw_b_host

        suffix = dut_id.split("::")[-1] if "::" in dut_id else dut_id
        agent_reply_queue = f"/queue/usp.agent.{suffix}"

        return {
            "dut_id": dut_id,
            "ctrl_id": ctrl_id,
            "rx_topic": rx_topic,
            "broker_host": b_host,
            "broker_port": b_port,
            "broker_user": b_user,
            "broker_pass": b_pass,
            "protocol": proto,
            "lan_ip": lan_ip,
            "agent_reply_queue": agent_reply_queue
        }

    @classmethod
    def generate_guide(cls, config: Optional[ControllerConfig] = None,
                       dut_endpoint_id: Optional[str] = None,
                       broker_host: Optional[str] = None,
                       broker_port: Optional[int] = None) -> str:
        """
        生成 DUT 核心 DataModel 參數方向指南與建議值對照表 (核心推薦)
        """
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)

        text = f"""======================================================================
  [DUT TR-181 DataModel 連線設定方向指南 (建議清單)]
======================================================================
  本指南提供外部 DUT 實體設備連線至當前 USP Controller 所需配置的核心參數建議值。

  [!] 重要提示 (Notice):
      Broker IP 必須是 DUT 在區域網路 (LAN) 或外部站點能連通的「實體 IP / 網域名稱」。
      切勿在 DUT 上設定 127.0.0.1 (否則 DUT 會連到它自己本機而失敗)！
      系統已為您自動代入可對外通訊的實體 IP: {p['broker_host']}

[1. DUT Agent 自身身分識別 (Device.LocalAgent.)]
  * Device.LocalAgent.EndpointID
    -> 建議值: "{p['dut_id']}"
    -> 說明:   DUT 自身的唯一識別碼 (通常為 proto::agent.<序號> 或 oui:serial)。

[2. STOMP Broker 連線設定 (Device.STOMP.Connection.1.)]
  * Device.STOMP.Connection.1.Enable
    -> 建議值: true
    -> 說明:   啟用此 STOMP 伺服器連線通道。
  * Device.STOMP.Connection.1.Host
    -> 建議值: "{p['broker_host']}"
    -> 說明:   STOMP Broker 主機的區域網路/實體 IP (不可填 127.0.0.1，需確保 DUT 能 Ping 通)。
  * Device.STOMP.Connection.1.Port
    -> 建議值: {p['broker_port']}
    -> 說明:   STOMP Broker 監聽通訊埠 (預設 61614 或 61613)。
  * Device.STOMP.Connection.1.Username
    -> 建議值: "{p['broker_user']}"
    -> 說明:   STOMP 登入帳號。
  * Device.STOMP.Connection.1.Password
    -> 建議值: "{p['broker_pass']}"
    -> 說明:   STOMP 登入密碼。
  * Device.STOMP.Connection.1.EnableEncryption
    -> 建議值: false
    -> 說明:   是否使用 TLS 加密 (一般測試環境設為 false 走純 TCP)。

[3. DUT 本身接收通道 (Device.LocalAgent.MTP.1.)]
  * Device.LocalAgent.MTP.1.Enable
    -> 建議值: true
  * Device.LocalAgent.MTP.1.Protocol
    -> 建議值: "STOMP"
  * Device.LocalAgent.MTP.1.STOMP.Reference
    -> 建議值: "Device.STOMP.Connection.1."
  * Device.LocalAgent.MTP.1.STOMP.Destination
    -> 建議值: "{p['agent_reply_queue']}"
    -> 說明:   DUT 於 Broker 上的接收佇列 (Controller 會將請求發往此 Topic)。

[4. Controller 白名單與授權 (Device.LocalAgent.Controller.1.)]
  * Device.LocalAgent.Controller.1.Enable
    -> 建議值: true
  * Device.LocalAgent.Controller.1.EndpointID
    -> 建議值: "{p['ctrl_id']}"
    -> 說明:   允許連線並控制 DUT 的 Controller Endpoint ID (必須一致)。

[5. Controller 的訊息送達佇列 (Device.LocalAgent.Controller.1.MTP.1.)]
  * Device.LocalAgent.Controller.1.MTP.1.Enable
    -> 建議值: true
  * Device.LocalAgent.Controller.1.MTP.1.Protocol
    -> 建議值: "STOMP"
  * Device.LocalAgent.Controller.1.MTP.1.STOMP.Reference
    -> 建議值: "Device.STOMP.Connection.1."
  * Device.LocalAgent.Controller.1.MTP.1.STOMP.Destination
    -> 建議值: "{p['rx_topic']}"
    -> 說明:   Controller 接收訊息的 Topic (DUT 的 Response / Notify 會送到此處)。

[6. (選填) 開機自動通知 (Device.LocalAgent.Subscription.1.)]
  * Device.LocalAgent.Subscription.1.Enable = true
  * Device.LocalAgent.Subscription.1.Recipient = "Device.LocalAgent.Controller.1."
  * Device.LocalAgent.Subscription.1.NotifType = "Event"
  * Device.LocalAgent.Subscription.1.ReferenceList = "Device.Boot!"
  * 說明:   讓 DUT 連上 Broker 後自動發送 Boot 封包向 Controller 報到註冊。
======================================================================"""
        return text


    @classmethod

    def generate_tr181_commands(cls, config: Optional[ControllerConfig] = None,
                                dut_endpoint_id: Optional[str] = None,
                                broker_host: Optional[str] = None,
                                broker_port: Optional[int] = None) -> str:
        """標準 TR-181 參數清單 (快速複製)"""
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)
        lines = [
            f"# === TR-181 USP Data Model 參數值設定建議 ===",
            f"Device.LocalAgent.EndpointID = \"{p['dut_id']}\"",
            f"Device.STOMP.Connection.1.Enable = true",
            f"Device.STOMP.Connection.1.Host = \"{p['broker_host']}\"",
            f"Device.STOMP.Connection.1.Port = {p['broker_port']}",
            f"Device.STOMP.Connection.1.Username = \"{p['broker_user']}\"",
            f"Device.STOMP.Connection.1.Password = \"{p['broker_pass']}\"",
            f"Device.STOMP.Connection.1.EnableEncryption = false",
            f"Device.LocalAgent.MTP.1.Enable = true",
            f"Device.LocalAgent.MTP.1.Protocol = \"STOMP\"",
            f"Device.LocalAgent.MTP.1.STOMP.Reference = \"Device.STOMP.Connection.1.\"",
            f"Device.LocalAgent.MTP.1.STOMP.Destination = \"{p['agent_reply_queue']}\"",
            f"Device.LocalAgent.Controller.1.Enable = true",
            f"Device.LocalAgent.Controller.1.EndpointID = \"{p['ctrl_id']}\"",
            f"Device.LocalAgent.Controller.1.MTP.1.Enable = true",
            f"Device.LocalAgent.Controller.1.MTP.1.Protocol = \"STOMP\"",
            f"Device.LocalAgent.Controller.1.MTP.1.STOMP.Reference = \"Device.STOMP.Connection.1.\"",
            f"Device.LocalAgent.Controller.1.MTP.1.STOMP.Destination = \"{p['rx_topic']}\"",
        ]
        return "\n".join(lines)

    @classmethod
    def generate_openwrt_uci(cls, config: Optional[ControllerConfig] = None,
                             dut_endpoint_id: Optional[str] = None,
                             broker_host: Optional[str] = None,
                             broker_port: Optional[int] = None) -> str:
        """OpenWrt / prplOS UCI 指令建議"""
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)
        lines = [
            "# === OpenWrt / prplOS UCI 建議指令 ===",
            f"uci set usp.localagent.EndpointID='{p['dut_id']}'",
            "uci set usp.stomp_conn=stomp_connection",
            "uci set usp.stomp_conn.enable='1'",
            f"uci set usp.stomp_conn.host='{p['broker_host']}'",
            f"uci set usp.stomp_conn.port='{p['broker_port']}'",
            f"uci set usp.stomp_conn.username='{p['broker_user']}'",
            f"uci set usp.stomp_conn.password='{p['broker_pass']}'",
            "uci set usp.agent_mtp=agent_mtp",
            "uci set usp.agent_mtp.enable='1'",
            "uci set usp.agent_mtp.protocol='STOMP'",
            "uci set usp.agent_mtp.stomp_connection='usp.stomp_conn'",
            f"uci set usp.agent_mtp.destination='{p['agent_reply_queue']}'",
            "uci set usp.controller=controller",
            "uci set usp.controller.enable='1'",
            f"uci set usp.controller.endpoint_id='{p['ctrl_id']}'",
            "uci set usp.ctrl_mtp=controller_mtp",
            "uci set usp.ctrl_mtp.enable='1'",
            "uci set usp.ctrl_mtp.protocol='STOMP'",
            "uci set usp.ctrl_mtp.controller='usp.controller'",
            "uci set usp.ctrl_mtp.stomp_connection='usp.stomp_conn'",
            f"uci set usp.ctrl_mtp.destination='{p['rx_topic']}'",
            "uci commit usp",
            "/etc/init.d/obuspa restart 2>/dev/null || /etc/init.d/usp restart 2>/dev/null || true"
        ]
        return "\n".join(lines)


    @classmethod
    def generate_obuspa_config(cls, config: Optional[ControllerConfig] = None,
                               dut_endpoint_id: Optional[str] = None,
                               broker_host: Optional[str] = None,
                               broker_port: Optional[int] = None) -> str:
        """
        Generate Broadband Forum OB-USP-Agent (obuspa) CLI setup commands / config.
        """
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)

        lines = [
            f"# =================================================================",
            f"# Broadband Forum OB-USP-Agent (obuspa) 初始化指令",
            f"# (可作為 obuspa 啟動參數或 -r factory reset 重設腳本)",
            f"# =================================================================",
            "",
            f"obuspa -e \"Device.LocalAgent.EndpointID={p['dut_id']}\" \\",
            f"       -c \"Device.STOMP.Connection.1.Host={p['broker_host']}\" \\",
            f"       -c \"Device.STOMP.Connection.1.Port={p['broker_port']}\" \\",
            f"       -c \"Device.STOMP.Connection.1.Username={p['broker_user']}\" \\",
            f"       -c \"Device.STOMP.Connection.1.Password={p['broker_pass']}\" \\",
            f"       -c \"Device.STOMP.Connection.1.Enable=true\" \\",
            f"       -c \"Device.LocalAgent.MTP.1.Protocol=STOMP\" \\",
            f"       -c \"Device.LocalAgent.MTP.1.STOMP.Reference=Device.STOMP.Connection.1.\" \\",
            f"       -c \"Device.LocalAgent.MTP.1.STOMP.Destination={p['agent_reply_queue']}\" \\",
            f"       -c \"Device.LocalAgent.MTP.1.Enable=true\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.EndpointID={p['ctrl_id']}\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.Enable=true\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.MTP.1.Protocol=STOMP\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.MTP.1.STOMP.Reference=Device.STOMP.Connection.1.\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.MTP.1.STOMP.Destination={p['rx_topic']}\" \\",
            f"       -c \"Device.LocalAgent.Controller.1.MTP.1.Enable=true\""
        ]
        return "\n".join(lines)

    @classmethod
    def generate_shell_script(cls, config: Optional[ControllerConfig] = None,
                              dut_endpoint_id: Optional[str] = None,
                              broker_host: Optional[str] = None,
                              broker_port: Optional[int] = None) -> str:
        """
        Generate standalone executable setup_dut.sh shell script for Linux/Busybox DUT.
        """
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)

        lines = [
            "#!/bin/sh",
            "# =================================================================",
            "# USP DUT Automatic Configuration Script (setup_dut.sh)",
            f"# Generated for Target Controller: {p['ctrl_id']}",
            "# =================================================================",
            "set -e",
            "",
            f"DUT_ENDPOINT=\"{p['dut_id']}\"",
            f"BROKER_HOST=\"{p['broker_host']}\"",
            f"BROKER_PORT=\"{p['broker_port']}\"",
            f"BROKER_USER=\"{p['broker_user']}\"",
            f"BROKER_PASS=\"{p['broker_pass']}\"",
            f"CONTROLLER_ID=\"{p['ctrl_id']}\"",
            f"CONTROLLER_TOPIC=\"{p['rx_topic']}\"",
            f"AGENT_TOPIC=\"{p['agent_reply_queue']}\"",
            "",
            "echo \"[*] Configuring USP Agent on DUT: $DUT_ENDPOINT ...\"",
            "",
            "# Check if OpenWrt / prplOS UCI is available",
            "if command -v uci >/dev/null 2>&1; then",
            "    echo \"[+] Detected OpenWrt/prplOS UCI subsystem, writing config...\"",
            "    uci set usp.localagent.EndpointID=\"$DUT_ENDPOINT\"",
            "    uci set usp.stomp_conn=stomp_connection",
            "    uci set usp.stomp_conn.enable='1'",
            "    uci set usp.stomp_conn.host=\"$BROKER_HOST\"",
            "    uci set usp.stomp_conn.port=\"$BROKER_PORT\"",
            "    uci set usp.stomp_conn.username=\"$BROKER_USER\"",
            "    uci set usp.stomp_conn.password=\"$BROKER_PASS\"",
            "    uci set usp.agent_mtp=agent_mtp",
            "    uci set usp.agent_mtp.enable='1'",
            "    uci set usp.agent_mtp.protocol='STOMP'",
            "    uci set usp.agent_mtp.stomp_connection='usp.stomp_conn'",
            "    uci set usp.agent_mtp.destination=\"$AGENT_TOPIC\"",
            "    uci set usp.controller=controller",
            "    uci set usp.controller.enable='1'",
            "    uci set usp.controller.endpoint_id=\"$CONTROLLER_ID\"",
            "    uci set usp.ctrl_mtp=controller_mtp",
            "    uci set usp.ctrl_mtp.enable='1'",
            "    uci set usp.ctrl_mtp.protocol='STOMP'",
            "    uci set usp.ctrl_mtp.controller='usp.controller'",
            "    uci set usp.ctrl_mtp.stomp_connection='usp.stomp_conn'",
            "    uci set usp.ctrl_mtp.destination=\"$CONTROLLER_TOPIC\"",
            "    uci commit usp",
            "    echo \"[+] Restarting USP Agent service...\"",
            "    /etc/init.d/obuspa restart 2>/dev/null || /etc/init.d/usp restart 2>/dev/null || true",
            "    echo \"[✓] USP Agent configured and restarted successfully!\"",
            "else",
            "    echo \"[!] UCI not found. Trying obuspa CLI directly...\"",
            "    if command -v obuspa >/dev/null 2>&1; then",
            "        obuspa -p -v 1 \\",
            "          -e \"Device.LocalAgent.EndpointID=$DUT_ENDPOINT\" \\",
            "          -c \"Device.STOMP.Connection.1.Host=$BROKER_HOST\" \\",
            "          -c \"Device.STOMP.Connection.1.Port=$BROKER_PORT\" \\",
            "          -c \"Device.STOMP.Connection.1.Username=$BROKER_USER\" \\",
            "          -c \"Device.STOMP.Connection.1.Password=$BROKER_PASS\" \\",
            "          -c \"Device.STOMP.Connection.1.Enable=true\" \\",
            "          -c \"Device.LocalAgent.MTP.1.Protocol=STOMP\" \\",
            "          -c \"Device.LocalAgent.MTP.1.STOMP.Reference=Device.STOMP.Connection.1.\" \\",
            "          -c \"Device.LocalAgent.MTP.1.STOMP.Destination=$AGENT_TOPIC\" \\",
            "          -c \"Device.LocalAgent.MTP.1.Enable=true\" \\",
            "          -c \"Device.LocalAgent.Controller.1.EndpointID=$CONTROLLER_ID\" \\",
            "          -c \"Device.LocalAgent.Controller.1.Enable=true\" \\",
            "          -c \"Device.LocalAgent.Controller.1.MTP.1.Protocol=STOMP\" \\",
            "          -c \"Device.LocalAgent.Controller.1.MTP.1.STOMP.Reference=Device.STOMP.Connection.1.\" \\",
            "          -c \"Device.LocalAgent.Controller.1.MTP.1.STOMP.Destination=$CONTROLLER_TOPIC\" \\",
            "          -c \"Device.LocalAgent.Controller.1.MTP.1.Enable=true\"",
            "        echo \"[✓] OB-USP-Agent configured successfully!\"",
            "    else",
            "        echo \"[!] Neither UCI nor obuspa binary found on this system.\"",
            "        echo \"[!] Please refer to TR-181 data model parameters above to configure your device.\"",
            "    fi",
            "fi"
        ]
        return "\n".join(lines)

    @classmethod
    def generate_json_profile(cls, config: Optional[ControllerConfig] = None,
                              dut_endpoint_id: Optional[str] = None,
                              broker_host: Optional[str] = None,
                              broker_port: Optional[int] = None) -> str:
        """
        Generate JSON Data Model Profile for DUT import/export.
        """
        import json
        p = cls._extract_params(config, dut_endpoint_id, broker_host, broker_port)

        data = {
            "Device": {
                "LocalAgent": {
                    "EndpointID": p["dut_id"],
                    "MTP": {
                        "1": {
                            "Enable": True,
                            "Protocol": "STOMP",
                            "STOMP": {
                                "Reference": "Device.STOMP.Connection.1.",
                                "Destination": p["agent_reply_queue"]
                            }
                        }
                    },
                    "Controller": {
                        "1": {
                            "Enable": True,
                            "EndpointID": p["ctrl_id"],
                            "AssignedRole": "Device.LocalAgent.ControllerTrust.Role.1.",
                            "MTP": {
                                "1": {
                                    "Enable": True,
                                    "Protocol": "STOMP",
                                    "STOMP": {
                                        "Reference": "Device.STOMP.Connection.1.",
                                        "Destination": p["rx_topic"]
                                    }
                                }
                            }
                        }
                    }
                },
                "STOMP": {
                    "Connection": {
                        "1": {
                            "Enable": True,
                            "Host": p["broker_host"],
                            "Port": p["broker_port"],
                            "Username": p["broker_user"],
                            "Password": p["broker_pass"],
                            "EnableEncryption": False
                        }
                    }
                }
            }
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
