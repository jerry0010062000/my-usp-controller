#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Handler
Unified command dispatcher supporting all USP operations, scripting, device targets, and system commands.
"""

import re
import os
import platform
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from .base import CommandContext, CommandResult
from ..logger import get_logger, set_debug_level, get_debug_level

logger = get_logger()


class CommandHandler:
    """
    Unified command parser, validator, router, and executor.
    """

    def __init__(self, controller=None):
        self._commands: Dict[str, Dict[str, Any]] = {}
        self._aliases: Dict[str, str] = {}
        self._controller = controller
        self._register_builtin_commands()

    def set_controller(self, controller):
        """Set USP Controller Core instance"""
        self._controller = controller

    def register_command(
        self,
        name: str,
        handler: Callable,
        aliases: Optional[List[str]] = None,
        description: str = "",
        usage: str = "",
        min_args: int = 0,
        max_args: Optional[int] = None,
        category: str = "General",
        details: str = "",
        examples: Optional[List[str]] = None
    ):
        """Register a command with metadata, aliases, details, and examples"""
        self._commands[name] = {
            'handler': handler,
            'description': description,
            'usage': usage,
            'min_args': min_args,
            'max_args': max_args,
            'category': category,
            'details': details,
            'examples': examples or []
        }
        if aliases:
            for alias in aliases:
                self._aliases[alias.lower()] = name


    def parse_command(self, input_str: str) -> CommandContext:
        """Parse raw command line input into a CommandContext object"""
        s = input_str.strip()
        tokens = self._tokenize(s)

        if not tokens:
            return CommandContext(command="", raw_input=s)

        command = tokens[0].lower()
        if command in self._aliases:
            command = self._aliases[command]

        args = []
        kwargs = {}

        for token in tokens[1:]:
            if '=' in token and not token.startswith('Device.'):
                k, v = token.split('=', 1)
                kwargs[k] = v
            else:
                args.append(token)

        return CommandContext(
            command=command,
            args=args,
            kwargs=kwargs,
            raw_input=s
        )

    def _tokenize(self, s: str) -> List[str]:
        """Tokenize input with quote support"""
        pattern = r'''((?:[^\s"']|"[^"]*"|'[^']*')+)'''
        raw_tokens = re.findall(pattern, s)
        result = []
        for t in raw_tokens:
            if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
                result.append(t[1:-1])
            else:
                result.append(t)
        return result

    def execute(self, context: CommandContext) -> CommandResult:
        """Execute a parsed CommandContext"""
        command = context.command
        if not command:
            return CommandResult(success=True, message="")

        if command not in self._commands:
            return CommandResult(
                success=False,
                error=f"Unknown command: '{command}'. Type 'help' for available commands."
            )

        cmd_info = self._commands[command]
        handler = cmd_info['handler']
        arg_count = len(context.args)

        if arg_count < cmd_info['min_args']:
            return CommandResult(
                success=False,
                error=f"Too few arguments. Usage: {cmd_info['usage']}"
            )

        if cmd_info['max_args'] is not None and arg_count > cmd_info['max_args']:
            return CommandResult(
                success=False,
                error=f"Too many arguments. Usage: {cmd_info['usage']}"
            )

        try:
            return handler(context)
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return CommandResult(
                success=False,
                error=f"Execution error: {e}"
            )

    def _register_builtin_commands(self):
        """Register the complete suite of USP controller commands"""

        # --- System & Connection Commands ---
        self.register_command(
            name='help', handler=self._cmd_help,
            aliases=['h', '?'], description='顯示指令清單或指定指令的詳細用法與範例',
            usage='help [command]', category='System',
            details='若未加參數，列出所有可用指令。加上指令名稱可查看該指令的詳細參數說明與操作範例。',
            examples=['help', 'help get', 'help set', 'help operate', 'help run_script']
        )
        self.register_command(
            name='status', handler=self._cmd_status,
            aliases=['stat', 'info'], description='檢視 Controller 核心、Broker 連線與目標 Agent 狀態',
            usage='status', category='System',
            details='回傳 Controller Endpoint ID、STOMP 連線狀態、當前鎖定的目標 Agent 及通訊埠資訊。',
            examples=['status']
        )
        self.register_command(
            name='connect', handler=self._cmd_connect,
            aliases=['conn'], description='手動連線至 STOMP Message Broker',
            usage='connect', category='System',
            details='向 config.json 中定義的 STOMP Broker 發起 TCP 連線並自動完成 STOMP 握手與主題訂閱。',
            examples=['connect']
        )
        self.register_command(
            name='disconnect', handler=self._cmd_disconnect,
            aliases=['disconn'], description='中斷與 STOMP Broker 的連線',
            usage='disconnect', category='System',
            details='優雅送出 STOMP DISCONNECT 幀並關閉 TCP 連線。',
            examples=['disconnect']
        )
        self.register_command(
            name='debug', handler=self._cmd_debug,
            description='檢視或設定控制台日誌詳細級別 (0=簡潔, 1=標準, 2=除錯)',
            usage='debug [0|1|2]', max_args=1, category='System',
            details='0: 僅顯示 Agent 相關訊息；1: 顯示雙向 USP Payload 封包；2: 輸出完整 STOMP 幀與 Hex 標頭細節。',
            examples=['debug', 'debug 0', 'debug 1', 'debug 2']
        )
        self.register_command(
            name='logs', handler=self._cmd_logs,
            aliases=['log', 'history'], description='調用並顯示 Daemon 控制台最近的運作日誌',
            usage='logs [count]', max_args=1, category='System',
            details='從 Daemon 伺服器獲取最近 N 筆即時運作與通訊日誌 (預設 20 筆)，方便除錯調適。',
            examples=['logs', 'logs 10', 'logs 50']
        )
        self.register_command(
            name='clear', handler=self._cmd_clear,
            aliases=['cls'], description='清除終端機畫面',
            usage='clear', category='System',
            examples=['clear', 'cls']
        )

        self.register_command(
            name='quit', handler=self._cmd_quit,
            aliases=['exit', 'q'], description='結束並退出互動式主控台',
            usage='quit', category='System',
            examples=['quit', 'exit']
        )

        # --- Device Management Commands ---
        self.register_command(
            name='devices', handler=self._cmd_devices,
            aliases=['list', 'ls'], description='列出所有已註冊與發現的 USP Agent 設備清單',
            usage='devices', category='Device',
            details='顯示各 Agent 的 Endpoint ID、回應佇列 (Reply-To)、最後在線時間與當前狀態。',
            examples=['devices', 'ls']
        )
        self.register_command(
            name='target', handler=self._cmd_target,
            aliases=['use', 'device'], description='檢視或切換當前預設操作的目標 Agent',
            usage='target [endpoint_id]', max_args=1, category='Device',
            details='設定後續 get/set/operate 等指令的預設目標設備，避免每次手動輸入 endpoint_id。',
            examples=['target', 'target proto::agent-001', 'target proto::agent-002']
        )
        self.register_command(
            name='scan', handler=self._cmd_scan,
            aliases=['discover'], description='發起 mDNS 區域網路掃描主動發現 USP Agents (Port 5353)',
            usage='scan', category='Device',
            details='廣播查詢區域網路內廣播 _usp-agent._tcp.local 的 TR-369 設備並自動註冊。',
            examples=['scan']
        )
        self.register_command(
            name='remove_device', handler=self._cmd_remove_device,
            aliases=['forget'], description='從清單中移除指定的 Agent 設備',
            usage='remove_device <endpoint_id>', min_args=1, max_args=1, category='Device',
            examples=['remove_device proto::agent-id']
        )
        self.register_command(
            name='clear_offline', handler=self._cmd_clear_offline,
            aliases=['clean_devices'], description='清除所有處於離線狀態的過期 Agent 設備',
            usage='clear_offline', category='Device',
            examples=['clear_offline']
        )


        # --- USP Operations ---
        self.register_command(
            name='get', handler=self._cmd_get,
            description='向 Agent 查詢 USP 參數值 (支援萬用字元 * 與物件路徑)',
            usage='get [endpoint] <path>', min_args=1, category='USP Operations',
            details='查詢指定 TR-181 參數或物件。若未指定 endpoint，則發送至目前 target 設備。',
            examples=[
                'get Device.DeviceInfo.',
                'get Device.WiFi.SSID.*.SSID',
                'get proto::agent-001 Device.DeviceInfo.SoftwareVersion'
            ]
        )
        self.register_command(
            name='set', handler=self._cmd_set,
            description='設定 Agent 上的 TR-181 參數值',
            usage='set [endpoint] <path> <value>', min_args=2, category='USP Operations',
            details='修改單一參數值。字串包含空格時請用引號包覆。',
            examples=[
                'set Device.WiFi.SSID.1.SSID "Office_WiFi_5G"',
                'set Device.ManagementServer.PeriodicInformEnable true',
                'set proto::agent-001 Device.WiFi.Radio.1.Enable true'
            ]
        )
        self.register_command(
            name='add', handler=self._cmd_add,
            description='在 Agent 上建立新的多實例物件 (Multi-Instance Object)',
            usage='add [endpoint] <obj_path> [param=value ...]', min_args=1, category='USP Operations',
            details='為指定的表格或物件集新增實例，並可選擇性直接初始化欄位值。',
            examples=[
                'add Device.DHCPv4.Server.Pool.',
                'add Device.WiFi.SSID. SSID="GuestWiFi" Enable=true'
            ]
        )
        self.register_command(
            name='delete', handler=self._cmd_delete,
            aliases=['del', 'rm'], description='刪除 Agent 上的指定多實例物件',
            usage='delete [endpoint] <obj_path>', min_args=1, category='USP Operations',
            details='刪除指定實例（路徑末尾必須指定實例編號與句號）。',
            examples=[
                'delete Device.DHCPv4.Server.Pool.2.',
                'delete proto::agent-001 Device.WiFi.SSID.3.'
            ]
        )
        self.register_command(
            name='operate', handler=self._cmd_operate,
            aliases=['op'], description='在 Agent 上執行 RPC 操作/命令 (Command / Operation)',
            usage='operate [endpoint] <command_path> [param=val ...]', min_args=1, category='USP Operations',
            details='觸發 TR-181 定義的非同步或同步方法，如重啟、Ping 診斷、韌體更新等。',
            examples=[
                'operate Device.Reboot()',
                'operate Device.IP.Diagnostics.IPPing() Host="8.8.8.8" NumberOfRepetitions=3'
            ]
        )
        self.register_command(
            name='get_supported_dm', handler=self._cmd_get_supported_dm,
            aliases=['get_supported', 'dm', 'supported_dm'], description='查詢 Agent 支援的資料模型架構 (Schema / Types)',
            usage='get_supported_dm [endpoint] [path] [first_level_only=true|false]', category='USP Operations',
            details='取得設備支援的參數名稱、型別 (string/boolean/int) 與讀寫權限。',
            examples=[
                'get_supported_dm Device.',
                'get_supported_dm Device.WiFi. first_level_only=true'
            ]
        )
        self.register_command(
            name='get_instances', handler=self._cmd_get_instances,
            aliases=['get_inst', 'instances', 'inst'], description='查詢所有已具體實例化的物件路徑清單',
            usage='get_instances [endpoint] <obj_path> [first_level_only=true|false]', min_args=1, category='USP Operations',
            details='回傳指定多實例路徑下實際存在的物件實例清單。',
            examples=[
                'get_instances Device.WiFi.SSID.',
                'get_instances Device.IP.Interface.'
            ]
        )

        # --- Scripting & Testing ---
        self.register_command(
            name='run_script', handler=self._cmd_run_script,
            aliases=['script', 'run', 'test'], description='自動化執行 CDRouter / USP 測試腳本 (.txt)',
            usage='run_script <script_path>', min_args=1, max_args=2, category='Scripting',
            details='逐行執行腳本檔案中的指令，支援智慧路徑推斷、變數替換 ($VAR) 與自動重試。',
            examples=[
                'run_script scripts/test_dhcpv4_pool.txt',
                'run_script scripts/test_wifi_setup.txt'
            ]
        )
        self.register_command(
            name='list_scripts', handler=self._cmd_list_scripts,
            aliases=['scripts'], description='列出 scripts/ 目錄下所有可用的測試腳本檔案',
            usage='list_scripts', category='Scripting',
            examples=['list_scripts', 'scripts']
        )

        # --- DUT & Tooling ---
        self.register_command(
            name='dut_config', handler=self._cmd_dut_config,
            aliases=['dut_guide', 'gen_dut', 'dut'],
            description='智慧生成 DUT (Agent) 端 USP Data Model 與 MTP 設定指南',
            usage='dut_config [format: tr181|uci|obuspa|sh|json] [dut_endpoint_id]',
            max_args=2, category='Device',
            details='根據當前 Controller 與 Broker 設定，快速生成建議 DUT 應配置的 Data Model 參數或腳本 (支援 OpenWrt UCI、OB-USP-Agent、Shell Script 等格式)。',
            examples=[
                'dut_config',
                'dut_config uci',
                'dut_config obuspa proto::agent-001',
                'dut_config sh',
                'dut_config json'
            ]
        )



    # ==================== Command Handlers ====================

    def _cmd_help(self, context: CommandContext) -> CommandResult:
        if context.args:
            name = context.args[0].lower()
            if name in self._aliases:
                name = self._aliases[name]
            if name in self._commands:
                cmd = self._commands[name]
                aliases = [k for k, v in self._aliases.items() if v == name]
                msg = "\n" + "=" * 65 + "\n"
                msg += f"  [INFO] 指令說明: {name.upper()}\n"
                msg += "=" * 65 + "\n"
                msg += f"  * 簡述:     {cmd['description']}\n"
                msg += f"  * 語法格式: {cmd['usage']}\n"
                if aliases:
                    msg += f"  * 別名縮寫: {', '.join(aliases)}\n"
                if cmd.get('details'):
                    msg += f"  * 詳細說明: {cmd['details']}\n"
                if cmd.get('examples'):
                    msg += "\n  操作範例 (Examples):\n"
                    for ex in cmd['examples']:
                        msg += f"    > {ex}\n"
                msg += "=" * 65 + "\n"
                return CommandResult(success=True, message=msg)
            return CommandResult(success=False, error=f"未知指令: '{name}'。請輸入 'help' 查看所有可用指令。")

        # Group by category
        categories: Dict[str, List[str]] = {}
        for cmd_name, info in self._commands.items():
            cat = info.get('category', 'General')
            categories.setdefault(cat, []).append(cmd_name)

        text = "\n" + "=" * 65 + "\n"
        text += "  [+] USP Controller - 指令清單與參考手冊 (Command Reference)\n"
        text += "=" * 65 + "\n"


        for cat, cmds in categories.items():
            text += f"\n[{cat}]\n"
            for c in sorted(cmds):
                info = self._commands[c]
                aliases = [k for k, v in self._aliases.items() if v == c]
                alias_str = f" ({', '.join(aliases)})" if aliases else ""
                text += f"  {c:<18}{alias_str:<14} - {info['description']}\n"

        text += "\n輸入 'help <指令名稱>' (例如: help get 或 help operate) 即可查看詳細參數說明與範例。\n"
        text += "=" * 65 + "\n"
        return CommandResult(success=True, message=text)


    def _cmd_status(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="Controller instance not attached")

        status = self._controller.get_status()
        conn_str = "CONNECTED" if status['connected'] else "DISCONNECTED"
        msg = f"\n=== USP Controller Status ===\n"
        msg += f"  Controller ID:  {status['controller_id']}\n"
        msg += f"  Transport:      {status['protocol'].upper()} ({conn_str})\n"
        msg += f"  Broker:         {status['broker_host']}:{status['broker_port']}\n"
        msg += f"  Receive Topic:  {status['receive_topic']}\n"
        msg += f"  Active Target:  {status['active_device'] or '(None)'} [{status['active_device_status']}]\n"
        msg += f"  Known Devices:  {status['total_devices']}\n"
        msg += f"  Debug Level:    {status['debug_level']}\n"
        return CommandResult(success=True, message=msg, data=status)

    def _cmd_connect(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        if self._controller.is_connected():
            return CommandResult(success=True, message="Already connected to broker.")
        ok = self._controller.connect()
        return CommandResult(
            success=ok,
            message="Connected to broker successfully." if ok else "Failed to connect to broker."
        )

    def _cmd_disconnect(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        self._controller.disconnect()
        return CommandResult(success=True, message="Disconnected from broker.")

    def _cmd_devices(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        devs = self._controller.device_manager.list_devices()
        if not devs:
            return CommandResult(success=True, message="No devices registered yet.")

        # Format as table
        active_ep = self._controller.device_manager.get_active_device()
        table_data = []
        for d in devs:
            is_act = " *" if d['endpoint_id'] == active_ep else "  "
            table_data.append({
                "Target": f"{is_act} {d['endpoint_id']}",
                "Status": d['status'].upper(),
                "Reply-To": d['reply_to'],
                "Last Seen": d['last_seen'][:19] if len(d['last_seen']) >= 19 else d['last_seen'],
                "Source": d['discovered_via']
            })

        return CommandResult(
            success=True,
            message=f"Known Devices ({len(devs)}) [* = Active Target]",
            data=table_data
        )

    def _cmd_target(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        if not context.args:
            active = self._controller.device_manager.get_active_device()
            return CommandResult(
                success=True,
                message=f"Active Target Device: {active or '(None selected)'}"
            )

        new_target = context.args[0]
        self._controller.device_manager.set_active_device(new_target)
        return CommandResult(
            success=True,
            message=f"Active Target Device set to: '{new_target}'"
        )

    def _cmd_scan(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        logger.info("Scanning for agents...", level=0)
        found = self._controller.device_manager.scan_mdns(timeout=2.5)
        if not found:
            return CommandResult(success=True, message="Scan complete: No new agents discovered via mDNS.")
        return CommandResult(
            success=True,
            message=f"Scan complete: Found {len(found)} agent(s)",
            data=found
        )

    def _cmd_remove_device(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        ep = context.args[0]
        ok = self._controller.device_manager.remove_device(ep)
        if ok:
            return CommandResult(success=True, message=f"已成功從清單中移除設備: {ep}")
        return CommandResult(success=False, error=f"找不到指定的設備: {ep}")

    def _cmd_clear_offline(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")
        count = self._controller.device_manager.clear_offline_devices()
        return CommandResult(success=True, message=f"已成功清理 {count} 個離線設備。")


    def _cmd_get(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, path = self._resolve_ep_and_path(context.args)
        if not path:
            return CommandResult(success=False, error="Usage: get [endpoint] <path>")

        resp = self._controller.get(path, endpoint=endpoint, timeout=5.0)
        if resp.get("status") != "success":
            return CommandResult(success=False, error=resp.get("error", "Get request failed"))

        params = resp.get("parameters", {})
        count = len(params)
        elapsed = resp.get("elapsed_sec", 0.0)

        # Build table output
        table_rows = [{"Parameter": k, "Value": str(v)} for k, v in params.items()]
        msg = f"GET Response from '{resp.get('endpoint')}': {count} parameter(s) in {elapsed:.2f}s"
        return CommandResult(success=True, message=msg, data=table_rows)

    def _format_usp_error_details(self, resp: Dict[str, Any], default_msg: str = "Request failed") -> str:
        """Format detailed TR-369 / USP error descriptions from response"""
        errors = resp.get("errors", [])
        ep = resp.get("endpoint", "")
        ep_prefix = f"[{ep}] " if ep else ""

        if errors:
            details = []
            for e in errors:
                if isinstance(e, dict):
                    code = e.get("err_code", "")
                    msg = e.get("err_msg", "")
                    p = e.get("param") or e.get("requested_path") or e.get("affected_path") or ""
                    code_str = f"代碼 {code}" if code != "" else "錯誤"
                    if p:
                        details.append(f"{p} ({code_str}: {msg})")
                    else:
                        details.append(f"{code_str}: {msg}")
                else:
                    details.append(str(e))
            return f"{ep_prefix}{'; '.join(details)}"

        if resp.get("err_msg"):
            code = resp.get("err_code", "")
            code_str = f"[{code}] " if code != "" else ""
            return f"{ep_prefix}{code_str}{resp.get('err_msg')}"

        if resp.get("error"):
            return f"{ep_prefix}{resp.get('error')}"

        return f"{ep_prefix}{default_msg}"

    def _cmd_set(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        args = context.args
        if len(args) == 2:
            endpoint = None
            path, val = args[0], args[1]
        elif len(args) >= 3:
            if self._looks_like_endpoint(args[0]):
                endpoint, path, val = args[0], args[1], " ".join(args[2:])
            else:
                endpoint = None
                path, val = args[0], " ".join(args[1:])
        else:
            return CommandResult(success=False, error="Usage: set [endpoint] <path> <value>")

        resp = self._controller.set({path: val}, endpoint=endpoint, timeout=5.0)
        if resp.get("status") not in ("success", "partial"):
            err_msg = self._format_usp_error_details(resp, "Set request rejected by Agent")
            return CommandResult(success=False, error=f"SET 失敗: {err_msg}")

        if resp.get("status") == "partial":
            err_msg = self._format_usp_error_details(resp, "Partial failure")
            msg = f"SET 部分成功: {resp.get('updated_params')} (部分欄位失敗: {err_msg})"
            return CommandResult(success=True, message=msg, data=resp.get("updated_params"))

        msg = f"SET 成功 ({resp.get('endpoint')}): {path} = {val} ({resp.get('elapsed_sec', 0.0):.2f}s)"
        return CommandResult(success=True, message=msg, data=resp.get("updated_params"))

    def _cmd_add(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, path = self._resolve_ep_and_path(context.args)
        if not path:
            return CommandResult(success=False, error="Usage: add [endpoint] <obj_path>")

        resp = self._controller.add(path, endpoint=endpoint, timeout=5.0)
        if resp.get("status") != "success":
            err_msg = self._format_usp_error_details(resp, "Add request rejected by Agent")
            return CommandResult(success=False, error=f"ADD 失敗: {err_msg}")

        created = resp.get("created", [])
        created_paths = [c.get("instantiated_path") for c in created if c.get("instantiated_path")]
        msg = f"ADD 成功 ({resp.get('endpoint')}): 建立實例 {', '.join(created_paths) or path} ({resp.get('elapsed_sec', 0.0):.2f}s)"
        return CommandResult(success=True, message=msg, data=created)

    def _cmd_delete(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, path = self._resolve_ep_and_path(context.args)
        if not path:
            return CommandResult(success=False, error="Usage: delete [endpoint] <obj_path>")

        resp = self._controller.delete(path, endpoint=endpoint, timeout=5.0)
        if resp.get("status") != "success":
            err_msg = self._format_usp_error_details(resp, "Delete request rejected by Agent")
            return CommandResult(success=False, error=f"DELETE 失敗: {err_msg}")

        msg = f"DELETE 成功 ({resp.get('endpoint')}): 刪除實例 {path} ({resp.get('elapsed_sec', 0.0):.2f}s)"
        return CommandResult(success=True, message=msg, data=resp.get("deleted_paths"))

    def _cmd_operate(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, cmd_path = self._resolve_ep_and_path(context.args)
        if not cmd_path:
            return CommandResult(success=False, error="Usage: operate [endpoint] <command_path>")

        resp = self._controller.operate(cmd_path, args=context.kwargs, endpoint=endpoint, timeout=8.0)
        results = resp.get("operation_results", [])
        failures = [r for r in results if r.get("cmd_failure")]
        if resp.get("status") != "success" or failures:
            if failures:
                fail_msgs = [f"[{f['cmd_failure'].get('err_code', '')}] {f['cmd_failure'].get('err_msg', '')}" for f in failures]
                err_msg = "; ".join(fail_msgs)
            else:
                err_msg = self._format_usp_error_details(resp, "Operate command rejected")
            return CommandResult(success=False, error=f"OPERATE 失敗: {err_msg}")

        msg = f"OPERATE 成功 ({resp.get('endpoint')}): {cmd_path} 執行完成 ({resp.get('elapsed_sec', 0.0):.2f}s)"
        return CommandResult(success=True, message=msg, data=resp.get("operation_results"))


    def _cmd_get_supported_dm(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, path = self._resolve_ep_and_path(context.args)
        target_path = path or "Device."

        resp = self._controller.get_supported_dm(target_path, endpoint=endpoint, timeout=8.0)
        if resp.get("status") != "success":
            return CommandResult(success=False, error=resp.get("error", "GetSupportedDM request failed"))

        dm_list = resp.get("supported_dm", [])
        return CommandResult(
            success=True,
            message=f"GetSupportedDM Response from '{resp.get('endpoint')}' ({resp.get('elapsed_sec', 0.0):.2f}s)",
            data=dm_list
        )

    def _cmd_get_instances(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        endpoint, path = self._resolve_ep_and_path(context.args)
        if not path:
            return CommandResult(success=False, error="Usage: get_instances [endpoint] <obj_path>")

        resp = self._controller.get_instances(path, endpoint=endpoint, timeout=5.0)
        if resp.get("status") != "success":
            return CommandResult(success=False, error=resp.get("error", "GetInstances request failed"))

        insts = resp.get("instances", [])
        msg = f"GetInstances Response from '{resp.get('endpoint')}': {len(insts)} instance(s) ({resp.get('elapsed_sec', 0.0):.2f}s)"
        return CommandResult(success=True, message=msg, data=[{"Instance Path": i} for i in insts])

    def _cmd_run_script(self, context: CommandContext) -> CommandResult:
        if not self._controller:
            return CommandResult(success=False, error="No controller instance")

        from ..scripting import CDRouterScriptEngine

        script_path = context.args[0]
        p = Path(script_path)
        if not p.is_absolute() and not p.exists():
            # Check under scripts/
            candidate = Path("scripts") / script_path
            if candidate.exists():
                p = candidate
            elif not script_path.endswith('.txt'):
                candidate_txt = Path("scripts") / f"{script_path}.txt"
                if candidate_txt.exists():
                    p = candidate_txt

        if not p.exists():
            return CommandResult(success=False, error=f"Script file '{script_path}' not found.")

        target_ep = context.args[1] if len(context.args) > 1 else None

        engine = CDRouterScriptEngine(self._controller)
        report = engine.execute_script(p, controller=self._controller, active_endpoint=target_ep)

        summary = f"\n=== Test Script Report: {report.script_path} ===\n"
        summary += f"Status:         {report.status}\n"
        summary += f"Total Steps:    {report.total_steps}\n"
        summary += f"Passed:         {report.passed_count}\n"
        summary += f"Failed:         {report.failed_count}\n"
        summary += f"Errors:         {report.error_count}\n"
        summary += f"Execution Time: {report.elapsed_sec:.2f}s\n"

        return CommandResult(
            success=(report.status == "PASS"),
            message=summary,
            data=report
        )

    def _cmd_list_scripts(self, context: CommandContext) -> CommandResult:
        p = Path("scripts")
        if not p.exists():
            return CommandResult(success=True, message="No 'scripts/' directory found.")

        txt_files = sorted(list(p.glob("*.txt")))
        if not txt_files:
            return CommandResult(success=True, message="No .txt test scripts found in 'scripts/' directory.")

        rows = [{"Script Name": f.name, "Size (Bytes)": str(f.stat().st_size)} for f in txt_files]
        return CommandResult(
            success=True,
            message=f"Available Test Scripts ({len(txt_files)}) in scripts/",
            data=rows
        )

    def _cmd_dut_config(self, context: CommandContext) -> CommandResult:
        """Generate DUT USP Data Model configuration guide"""
        from ..device.dut_generator import DUTConfigGenerator

        fmt = "tr181"
        dut_id = "proto::agent.001"
        b_host = None

        if context.args:
            fmt = context.args[0].lower()
        if len(context.args) > 1:
            dut_id = context.args[1]
        if len(context.args) > 2:
            b_host = context.args[2]

        # Use active target device ID if available and not explicitly provided
        if len(context.args) <= 1 and self._controller and self._controller.device_manager:
            active = self._controller.device_manager.get_active_device()
            if active:
                dut_id = active

        cfg = getattr(self._controller, 'config', None) if self._controller else None

        if fmt in ["guide", "help", "info"]:
            content = DUTConfigGenerator.generate_guide(cfg, dut_endpoint_id=dut_id, broker_host=b_host)
        elif fmt in ["uci", "openwrt", "prpl"]:
            content = DUTConfigGenerator.generate_openwrt_uci(cfg, dut_endpoint_id=dut_id, broker_host=b_host)
        elif fmt in ["obuspa", "bbf"]:
            content = DUTConfigGenerator.generate_obuspa_config(cfg, dut_endpoint_id=dut_id, broker_host=b_host)
        elif fmt in ["sh", "bash", "script"]:
            content = DUTConfigGenerator.generate_shell_script(cfg, dut_endpoint_id=dut_id, broker_host=b_host)
        elif fmt in ["json", "profile"]:
            content = DUTConfigGenerator.generate_json_profile(cfg, dut_endpoint_id=dut_id, broker_host=b_host)
        else:
            content = DUTConfigGenerator.generate_tr181_commands(cfg, dut_endpoint_id=dut_id, broker_host=b_host)

        return CommandResult(
            success=True,
            message=content,
            data={"format": fmt, "dut_id": dut_id, "content": content}
        )



    def _cmd_debug(self, context: CommandContext) -> CommandResult:
        if not context.args:
            lvl = get_debug_level()
            names = ["0 (Agent Only)", "1 (Both Payloads)", "2 (Full STOMP Details)"]
            msg = f"Current Debug Level: {names[lvl]}\nUsage: debug <0|1|2>"
            return CommandResult(success=True, message=msg)

        try:
            val = int(context.args[0])
            if 0 <= val <= 2:
                set_debug_level(val)
                if self._controller and hasattr(self._controller, 'config'):
                    self._controller.config.debug_level = val
                return CommandResult(success=True, message=f"Debug level updated to {val}")
            return CommandResult(success=False, error="Debug level must be 0, 1, or 2")
        except ValueError:
            return CommandResult(success=False, error="Invalid debug level. Use 0, 1, or 2")

    def _cmd_logs(self, context: CommandContext) -> CommandResult:
        count = 20
        if context.args:
            try:
                count = max(1, min(500, int(context.args[0])))
            except ValueError:
                return CommandResult(success=False, error="日誌筆數必須為整數。")

        history = logger.get_history(since_id=-1, max_count=count)
        if not history:
            return CommandResult(success=True, message="目前尚無歷史日誌紀錄。")

        lines = [f"\n=== Daemon 系統日誌 (最近 {len(history)} 筆) ==="]
        for item in history:
            ts = item.get('timestamp', '')
            ltype = item.get('type', 'INFO').upper()
            msg = item.get('message', '')
            lines.append(f"  [{ts}] [{ltype:<7}] {msg}")
        lines.append("=" * 55 + "\n")
        return CommandResult(success=True, message="\n".join(lines), data=history)

    def _cmd_clear(self, context: CommandContext) -> CommandResult:

        if platform.system() == "Windows":
            os.system('cls')
        else:
            os.system('clear')
        return CommandResult(success=True, message="")

    def _cmd_quit(self, context: CommandContext) -> CommandResult:
        if self._controller:
            self._controller.disconnect()
        return CommandResult(
            success=True,
            message="Exiting USP Controller CLI...",
            metadata={'action': 'quit'}
        )

    # ==================== Helpers ====================

    def _looks_like_endpoint(self, token: str) -> bool:
        if not token:
            return False
        if token.startswith('{') and token.endswith('}'):
            return True
        if '::' in token or 'agent' in token.lower() or 'proto::' in token.lower():
            return True
        if token.startswith('Device.') or token.startswith('USP.'):
            return False
        return False

    def _resolve_ep_and_path(self, args: List[str]) -> Tuple[Optional[str], Optional[str]]:
        if not args:
            return None, None
        if len(args) == 1:
            return None, args[0]
        if self._looks_like_endpoint(args[0]):
            return args[0], args[1]
        return None, args[0]

    def get_command_names(self) -> List[str]:
        return sorted(list(self._commands.keys()) + list(self._aliases.keys()))
