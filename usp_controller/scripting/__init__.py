#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CDRouter & Smart Automation Scripting Engine
Parses and executes test scripts (.txt) with variable interpolation,
auto-discovery, step assertions, and comprehensive reporting.
"""

import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union
from enum import Enum
from ..logger import get_logger

logger = get_logger()


class ScriptCommandType(Enum):
    """Script command type enumeration"""
    GET = "get"
    SET = "set"
    ADD = "add"
    DELETE = "delete"
    OPERATE = "operate"
    DISCOVER = "discover"
    GET_INSTANCES = "get_instances"
    WAIT = "wait"
    COMMENT = "comment"
    VARIABLE = "variable"
    ASSERT = "assert"
    SPECIAL = "special"


@dataclass
class ScriptCommand:
    """Represents a parsed script command with both structured properties and param dict"""
    type: ScriptCommandType
    raw_line: str
    line_number: int
    params: Dict[str, Any] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    command: str = ""
    endpoint: Optional[str] = None
    path: Optional[str] = None
    value: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    is_comment: bool = False
    comment_text: str = ""


# Alias ScriptStep to ScriptCommand
ScriptStep = ScriptCommand


@dataclass
class StepResult:
    """Result of executing a single test step"""
    step: ScriptCommand
    success: bool
    status: str  # PASS, FAIL, ERROR, SKIP, INFO
    actual_value: Optional[Any] = None
    expected_value: Optional[str] = None
    error_message: Optional[str] = None
    elapsed_sec: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptExecutionReport:
    """Summary report of a script execution run"""
    script_path: str
    total_steps: int
    executed_steps: int
    passed_count: int
    failed_count: int
    error_count: int
    status: str  # PASS, FAIL, ERROR
    elapsed_sec: float
    results: List[StepResult] = field(default_factory=list)


class SmartScriptEngine:
    """
    CDRouter & Smart Test Script Engine
    """

    def __init__(self, controller=None, intelligence_level: int = 2,
                 dm_cache: Optional[Dict] = None, auto_discovery: bool = True):
        self.controller = controller
        self.intelligence_level = intelligence_level
        self.dm_cache = dm_cache or {}
        self.auto_discovery = auto_discovery
        self.variables: Dict[str, str] = {}
        self.last_created_instance: Optional[str] = None
        self.bridge_instances: Dict[str, str] = {}

    def save_variable(self, name: str, value: str):
        """Save a variable"""
        var_name = name.lstrip('$')
        self.variables[var_name] = str(value)
        logger.info(f"Variable saved: {var_name} = {value}", level=1)

    def substitute_variables(self, text: str, active_endpoint: Optional[str] = None) -> str:
        """Substitute variables and placeholders in text"""
        return self.interpolate_string(text, active_endpoint) or ""

    def interpolate_string(self, s: Optional[str], active_endpoint: Optional[str] = None) -> Optional[str]:
        """Interpolate placeholders and variables into string"""
        if s is None:
            return None

        res = str(s)

        # 1. Endpoint replacement
        ep = active_endpoint or self.variables.get('ENDPOINT', '')
        res = res.replace('{ENDPOINT}', ep)
        res = res.replace('$ENDPOINT', ep)

        # 2. Instance replacement
        if self.last_created_instance:
            res = res.replace('{INSTANCE}', str(self.last_created_instance))
            res = res.replace('$INSTANCE', str(self.last_created_instance))

        # 3. Discovered bridge & port replacement
        for k, v in self.bridge_instances.items():
            res = res.replace(f"{{{k}}}", str(v))
            res = res.replace(f"${k}", str(v))

        # 4. Custom saved variables
        for k, v in self.variables.items():
            res = res.replace(f"{{{k}}}", str(v))
            res = res.replace(f"${k}", str(v))

        return res

    def parse_script(self, script_content: str) -> List[ScriptCommand]:
        """Parse script text content (backward compatibility alias)"""
        return self.parse_script_text(script_content)

    def parse_script_file(self, file_path: Union[str, Path]) -> List[ScriptCommand]:
        """Parse a test script file from disk"""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Script file not found: {file_path}")

        content = p.read_text(encoding='utf-8')
        return self.parse_script_text(content)

    def parse_script_text(self, text: str) -> List[ScriptCommand]:
        """Parse script text into a sequence of executable ScriptCommand objects"""
        commands: List[ScriptCommand] = []
        lines = text.splitlines()

        for idx, line in enumerate(lines, start=1):
            raw = line
            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith('#'):
                commands.append(ScriptCommand(
                    type=ScriptCommandType.COMMENT,
                    raw_line=raw,
                    line_number=idx,
                    params={'text': stripped[1:].strip()},
                    command="comment",
                    is_comment=True,
                    comment_text=stripped[1:].strip()
                ))
                continue

            # Handle variable assignments like: $AGENT1 = agent-001
            if stripped.startswith('$') and '=' in stripped:
                var_part, val_part = stripped.split('=', 1)
                var_name = var_part.strip().lstrip('$')
                var_val = val_part.strip().strip('"').strip("'")
                self.save_variable(var_name, var_val)
                continue

            # Extract inline annotations (e.g. `# expect: 192.168.1.5` or `# save_to: info`)
            annotations = {}
            if '#' in stripped:
                code_part, comment_part = stripped.split('#', 1)
                code_part = code_part.strip()
                comment_part = comment_part.strip()

                # Parse annotations like "expect: xxx" or "save_to: xxx"
                for match in re.finditer(r'(\w+)\s*:\s*([^\s,]+)', comment_part):
                    k, v = match.group(1).lower(), match.group(2).strip()
                    annotations[k] = v
            else:
                code_part = stripped

            if not code_part:
                continue

            tokens = self._tokenize(code_part)
            if not tokens:
                continue

            cmd_name = tokens[0].lower()

            # Command Type Mapping
            type_map = {
                'get': ScriptCommandType.GET,
                'set': ScriptCommandType.SET,
                'add': ScriptCommandType.ADD,
                'delete': ScriptCommandType.DELETE,
                'del': ScriptCommandType.DELETE,
                'operate': ScriptCommandType.OPERATE,
                'op': ScriptCommandType.OPERATE,
                'get_instances': ScriptCommandType.GET_INSTANCES,
                'get_inst': ScriptCommandType.GET_INSTANCES,
                'get_supported_dm': ScriptCommandType.DISCOVER,
                'get_supported': ScriptCommandType.DISCOVER,
                'discover_bridge_port': ScriptCommandType.DISCOVER,
                'wait': ScriptCommandType.WAIT,
                'sleep': ScriptCommandType.WAIT,
                'assert': ScriptCommandType.ASSERT
            }
            cmd_type = type_map.get(cmd_name, ScriptCommandType.SPECIAL)

            # Discover bridge port
            if cmd_name == 'discover_bridge_port':
                commands.append(ScriptCommand(
                    type=cmd_type,
                    raw_line=raw,
                    line_number=idx,
                    command=cmd_name,
                    args={'bridge': tokens[1] if len(tokens) > 1 else 'lan',
                          'port': tokens[2] if len(tokens) > 2 else 'lan'},
                    annotations=annotations
                ))
                continue

            # Wait
            if cmd_type == ScriptCommandType.WAIT:
                sec = tokens[1] if len(tokens) > 1 else "1"
                commands.append(ScriptCommand(
                    type=cmd_type,
                    raw_line=raw,
                    line_number=idx,
                    command='wait',
                    value=sec,
                    params={'seconds': sec},
                    annotations=annotations
                ))
                continue

            # Standard USP commands
            if len(tokens) >= 2:
                if self._is_endpoint_token(tokens[1]):
                    endpoint_token = tokens[1]
                    path_token = tokens[2] if len(tokens) > 2 else ""
                    val_token = " ".join(tokens[3:]) if len(tokens) > 3 else None
                else:
                    endpoint_token = "{ENDPOINT}"
                    path_token = tokens[1]
                    val_token = " ".join(tokens[2:]) if len(tokens) > 2 else None

                # Path inference (level 2)
                if self.intelligence_level >= 2 and path_token:
                    if not path_token.startswith("Device.") and not path_token.startswith("USP.") and not path_token.startswith("{"):
                        if not path_token.startswith("$"):
                            path_token = f"Device.{path_token}"

                commands.append(ScriptCommand(
                    type=cmd_type,
                    raw_line=raw,
                    line_number=idx,
                    command=cmd_name,
                    endpoint=endpoint_token,
                    path=path_token,
                    value=val_token,
                    params={'endpoint': endpoint_token, 'path': path_token, 'value': val_token},
                    annotations=annotations
                ))
            else:
                commands.append(ScriptCommand(
                    type=cmd_type,
                    raw_line=raw,
                    line_number=idx,
                    command=cmd_name,
                    annotations=annotations
                ))

        logger.success(f"Parsed {len(commands)} commands from script", level=1)
        return commands

    def _is_endpoint_token(self, token: str) -> bool:
        if token.startswith('{') and token.endswith('}'):
            return True
        if token.startswith('$') and ('AGENT' in token or 'ENDPOINT' in token):
            return True
        if '::' in token or 'agent' in token.lower() or 'proto::' in token.lower():
            return True
        if token.startswith('Device.') or token.startswith('USP.'):
            return False
        return False

    def _tokenize(self, s: str) -> List[str]:
        pattern = r'''((?:[^\s"']|"[^"]*"|'[^']*')+)'''
        raw_tokens = re.findall(pattern, s)
        result = []
        for t in raw_tokens:
            if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
                result.append(t[1:-1])
            else:
                result.append(t)
        return result

    def execute_script(self,
                       script_input: Any,
                       controller=None,
                       active_endpoint: Optional[str] = None,
                       progress_callback: Optional[Callable[[StepResult], None]] = None) -> ScriptExecutionReport:
        """Execute a parsed script or script file/text"""
        ctrl = controller or self.controller
        if not ctrl:
            raise ValueError("No USP Controller Core provided for script execution")

        if isinstance(script_input, (str, Path)):
            p = Path(script_input)
            if p.exists():
                steps = self.parse_script_file(p)
                script_name = p.name
            else:
                steps = self.parse_script_text(str(script_input))
                script_name = "Inline Script"
        elif isinstance(script_input, list):
            steps = script_input
            script_name = "Step Sequence"
        else:
            raise TypeError("Unsupported script input type")

        target_ep = active_endpoint or ctrl.device_manager.get_active_device() or ""
        self.variables['ENDPOINT'] = target_ep

        report_results: List[StepResult] = []
        start_time = time.time()
        passed_count = 0
        failed_count = 0
        error_count = 0

        logger.info(f"=== Starting Script Execution: {script_name} ===", level=0)
        logger.info(f"Target Endpoint: {target_ep}", level=0)

        for step in steps:
            if step.is_comment or step.type == ScriptCommandType.COMMENT:
                continue

            step_res = self._execute_step(ctrl, step, target_ep)
            report_results.append(step_res)

            if step_res.status == 'PASS':
                passed_count += 1
                logger.success(f"[Line {step.line_number}] PASS: {step.command} {step.path or ''} ({step_res.elapsed_sec:.2f}s)", level=0)
            elif step_res.status == 'FAIL':
                failed_count += 1
                logger.error(f"[Line {step.line_number}] FAIL: {step_res.error_message}", level=0)
            elif step_res.status == 'ERROR':
                error_count += 1
                logger.error(f"[Line {step.line_number}] ERROR: {step_res.error_message}", level=0)
            else:
                logger.info(f"[Line {step.line_number}] INFO: {step.command} completed", level=1)

            if progress_callback:
                try:
                    progress_callback(step_res)
                except Exception:
                    pass

        total_elapsed = time.time() - start_time
        final_status = "PASS" if (failed_count == 0 and error_count == 0) else "FAIL"

        logger.info(f"=== Script Completed: {final_status} ({passed_count} Passed, {failed_count} Failed, {error_count} Errors) in {total_elapsed:.2f}s ===", level=0)

        return ScriptExecutionReport(
            script_path=script_name,
            total_steps=len([s for s in steps if not s.is_comment and s.type != ScriptCommandType.COMMENT]),
            executed_steps=len(report_results),
            passed_count=passed_count,
            failed_count=failed_count,
            error_count=error_count,
            status=final_status,
            elapsed_sec=round(total_elapsed, 3),
            results=report_results
        )

    def _execute_step(self, ctrl, step: ScriptCommand, active_ep: str) -> StepResult:
        """Execute one step with parameter resolution and assertion checking"""
        t0 = time.time()
        cmd = step.command.lower()
        ep = self.interpolate_string(step.endpoint, active_ep) or active_ep
        path = self.interpolate_string(step.path, active_ep)
        val = self.interpolate_string(step.value, active_ep)

        try:
            # 1. discover_bridge_port
            if cmd == 'discover_bridge_port':
                b_resp = ctrl.get_instances("Device.Bridging.Bridge.", endpoint=ep, timeout=5.0)
                if b_resp.get("status") == "success" and b_resp.get("instances"):
                    b_inst_path = b_resp["instances"][0]
                    m = re.search(r'Device\.Bridging\.Bridge\.(\d+)\.', b_inst_path)
                    b_num = m.group(1) if m else "1"
                    self.bridge_instances['BRIDGE_INST'] = b_num

                    p_resp = ctrl.get_instances(f"Device.Bridging.Bridge.{b_num}.Port.", endpoint=ep, timeout=5.0)
                    if p_resp.get("status") == "success" and p_resp.get("instances"):
                        p_inst_path = p_resp["instances"][0]
                        pm = re.search(r'Port\.(\d+)\.', p_inst_path)
                        p_num = pm.group(1) if pm else "1"
                        self.bridge_instances['PORT_INST'] = p_num
                    else:
                        self.bridge_instances['PORT_INST'] = "1"
                else:
                    self.bridge_instances['BRIDGE_INST'] = "1"
                    self.bridge_instances['PORT_INST'] = "1"

                return StepResult(
                    step=step, success=True, status="PASS",
                    elapsed_sec=round(time.time() - t0, 3),
                    details={"bridge_instances": self.bridge_instances.copy()}
                )

            # 2. wait
            if cmd in ('wait', 'sleep') or step.type == ScriptCommandType.WAIT:
                sec = float(val or 1.0)
                time.sleep(sec)
                return StepResult(step=step, success=True, status="PASS", elapsed_sec=sec)

            # 3. GET
            if cmd == 'get' or step.type == ScriptCommandType.GET:
                resp = ctrl.get(path, endpoint=ep, timeout=5.0)
                elapsed = round(time.time() - t0, 3)

                if resp.get("status") != "success":
                    return StepResult(
                        step=step, success=False, status="FAIL",
                        error_message=resp.get("error", "Get failed"),
                        elapsed_sec=elapsed, details=resp
                    )

                params = resp.get("parameters", {})
                actual_val = params.get(path)
                if actual_val is None and params:
                    for k, v in params.items():
                        if k == path or k.endswith(path) or path.endswith(k):
                            actual_val = v
                            break

                save_var = step.annotations.get('save_to')
                if save_var and actual_val is not None:
                    var_name = save_var.lstrip('$')
                    self.save_variable(var_name, str(actual_val))

                expected = step.annotations.get('expect')
                if expected is not None:
                    expected_interp = self.interpolate_string(expected, active_ep)
                    if str(actual_val).strip() != str(expected_interp).strip():
                        return StepResult(
                            step=step, success=False, status="FAIL",
                            actual_value=actual_val,
                            expected_value=expected_interp,
                            error_message=f"Value mismatch for '{path}'. Expected: '{expected_interp}', Got: '{actual_val}'",
                            elapsed_sec=elapsed, details=resp
                        )

                return StepResult(
                    step=step, success=True, status="PASS",
                    actual_value=actual_val or params,
                    expected_value=step.annotations.get('expect'),
                    elapsed_sec=elapsed, details=resp
                )

            # 4. SET
            if cmd == 'set' or step.type == ScriptCommandType.SET:
                param_dict = {path: val}
                resp = ctrl.set(param_dict, endpoint=ep, timeout=5.0)
                elapsed = round(time.time() - t0, 3)
                success = (resp.get("status") in ("success", "partial"))
                return StepResult(
                    step=step, success=success,
                    status="PASS" if success else "FAIL",
                    error_message=resp.get("error") if not success else None,
                    elapsed_sec=elapsed, details=resp
                )

            # 5. ADD
            if cmd == 'add' or step.type == ScriptCommandType.ADD:
                resp = ctrl.add(path, endpoint=ep, timeout=5.0)
                elapsed = round(time.time() - t0, 3)
                success = (resp.get("status") == "success")

                if success and resp.get("created"):
                    created_path = resp["created"][0].get("instantiated_path", "")
                    m = re.search(r'\.(\d+)\.?$', created_path)
                    if m:
                        self.last_created_instance = m.group(1)

                return StepResult(
                    step=step, success=success,
                    status="PASS" if success else "FAIL",
                    error_message=resp.get("error") if not success else None,
                    elapsed_sec=elapsed, details=resp
                )

            # 6. DELETE
            if cmd in ('delete', 'del') or step.type == ScriptCommandType.DELETE:
                resp = ctrl.delete(path, endpoint=ep, timeout=5.0)
                elapsed = round(time.time() - t0, 3)
                success = (resp.get("status") == "success")
                return StepResult(
                    step=step, success=success,
                    status="PASS" if success else "FAIL",
                    error_message=resp.get("error") if not success else None,
                    elapsed_sec=elapsed, details=resp
                )

            # 7. GET_INSTANCES
            if cmd in ('get_instances', 'get_inst') or step.type == ScriptCommandType.GET_INSTANCES:
                resp = ctrl.get_instances(path, endpoint=ep, timeout=5.0)
                elapsed = round(time.time() - t0, 3)
                success = (resp.get("status") == "success")

                if success and resp.get("instances"):
                    insts = resp["instances"]
                    nums = []
                    for ipath in insts:
                        m = re.search(r'\.(\d+)\.?$', ipath)
                        if m:
                            nums.append(int(m.group(1)))
                    if nums:
                        self.last_created_instance = str(max(nums))

                return StepResult(
                    step=step, success=success,
                    status="PASS" if success else "FAIL",
                    actual_value=resp.get("instances"),
                    elapsed_sec=elapsed, details=resp
                )

            # 8. OPERATE
            if cmd in ('operate', 'op') or step.type == ScriptCommandType.OPERATE:
                resp = ctrl.operate(path, endpoint=ep, timeout=8.0)
                elapsed = round(time.time() - t0, 3)
                success = (resp.get("status") == "success")
                return StepResult(
                    step=step, success=success,
                    status="PASS" if success else "FAIL",
                    error_message=resp.get("error") if not success else None,
                    elapsed_sec=elapsed, details=resp
                )

            # Fallback
            return StepResult(
                step=step, success=False, status="ERROR",
                error_message=f"Unsupported command: {cmd}",
                elapsed_sec=round(time.time() - t0, 3)
            )

        except Exception as e:
            return StepResult(
                step=step, success=False, status="ERROR",
                error_message=str(e),
                elapsed_sec=round(time.time() - t0, 3)
            )


CDRouterScriptEngine = SmartScriptEngine

__all__ = [
    'SmartScriptEngine',
    'CDRouterScriptEngine',
    'ScriptCommand',
    'ScriptStep',
    'ScriptCommandType',
    'StepResult',
    'ScriptExecutionReport'
]
