#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
USP Protocol Layer Module
Handles encoding and decoding of USP Records and USP Messages (TR-369 / USP 1.4)
"""

import uuid
from typing import Dict, Optional, Any, List, Tuple
from ..logger import get_logger

logger = get_logger()

# Import protobuf definitions from proto package
try:
    from proto import usp_record_1_4_pb2 as record_pb2
    from proto import usp_msg_1_4_pb2 as msg_pb2
    PROTOBUF_AVAILABLE = True
except ImportError:
    try:
        import usp_record_1_4_pb2 as record_pb2
        import usp_msg_1_4_pb2 as msg_pb2
        PROTOBUF_AVAILABLE = True
    except ImportError:
        logger.critical("Protobuf files not found in proto/ directory. Please generate them from .proto files")
        PROTOBUF_AVAILABLE = False
        record_pb2 = None
        msg_pb2 = None



class USPMessage:
    """USP Message and Record Builder"""

    def __init__(self, controller_id: str):
        self.controller_id = controller_id
        if not PROTOBUF_AVAILABLE:
            raise RuntimeError("Protobuf not available")

    def _new_msg(self, msg_type: int, msg_id: Optional[str] = None) -> Tuple[str, Any]:
        """Create a new USP Msg object with header"""
        mid = msg_id or str(uuid.uuid4())
        usp_msg = msg_pb2.Msg()
        usp_msg.header.msg_id = mid
        usp_msg.header.msg_type = msg_type
        return mid, usp_msg

    def _wrap_message(self, endpoint_id: str, usp_msg: Any) -> bytes:
        """Wrap USP Message into a USP Record"""
        msg_bytes = usp_msg.SerializeToString()
        usp_record = record_pb2.Record()
        usp_record.version = "1.4"
        usp_record.to_id = endpoint_id
        usp_record.from_id = self.controller_id
        usp_record.payload_security = record_pb2.Record.PayloadSecurity.PLAINTEXT
        usp_record.no_session_context.payload = msg_bytes
        return usp_record.SerializeToString()

    def build_get(self, endpoint_id: str, paths: List[str], msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create GET request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.GET, msg_id)
        for path in paths:
            usp_msg.body.request.get.param_paths.append(path)
        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_get(self, endpoint_id: str, paths: List[str]) -> bytes:
        """Backward-compatible create_get returning bytes"""
        _, data = self.build_get(endpoint_id, paths)
        return data

    def build_set(self, endpoint_id: str, params: Dict[str, Any],
                  allow_partial: bool = False, msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create SET request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.SET, msg_id)
        set_req = usp_msg.body.request.set
        set_req.allow_partial = allow_partial

        # Group parameters by parent object path (TR-369 standard)
        grouped: Dict[str, Dict[str, str]] = {}
        for path, value in params.items():
            if "." in path:
                last_dot = path.rfind(".")
                obj_p = path[:last_dot + 1]
                param_name = path[last_dot + 1:]
            else:
                obj_p = ""
                param_name = path

            if obj_p not in grouped:
                grouped[obj_p] = {}
            grouped[obj_p][param_name] = str(value)

        for obj_p, param_map in grouped.items():
            update_obj = set_req.update_objs.add()
            update_obj.obj_path = obj_p
            for p_name, p_val in param_map.items():
                param = update_obj.param_settings.add()
                param.param = p_name
                param.value = str(p_val)
                param.required = True

        return mid, self._wrap_message(endpoint_id, usp_msg)


    def create_set(self, endpoint_id: str, params: Dict[str, Any],
                   allow_partial: bool = False) -> bytes:
        """Backward-compatible create_set returning bytes"""
        _, data = self.build_set(endpoint_id, params, allow_partial)
        return data

    def build_add(self, endpoint_id: str, obj_path: str,
                  params: Optional[Dict[str, Any]] = None,
                  allow_partial: bool = False, msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create ADD request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.ADD, msg_id)
        add_req = usp_msg.body.request.add
        add_req.allow_partial = allow_partial
        create_obj = add_req.create_objs.add()
        create_obj.obj_path = obj_path

        if params:
            for key, value in params.items():
                param = create_obj.param_settings.add()
                param.param = key
                param.value = str(value)
                param.required = False

        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_add(self, endpoint_id: str, obj_path: str,
                   params: Optional[Dict[str, Any]] = None) -> bytes:
        """Backward-compatible create_add returning bytes"""
        _, data = self.build_add(endpoint_id, obj_path, params)
        return data

    def build_delete(self, endpoint_id: str, obj_paths: List[str],
                     allow_partial: bool = False, msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create DELETE request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.DELETE, msg_id)
        del_req = usp_msg.body.request.delete
        del_req.allow_partial = allow_partial
        for obj_path in obj_paths:
            del_req.obj_paths.append(obj_path)
        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_delete(self, endpoint_id: str, obj_paths: List[str],
                      allow_partial: bool = False) -> bytes:
        """Backward-compatible create_delete returning bytes"""
        _, data = self.build_delete(endpoint_id, obj_paths, allow_partial)
        return data

    def build_operate(self, endpoint_id: str, command: str,
                      args: Optional[Dict[str, Any]] = None,
                      send_resp: bool = True, msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create OPERATE request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.OPERATE, msg_id)
        op_req = usp_msg.body.request.operate
        op_req.command = command
        op_req.send_resp = send_resp

        if args:
            for key, value in args.items():
                op_req.input_args[key] = str(value)

        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_operate(self, endpoint_id: str, command: str,
                       args: Optional[Dict[str, Any]] = None,
                       send_resp: bool = True) -> bytes:
        """Backward-compatible create_operate returning bytes"""
        _, data = self.build_operate(endpoint_id, command, args, send_resp)
        return data

    def build_get_supported_dm(self, endpoint_id: str, obj_paths: List[str],
                               first_level_only: bool = False,
                               return_commands: bool = True,
                               return_events: bool = True,
                               return_params: bool = True,
                               msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create GetSupportedDM request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.GET_SUPPORTED_DM, msg_id)
        dm_req = usp_msg.body.request.get_supported_dm
        dm_req.first_level_only = first_level_only
        dm_req.return_commands = return_commands
        dm_req.return_events = return_events
        dm_req.return_params = return_params

        for obj_path in obj_paths:
            dm_req.obj_paths.append(obj_path)

        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_get_supported_dm(self, endpoint_id: str, obj_paths: List[str],
                                first_level_only: bool = False,
                                return_commands: bool = True,
                                return_events: bool = True,
                                return_params: bool = True) -> bytes:
        """Backward-compatible create_get_supported_dm returning bytes"""
        _, data = self.build_get_supported_dm(
            endpoint_id, obj_paths, first_level_only, return_commands, return_events, return_params
        )
        return data

    def build_get_instances(self, endpoint_id: str, obj_paths: List[str],
                            first_level_only: bool = False,
                            msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create GetInstances request, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.GET_INSTANCES, msg_id)
        inst_req = usp_msg.body.request.get_instances
        inst_req.first_level_only = first_level_only
        for obj_path in obj_paths:
            inst_req.obj_paths.append(obj_path)
        return mid, self._wrap_message(endpoint_id, usp_msg)

    def create_get_instances(self, endpoint_id: str, obj_paths: List[str],
                             first_level_only: bool = False) -> bytes:
        """Backward-compatible create_get_instances returning bytes"""
        _, data = self.build_get_instances(endpoint_id, obj_paths, first_level_only)
        return data

    def build_notify_resp(self, endpoint_id: str, subscription_id: str,
                           msg_id: Optional[str] = None) -> Tuple[str, bytes]:
        """Create NOTIFY_RESP response, returning (msg_id, serialized_record_bytes)"""
        mid, usp_msg = self._new_msg(msg_pb2.Header.MsgType.NOTIFY_RESP, msg_id)
        usp_msg.body.response.notify_resp.subscription_id = subscription_id
        return mid, self._wrap_message(endpoint_id, usp_msg)

    @staticmethod
    def parse_record(record_bytes: bytes) -> Tuple[Optional[str], Optional[str], Optional[Any]]:
        """
        Parse USP Record
        Returns: (from_id, to_id, usp_msg_object_or_None)
        """
        if not PROTOBUF_AVAILABLE:
            return None, None, None

        try:
            record = record_pb2.Record()
            record.ParseFromString(record_bytes)
            from_id = record.from_id
            to_id = record.to_id

            payload = None
            if record.HasField('no_session_context'):
                payload = record.no_session_context.payload
            elif record.HasField('session_context'):
                payload = record.session_context.payload

            if payload:
                msg = msg_pb2.Msg()
                msg.ParseFromString(payload)
                return from_id, to_id, msg

            return from_id, to_id, None
        except Exception as e:
            logger.error(f"Failed to parse USP record: {e}")
            return None, None, None


class USPParser:
    """Helper to parse USP Response Protobuf objects into structured Python dicts"""

    @staticmethod
    def parse_msg(msg: Any) -> Dict[str, Any]:
        """Parse any USP Msg into a structured dictionary"""
        if not msg:
            return {"type": "UNKNOWN", "status": "error", "error": "Empty message"}

        msg_id = msg.header.msg_id
        msg_type_code = msg.header.msg_type
        msg_type_name = msg_pb2.Header.MsgType.Name(msg_type_code)

        result: Dict[str, Any] = {
            "msg_id": msg_id,
            "msg_type": msg_type_name,
            "raw_msg": msg
        }

        if msg.body.HasField('response'):
            resp = msg.body.response
            result["body_type"] = "response"
            if resp.HasField('get_resp'):
                result.update(USPParser.parse_get_resp(resp.get_resp))
            elif resp.HasField('set_resp'):
                result.update(USPParser.parse_set_resp(resp.set_resp))
            elif resp.HasField('add_resp'):
                result.update(USPParser.parse_add_resp(resp.add_resp))
            elif resp.HasField('delete_resp'):
                result.update(USPParser.parse_delete_resp(resp.delete_resp))
            elif resp.HasField('operate_resp'):
                result.update(USPParser.parse_operate_resp(resp.operate_resp))
            elif resp.HasField('get_supported_dm_resp'):
                result.update(USPParser.parse_get_supported_dm_resp(resp.get_supported_dm_resp))
            elif resp.HasField('get_instances_resp'):
                result.update(USPParser.parse_get_instances_resp(resp.get_instances_resp))
            elif resp.HasField('notify_resp'):
                result["status"] = "success"
                result["subscription_id"] = resp.notify_resp.subscription_id
            else:
                result["status"] = "success"

        elif msg.body.HasField('request'):
            req = msg.body.request
            result["body_type"] = "request"
            if req.HasField('notify'):
                result.update(USPParser.parse_notify_req(req.notify))
            else:
                result["status"] = "received_request"

        elif msg.body.HasField('error'):
            err = msg.body.error
            result["body_type"] = "error"
            result["status"] = "error"
            result["err_code"] = getattr(err, "err_code", 7000)
            result["err_msg"] = getattr(err, "err_msg", "General Error")
            param_errs = []
            for pe in getattr(err, "param_errs", []):
                param_errs.append({
                    "param": getattr(pe, "param_path", ""),
                    "err_code": getattr(pe, "err_code", 0),
                    "err_msg": getattr(pe, "err_msg", "")
                })
            result["errors"] = param_errs

        return result


    @staticmethod
    def parse_get_resp(get_resp: Any) -> Dict[str, Any]:
        """Extract path-value pairs from GetResp"""
        params: Dict[str, str] = {}
        paths_status: List[Dict[str, Any]] = []

        for r in get_resp.req_path_results:
            p_stat = {
                "requested_path": r.requested_path,
                "err_code": r.err_code,
                "err_msg": r.err_msg,
                "success": (r.err_code == 0)
            }
            paths_status.append(p_stat)
            for res in r.resolved_path_results:
                for p, v in res.result_params.items():
                    # If resolved_path exists and param is just param name
                    full_key = f"{res.resolved_path}{p}" if not p.startswith(res.resolved_path) else p
                    params[full_key] = v

        return {
            "status": "success" if any(p["success"] for p in paths_status) or not paths_status else "error",
            "parameters": params,
            "path_results": paths_status,
            "count": len(params)
        }

    @staticmethod
    def parse_set_resp(set_resp: Any) -> Dict[str, Any]:
        """Extract results from SetResp (supports USP 1.0-1.4 oper_status hierarchy)"""
        updated_params: Dict[str, str] = {}
        errors: List[Dict[str, Any]] = []

        for obj_res in set_resp.updated_obj_results:
            req_path = getattr(obj_res, "requested_path", "")

            # Check if oper_status is present (USP 1.2+ standard)
            if hasattr(obj_res, "oper_status"):
                status_field = obj_res.oper_status.WhichOneof("oper_status")
                if status_field == "oper_success":
                    succ = obj_res.oper_status.oper_success
                    for inst_res in succ.updated_inst_results:
                        aff_path = getattr(inst_res, "affected_path", req_path)
                        for k, v in inst_res.updated_params.items():
                            full_k = f"{aff_path}{k}" if not k.startswith(aff_path) else k
                            updated_params[full_k] = v
                        for pe in inst_res.param_errs:
                            errors.append({
                                "param": pe.param,
                                "err_code": pe.err_code,
                                "err_msg": pe.err_msg
                            })
                elif status_field == "oper_failure":
                    fail = obj_res.oper_status.oper_failure
                    errors.append({
                        "requested_path": req_path,
                        "err_code": fail.err_code,
                        "err_msg": fail.err_msg
                    })
                    for inst_fail in fail.updated_inst_failures:
                        aff_path = getattr(inst_fail, "affected_path", req_path)
                        for pe in inst_fail.param_errs:
                            errors.append({
                                "param": f"{aff_path}{pe.param}",
                                "err_code": pe.err_code,
                                "err_msg": pe.err_msg
                            })
            else:
                # Fallback for direct attributes
                affected = getattr(obj_res, "affected_path", req_path)
                params_dict = getattr(obj_res, "updated_params", {})
                for k, v in params_dict.items():
                    full_k = f"{affected}{k}" if not k.startswith(affected) else k
                    updated_params[full_k] = v
                for pe in getattr(obj_res, "param_errs", []):
                    errors.append({
                        "param": getattr(pe, "param", ""),
                        "err_code": getattr(pe, "err_code", 0),
                        "err_msg": getattr(pe, "err_msg", "")
                    })

        return {
            "status": "success" if not errors else ("partial" if updated_params else "error"),
            "updated_params": updated_params,
            "errors": errors
        }

    @staticmethod
    def parse_add_resp(add_resp: Any) -> Dict[str, Any]:
        """Extract created instances from AddResp (supports USP 1.0-1.4 oper_status hierarchy)"""
        created: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        for res in add_resp.created_obj_results:
            req_path = getattr(res, "requested_path", "")

            if hasattr(res, "oper_status"):
                status_field = res.oper_status.WhichOneof("oper_status")
                if status_field == "oper_success":
                    succ = res.oper_status.oper_success
                    inst_path = getattr(succ, "instantiated_path", "")
                    u_keys = dict(succ.unique_keys) if hasattr(succ, "unique_keys") else {}
                    created.append({
                        "requested_path": req_path,
                        "instantiated_path": inst_path,
                        "params": u_keys
                    })
                    for pe in getattr(succ, "param_errs", []):
                        errors.append({
                            "param": pe.param,
                            "err_code": pe.err_code,
                            "err_msg": pe.err_msg
                        })
                elif status_field == "oper_failure":
                    fail = res.oper_status.oper_failure
                    errors.append({
                        "requested_path": req_path,
                        "err_code": getattr(fail, "err_code", 7000),
                        "err_msg": getattr(fail, "err_msg", "Add failed")
                    })
            else:
                err_c = getattr(res, "err_code", 0)
                if err_c == 0:
                    created.append({
                        "requested_path": req_path,
                        "instantiated_path": getattr(res, "instantiated_path", ""),
                        "params": dict(getattr(res, "unique_keys", {}))
                    })
                else:
                    errors.append({
                        "requested_path": req_path,
                        "err_code": err_c,
                        "err_msg": getattr(res, "err_msg", "")
                    })

        return {
            "status": "success" if created and not errors else ("partial" if created else "error"),
            "created": created,
            "errors": errors
        }

    @staticmethod
    def parse_delete_resp(del_resp: Any) -> Dict[str, Any]:
        """Extract deleted paths from DeleteResp (supports USP 1.0-1.4 oper_status hierarchy)"""
        deleted: List[str] = []
        errors: List[Dict[str, Any]] = []

        for res in del_resp.deleted_obj_results:
            req_path = getattr(res, "requested_path", "")

            if hasattr(res, "oper_status"):
                status_field = res.oper_status.WhichOneof("oper_status")
                if status_field == "oper_success":
                    succ = res.oper_status.oper_success
                    aff_paths = list(getattr(succ, "affected_paths", []))
                    deleted.extend(aff_paths)
                    for unaf in getattr(succ, "unaffected_path_errs", []):
                        errors.append({
                            "unaffected_path": getattr(unaf, "unaffected_path", ""),
                            "err_code": getattr(unaf, "err_code", 0),
                            "err_msg": getattr(unaf, "err_msg", "")
                        })
                elif status_field == "oper_failure":
                    fail = res.oper_status.oper_failure
                    errors.append({
                        "requested_path": req_path,
                        "err_code": getattr(fail, "err_code", 7000),
                        "err_msg": getattr(fail, "err_msg", "Delete failed")
                    })
            else:
                err_c = getattr(res, "err_code", 0)
                if err_c == 0:
                    deleted.append(getattr(res, "affected_path", req_path))
                else:
                    errors.append({
                        "affected_path": getattr(res, "affected_path", req_path),
                        "err_code": err_c,
                        "err_msg": getattr(res, "err_msg", "")
                    })

        return {
            "status": "success" if not errors else ("partial" if deleted else "error"),
            "deleted_paths": [p for p in deleted if p],
            "errors": errors
        }


    @staticmethod
    def parse_operate_resp(op_resp: Any) -> Dict[str, Any]:
        """Extract operation results from OperateResp"""
        results: List[Dict[str, Any]] = []
        for res in op_resp.operation_results:
            results.append({
                "executed_command": res.executed_command,
                "req_output_args": dict(res.req_output_args.output_args) if res.HasField('req_output_args') else {},
                "cmd_failure": {
                    "err_code": res.cmd_failure.err_code,
                    "err_msg": res.cmd_failure.err_msg
                } if res.HasField('cmd_failure') else None
            })

        return {
            "status": "success" if all(r["cmd_failure"] is None for r in results) else "error",
            "operation_results": results
        }

    @staticmethod
    def parse_get_supported_dm_resp(dm_resp: Any) -> Dict[str, Any]:
        """Extract supported data model items"""
        objects: List[Dict[str, Any]] = []
        for obj in dm_resp.req_obj_results:
            obj_info = {
                "req_obj_path": obj.req_obj_path,
                "err_code": obj.err_code,
                "err_msg": obj.err_msg,
                "supported_objs": []
            }
            for sup_obj in obj.supported_objs:
                sup_info = {
                    "supported_obj_path": sup_obj.supported_obj_path,
                    "access": sup_obj.access,
                    "is_multi_instance": sup_obj.is_multi_instance,
                    "supported_params": [
                        {"param_name": p.param_name, "value_type": p.value_type, "access": p.access}
                        for p in sup_obj.supported_params
                    ],
                    "supported_commands": [
                        {"command_name": c.command_name, "command_type": c.command_type}
                        for c in sup_obj.supported_commands
                    ],
                    "supported_events": [
                        {"event_name": e.event_name}
                        for e in sup_obj.supported_events
                    ]
                }
                obj_info["supported_objs"].append(sup_info)
            objects.append(obj_info)

        return {
            "status": "success",
            "supported_dm": objects
        }

    @staticmethod
    def parse_get_instances_resp(inst_resp: Any) -> Dict[str, Any]:
        """Extract object instance paths"""
        instances: List[str] = []
        for res in inst_resp.req_path_results:
            if res.err_code == 0:
                for inst in res.curr_insts:
                    instances.append(inst.instantiated_obj_path)

        return {
            "status": "success",
            "instances": instances
        }

    @staticmethod
    def parse_notify_req(notify: Any) -> Dict[str, Any]:
        """Extract notification details"""
        notify_type = "unknown"
        details: Dict[str, Any] = {}

        if notify.HasField('event'):
            notify_type = "event"
            ev = notify.event
            details = {
                "obj_path": ev.obj_path,
                "event_name": ev.event_name,
                "params": dict(ev.params)
            }
        elif notify.HasField('value_change'):
            notify_type = "value_change"
            vc = notify.value_change
            details = {
                "param_path": vc.param_path,
                "param_value": vc.param_value
            }
        elif notify.HasField('obj_creation'):
            notify_type = "obj_creation"
            details = {
                "obj_path": notify.obj_creation.obj_path,
                "unique_keys": dict(notify.obj_creation.unique_keys)
            }
        elif notify.HasField('obj_deletion'):
            notify_type = "obj_deletion"
            details = {"obj_path": notify.obj_deletion.obj_path}
        elif notify.HasField('oper_complete'):
            notify_type = "oper_complete"
            details = {"cmd_name": notify.oper_complete.cmd_name}

        return {
            "status": "received_notify",
            "subscription_id": notify.subscription_id,
            "send_resp": notify.send_resp,
            "notify_type": notify_type,
            "details": details
        }
