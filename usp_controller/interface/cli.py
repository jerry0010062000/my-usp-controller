#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI Interface Implementation
Cross-platform interactive shell and one-shot execution interface for USP Controller.
"""

import sys
import os
import atexit
import platform
from pathlib import Path
from typing import Optional, Any
from .base import InterfaceBase, InterfaceType, CommandContext, CommandResult
from .formatter import OutputFormatter, ColoredFormatter, get_formatter, OutputFormat
from .command_handler import CommandHandler
from usp_version import FULL_VERSION

# Try to setup readline / pyreadline for command history and navigation
try:
    if sys.platform == 'win32':
        import pyreadline3 as readline
    else:
        import readline

    histfile = os.path.join(os.path.expanduser("~"), ".usp_controller_history")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass
    atexit.register(readline.write_history_file, histfile)
    READLINE_AVAILABLE = True
except Exception:
    READLINE_AVAILABLE = False


class CLIInterface(InterfaceBase):
    """
    Standard Interactive CLI & Command Runner
    """

    def __init__(
        self,
        prompt: str = "usp> ",
        formatter: Optional[OutputFormatter] = None,
        command_handler: Optional[CommandHandler] = None
    ):
        super().__init__(InterfaceType.CLI)
        self._base_prompt = prompt
        self._running = False
        self._formatter = formatter or ColoredFormatter()
        self._command_handler = command_handler or CommandHandler()

        self._platform = platform.system()
        self._is_windows = (self._platform == "Windows")

        if self._is_windows:
            self._enable_windows_ansi()

    def _enable_windows_ansi(self):
        """Enable Windows 10+ Virtual Terminal ANSI support"""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass

    def initialize(self) -> bool:
        """Initialize CLI interface and banner"""
        try:
            self._display_banner()
            return True
        except Exception as e:
            print(f"Failed to initialize CLI: {e}")
            return False

    def _get_dynamic_prompt(self) -> str:
        """Get prompt with active target device context"""
        ctrl = getattr(self._command_handler, '_controller', None)
        if ctrl and hasattr(ctrl, 'device_manager'):
            target = ctrl.device_manager.get_active_device()
            if target:
                short_target = target.split('::')[-1] if '::' in target else target
                return f"usp [{short_target}]> "
        return self._base_prompt

    def _display_banner(self):
        """Display welcome banner"""
        ctrl = getattr(self._command_handler, '_controller', None)
        conn_info = "Standalone"
        if ctrl and hasattr(ctrl, 'config'):
            conn_info = f"{ctrl.config.transport.protocol.upper()} @ {ctrl.config.transport.host}:{ctrl.config.transport.port}"

        banner = f"""
{self._formatter.format_success('=' * 65)}
  USP Controller CLI v{FULL_VERSION}
  Platform:  {self._platform}
  Transport: {conn_info}
  Type 'help' for commands, 'devices' for agents, 'quit' to exit
{self._formatter.format_success('=' * 65)}
"""
        print(banner)

    def run(self):
        """Start interactive CLI REPL"""
        self._running = True

        # Setup tab completion if readline is available
        if READLINE_AVAILABLE:
            try:
                def completer(text, state):
                    names = self._command_handler.get_command_names()
                    matches = [c for c in names if c.startswith(text.lower())]
                    return matches[state] if state < len(matches) else None

                readline.set_completer(completer)
                readline.parse_and_bind('tab: complete')
            except Exception:
                pass

        while self._running:
            try:
                prompt_str = self._get_dynamic_prompt()
                user_input = self.prompt_input(prompt_str)

                if not user_input.strip():
                    continue

                context = self._command_handler.parse_command(user_input)
                self._emit('on_command', context)

                result = self._command_handler.execute(context)
                self.display_output(result)
                self._emit('on_result', result)

                if result.metadata.get('action') == 'quit':
                    self._running = False

            except KeyboardInterrupt:
                print(f"\n{self._formatter.format_info('Press Ctrl+C again or type quit/exit to leave.')}")
                continue
            except EOFError:
                print("\n" + self._formatter.format_info("Goodbye!"))
                break
            except Exception as e:
                self.display_error(f"Unexpected error: {e}")

    def execute_single(self, cmd_line: str) -> CommandResult:
        """Execute a single command string directly (for one-shot CLI mode)"""
        context = self._command_handler.parse_command(cmd_line)
        result = self._command_handler.execute(context)
        self.display_output(result)
        return result

    def shutdown(self):
        """Shutdown CLI interface"""
        self._running = False

    def display_output(self, result: CommandResult):
        """Display command result formatted"""
        if not result.success:
            self.display_error(result.error or "Command failed")
            return

        if result.message:
            print(result.message)

        if result.data is not None:
            # If report or special object, check format
            from ..scripting import ScriptExecutionReport
            if isinstance(result.data, ScriptExecutionReport):
                pass  # Summary message already contains details
            else:
                formatted = self._formatter.format_result(result.data)
                if formatted:
                    print(formatted)

    def display_error(self, error: str):
        """Display error message"""
        print(self._formatter.format_error(error))

    def display_info(self, message: str):
        """Display informational message"""
        print(self._formatter.format_info(message))

    def prompt_input(self, prompt: str = "") -> str:
        """Prompt user for input"""
        return input(prompt)

    def confirm_action(self, message: str) -> bool:
        """Prompt user for confirmation"""
        try:
            res = input(f"{message} [y/N]: ").strip().lower()
            return res in ('y', 'yes')
        except (EOFError, KeyboardInterrupt):
            return False


# Optional Enhanced CLI Interface (using prompt_toolkit)
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.styles import Style

    class EnhancedCLIInterface(CLIInterface):
        """Enhanced CLI Interface with prompt_toolkit"""

        def __init__(
            self,
            prompt: str = "usp> ",
            formatter: Optional[OutputFormatter] = None,
            command_handler: Optional[CommandHandler] = None
        ):
            super().__init__(prompt, formatter, command_handler)
            self._history = InMemoryHistory()
            self._session = None
            self._style = Style.from_dict({
                'prompt': 'ansicyan bold',
            })

        def initialize(self) -> bool:
            if not super().initialize():
                return False
            try:
                command_names = self._command_handler.get_command_names()
                completer = WordCompleter(command_names, ignore_case=True)
                self._session = PromptSession(
                    message=self._get_dynamic_prompt,
                    completer=completer,
                    history=self._history,
                    style=self._style
                )
                return True
            except Exception:
                return True

        def prompt_input(self, prompt: str = "") -> str:
            if self._session:
                try:
                    return self._session.prompt()
                except Exception:
                    return input(prompt)
            return input(prompt)

except ImportError:
    EnhancedCLIInterface = None


def create_cli_interface(
    enhanced: bool = False,
    prompt: str = "usp> ",
    output_format: OutputFormat = OutputFormat.COLORED,
    command_handler: Optional[CommandHandler] = None
) -> CLIInterface:
    """Create CLI interface instance"""
    formatter = get_formatter(output_format)
    handler = command_handler or CommandHandler()

    if enhanced and EnhancedCLIInterface is not None:
        try:
            return EnhancedCLIInterface(prompt, formatter, handler)
        except Exception:
            pass

    return CLIInterface(prompt, formatter, handler)
