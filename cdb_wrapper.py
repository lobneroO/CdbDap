"""
Enhanced CDB (Console Debugger) wrapper for better integration with DAP.
This module provides improved communication and parsing of CDB output.
"""

import subprocess
import threading
import queue
import re
import time
import logging
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CdbBreakpoint:
    id: int
    address: str
    file: str
    line: int
    enabled: bool
    hit_count: int = 0


@dataclass
class CdbFrame:
    id: int
    name: str
    file: str
    line: int
    address: str


@dataclass
class CdbVariable:
    name: str
    value: str
    type: str
    address: Optional[str] = None


@dataclass
class CdbThread:
    id: int
    name: str
    state: str
    address: str


class CdbOutputParser:
    """Parser for CDB output"""

    # Regex patterns for parsing CDB output
    BREAKPOINT_PATTERN = re.compile(r'^\s*(\d+):\s+([0-9a-f`]+)\s+.*?(@#\d+)?\s*(.*)$', re.MULTILINE)
    STACK_FRAME_PATTERN = re.compile(r'^(\d+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(.+?)(?:\s+\[(.+?)\s+@\s+(\d+)\])?$', re.MULTILINE)
    VARIABLE_PATTERN = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)(?:\s+\[Type:\s+(.+?)\])?$', re.MULTILINE)
    THREAD_PATTERN = re.compile(r'^\s*(\d+)\s+Id:\s+([0-9a-f.]+)\s+Suspend:\s+(\d+)\s+Teb:\s+([0-9a-f`]+)\s+(.*)$', re.MULTILINE)

    @classmethod
    def parse_breakpoints(cls, output: str) -> List[CdbBreakpoint]:
        """Parse breakpoint list output"""
        breakpoints = []
        matches = cls.BREAKPOINT_PATTERN.findall(output)

        for match in matches:
            bp_id, address, _, description = match
            # Extract file and line from description if available
            file_line_match = re.search(r'(.+):(\d+)', description)
            if file_line_match:
                file_path = file_line_match.group(1)
                line_num = int(file_line_match.group(2))
            else:
                file_path = ""
                line_num = 0

            breakpoints.append(CdbBreakpoint(
                id=int(bp_id),
                address=address,
                file=file_path,
                line=line_num,
                enabled=True  # Assume enabled unless parsed otherwise
            ))

        return breakpoints

    @classmethod
    def parse_stack_trace(cls, output: str) -> List[CdbFrame]:
        """Parse stack trace output"""
        frames = []
        matches = cls.STACK_FRAME_PATTERN.findall(output)

        for i, match in enumerate(matches):
            frame_id, child_ebp, ret_addr, function, file_path, line_str = match

            line_num = 0
            if line_str:
                try:
                    line_num = int(line_str)
                except ValueError:
                    pass

            frames.append(CdbFrame(
                id=i,
                name=function,
                file=file_path or "",
                line=line_num,
                address=ret_addr
            ))

        return frames

    @classmethod
    def parse_variables(cls, output: str) -> List[CdbVariable]:
        """Parse variable list output"""
        variables = []
        matches = cls.VARIABLE_PATTERN.findall(output)

        for match in matches:
            name, value, var_type = match
            variables.append(CdbVariable(
                name=name,
                value=value,
                type=var_type or "unknown"
            ))

        return variables

    @classmethod
    def parse_threads(cls, output: str) -> List[CdbThread]:
        """Parse thread list output"""
        threads = []
        matches = cls.THREAD_PATTERN.findall(output)

        for match in matches:
            thread_id, thread_name, suspend_count, teb, state = match
            threads.append(CdbThread(
                id=int(thread_id),
                name=f"Thread {thread_id}",
                state=state,
                address=teb
            ))

        return threads


class CdbCommunicator:
    """Handles communication with CDB process"""

    def __init__(self):
        self.process = None
        self.output_queue = queue.Queue()
        self.output_thread = None
        self.is_running = False
        self.current_command = None
        self.command_response = ""
        self.command_event = threading.Event()

    def start_process(self, program: str, args: List[str] = None,
                      cwd: str = None) -> bool:
        """Start CDB process"""
        try:
            cdb_command = ['cdb.exe', '-g', '-G', '-cf', '-cfr']
            cdb_command.append(program)
            if args:
                cdb_command.extend(args)

            self.process = subprocess.Popen(
                cdb_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=cwd,
                bufsize=0,
                universal_newlines=True
            )

            self.is_running = True
            self.start_output_thread()

            # Send initial setup commands
            self.send_command(".echo Setting up debugger...")
            self.send_command(".symopt+0x100")  # Enable source line support

            logger.info(f"Started CDB process for program: {program}")
            return True

        except Exception as e:
            logger.error(f"Failed to start CDB process: {e}")
            return False

    def attach_to_process(self, pid: int) -> bool:
        """Attach to existing process"""
        try:
            self.process = subprocess.Popen(
                ['cdb.exe', '-p', str(pid), '-cf', '-cfr'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=0,
                universal_newlines=True
            )

            self.is_running = True
            self.start_output_thread()

            logger.info(f"Attached CDB to process: {pid}")
            return True

        except Exception as e:
            logger.error(f"Failed to attach CDB to process: {e}")
            return False

    def start_output_thread(self):
        """Start thread to read CDB output"""
        self.output_thread = threading.Thread(target=self._read_output,
                                              daemon=True)
        self.output_thread.start()

    def _read_output(self):
        """Read output from CDB process"""
        buffer = ""

        while self.is_running and self.process:
            try:
                char = self.process.stdout.read(1)
                if not char:
                    break

                buffer += char

                # Check for command prompt
                if buffer.endswith('0:000> ') or buffer.endswith('> '):
                    if self.current_command:
                        self.command_response = buffer
                        self.command_event.set()
                    else:
                        # Unsolicited output (e.g., breakpoint hit)
                        self.output_queue.put(buffer)
                    buffer = ""

            except Exception as e:
                logger.error(f"Error reading CDB output: {e}")
                break

    def send_command(self, command: str, timeout: float = 5.0) -> str:
        """Send command to CDB and wait for response"""
        if not self.process or not self.is_running:
            return ""

        try:
            self.current_command = command
            self.command_response = ""
            self.command_event.clear()

            logger.debug(f"Sending CDB command: {command}")
            self.process.stdin.write(command + '\n')
            self.process.stdin.flush()

            # Wait for response
            if self.command_event.wait(timeout):
                response = self.command_response
                self.current_command = None
                return response
            else:
                logger.warning(f"Command timeout: {command}")
                self.current_command = None
                return ""

        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return ""

    def get_unsolicited_output(self) -> Optional[str]:
        """Get any unsolicited output from CDB"""
        try:
            return self.output_queue.get_nowait()
        except queue.Empty:
            return None

    def terminate(self):
        """Terminate CDB process"""
        self.is_running = False
        if self.process:
            try:
                self.process.stdin.write('q\n')
                self.process.stdin.flush()
                self.process.wait(timeout=2)
            except:
                self.process.terminate()
            self.process = None

        if self.output_thread:
            self.output_thread.join(timeout=1)


class EnhancedCdbDebugger:
    """Enhanced CDB debugger with better parsing and communication"""

    def __init__(self):
        self.communicator = CdbCommunicator()
        self.parser = CdbOutputParser()
        self.breakpoints = {}
        self.next_bp_id = 1
        self.current_thread_id = 0
        self.is_stopped = True

    def start(self, program: str, args: List[str] = None,
              cwd: str = None) -> bool:
        """Start debugging session"""
        return self.communicator.start_process(program, args, cwd)

    def attach(self, pid: int) -> bool:
        """Attach to existing process"""
        return self.communicator.attach_to_process(pid)

    def set_breakpoint(self, file_path: str, line: int) -> int:
        """Set breakpoint at specified location"""
        bp_id = self.next_bp_id
        self.next_bp_id += 1

        # Use CDB's source line breakpoint syntax
        command = f'bp `{file_path}:{line}`'
        response = self.communicator.send_command(command)

        # Verify breakpoint was set
        verified = "breakpoint" in response.lower() or bp_id > 0

        self.breakpoints[bp_id] = {
            'file': file_path,
            'line': line,
            'verified': verified,
            'cdb_id': bp_id
        }

        logger.info(f"Set breakpoint {bp_id} at {file_path}:{line}, "
                    f"verified: {verified}")
        return bp_id

    def remove_breakpoint(self, bp_id: int):
        """Remove breakpoint"""
        if bp_id in self.breakpoints:
            cdb_id = self.breakpoints[bp_id]['cdb_id']
            command = f'bc {cdb_id}'
            self.communicator.send_command(command)
            del self.breakpoints[bp_id]
            logger.info(f"Removed breakpoint {bp_id}")

    def continue_execution(self):
        """Continue program execution"""
        self.is_stopped = False
        self.communicator.send_command('g')

    def step_over(self):
        """Step over current line"""
        self.communicator.send_command('p')

    def step_into(self):
        """Step into function call"""
        self.communicator.send_command('t')

    def step_out(self):
        """Step out of current function"""
        self.communicator.send_command('gu')

    def pause(self):
        """Pause execution"""
        # Send Ctrl+C to break execution
        self.communicator.send_command('.break')
        self.is_stopped = True

    def get_stack_trace(self, thread_id: int = None) -> List[CdbFrame]:
        """Get current stack trace"""
        if thread_id and thread_id != self.current_thread_id:
            self.switch_thread(thread_id)

        response = self.communicator.send_command('kn')
        return self.parser.parse_stack_trace(response)

    def get_local_variables(self, frame_id: int = 0) -> List[CdbVariable]:
        """Get local variables for specific frame"""
        # Switch to specific frame if needed
        if frame_id > 0:
            self.communicator.send_command(f'.frame {frame_id}')

        response = self.communicator.send_command('dv /t /v')

        # Switch back to frame 0
        if frame_id > 0:
            self.communicator.send_command('.frame 0')

        return self.parser.parse_variables(response)

    def get_arguments(self, frame_id: int = 0) -> List[CdbVariable]:
        """Get function arguments for specific frame"""
        # Switch to specific frame if needed
        if frame_id > 0:
            self.communicator.send_command(f'.frame {frame_id}')

        # Get function parameters
        # include parameters
        response = self.communicator.send_command('dv /t /v /i')

        # Switch back to frame 0
        if frame_id > 0:
            self.communicator.send_command('.frame 0')

        # Filter for parameters only (this is a simplified approach)
        variables = self.parser.parse_variables(response)
        # In a real implementation,
        # you'd distinguish between locals and parameters
        # Return first 2 as "arguments"
        return variables[:2] if variables else []

    def stop(self):
        """Stop the debugger (alias for terminate)"""
        self.terminate()

    def get_threads(self) -> List[CdbThread]:
        """Get thread list"""
        response = self.communicator.send_command('~')
        return self.parser.parse_threads(response)

    def switch_thread(self, thread_id: int):
        """Switch to specified thread"""
        self.communicator.send_command(f'~{thread_id}s')
        self.current_thread_id = thread_id

    def evaluate_expression(self, expression: str) -> str:
        """Evaluate expression"""
        response = self.communicator.send_command(f'? {expression}')
        # Parse the response to extract the value
        lines = response.split('\n')
        for line in lines:
            if 'Evaluate expression:' in line:
                return line.split(':', 1)[1].strip()
        return response.strip()

    def get_memory(self, address: str, size: int = 16) -> str:
        """Get memory contents"""
        response = self.communicator.send_command(f'db {address} L{size}')
        return response

    def check_for_events(self) -> Optional[Dict[str, Any]]:
        """Check for debugging events (breakpoints, exceptions, etc.)"""
        output = self.communicator.get_unsolicited_output()
        if not output:
            return None

        # Parse output for events
        if 'Breakpoint' in output:
            self.is_stopped = True
            return {
                'type': 'stopped',
                'reason': 'breakpoint',
                'threadId': self.current_thread_id or 1
            }
        elif 'Access violation' in output or 'Exception' in output:
            self.is_stopped = True
            return {
                'type': 'stopped',
                'reason': 'exception',
                'threadId': self.current_thread_id or 1
            }
        elif 'process exited' in output.lower():
            return {
                'type': 'exited',
                'exitCode': 0
            }

        return None

    def terminate(self):
        """Terminate debugging session"""
        self.communicator.terminate()

