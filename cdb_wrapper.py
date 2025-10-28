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
import os
import sys
import shutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

# Configure logging
log_file = os.path.join(os.path.dirname(__file__), 'socket_dap_debug.log')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        # append mode to add to existing log
        logging.FileHandler(log_file, mode='a'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

# Configure CDB interaction logger
cdb_log_file = os.path.join(os.path.dirname(__file__), 'cdb_interaction.log')
cdb_logger = logging.getLogger('cdb_interaction')
cdb_logger.setLevel(logging.DEBUG)
cdb_handler = logging.FileHandler(cdb_log_file, mode='a')
cdb_formatter = logging.Formatter('%(asctime)s - %(message)s')
cdb_handler.setFormatter(cdb_formatter)
cdb_logger.addHandler(cdb_handler)
cdb_logger.propagate = False  # Don't propagate to root logger


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
    is_container: bool = False
    container_size: Optional[int] = None
    container_type: Optional[str] = None  # e.g., 'vector', 'array', 'map'


@dataclass
class CdbThread:
    id: int
    name: str
    state: str
    address: str


def clean_integer_value(value: str) -> str:
    """
    Clean up integer values by removing CDB-specific formatting.
    
    CDB often returns integers in the format "0n42" where "0n" indicates
    decimal format. Since we always want decimal view, we remove the "0n" prefix.
    
    Args:
        value: The value string from CDB
        
    Returns:
        Cleaned value string with "0n" prefix removed
    """
    if isinstance(value, str) and value.startswith('0n'):
        return value[2:]  # Remove "0n" prefix
    return value


class CdbOutputParser:
    """Parser for CDB output"""

    # Regex patterns for parsing CDB output
    BREAKPOINT_PATTERN = re.compile(r'^\s*(\d+):\s+([0-9a-f`]+)\s+.*?(@#\d+)?\s*(.*)$', re.MULTILINE)
    STACK_FRAME_PATTERN = re.compile(r'^(\d+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(.+?)(?:\s+\[(.+?)\s+@\s+(\d+)\])?$', re.MULTILINE)
    # Extended variable pattern: allow angle brackets, commas,
    # colons for C++ template types
    # Allow optional leading whitespace to handle indented output
    VARIABLE_PATTERN = re.compile(
        r'^\s*prv\s+(\w+)\s+([\w\s\*\[\]<>:,]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$',
        re.MULTILINE
    )
    # Secondary simple assignment pattern (lines without 'prv' prefix)
    SIMPLE_ASSIGN_PATTERN = re.compile(
        r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$'
    )
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
        logger.debug(f"Parsing stack trace output: {repr(output)}")

        # Split into lines and process each line
        lines = output.strip().split('\n')
        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line or 'Child-SP' in line or line.startswith('#'):
                continue

            logger.debug(f"Processing stack line {line_num}: {repr(line)}")

            # Try to match the stack frame pattern
            match = cls.STACK_FRAME_PATTERN.match(line)
            if match:
                frame_id, child_sp, ret_addr, function, file_path, line_str \
                    = match.groups()

                line_num = 0
                if line_str:
                    try:
                        line_num = int(line_str)
                    except ValueError:
                        pass

                frame = CdbFrame(
                    id=len(frames),  # Use sequential frame ID
                    name=function,
                    file=file_path or "",
                    line=line_num,
                    address=ret_addr
                )

                frames.append(frame)
                logger.debug(f"Parsed frame: {frame.name} at "
                             f"{frame.file}:{frame.line}")
            else:
                logger.debug(f"Stack line didn't match pattern: {repr(line)}")

        logger.debug(f"Parsed {len(frames)} frames total")
        return frames

    @classmethod
    def parse_variables(cls, output: str,
                        kind_filter: Optional[str] = None
                        ) -> List[CdbVariable]:
        """Parse variable list output"""
        variables: List[CdbVariable] = []

        # First collect all structured 'prv' variables
        matches = cls.VARIABLE_PATTERN.findall(output)
        for kind, var_type, name, value in matches:
            # Check if this is a container type
            is_container = False
            container_size = None
            container_type = None
            
            if 'std::vector' in var_type or 'vector' in var_type.lower():
                is_container = True
                container_type = 'vector'
                # Extract size from value like "{ size=5 }"
                size_match = re.search(r'size=(\d+)', value)
                if size_match:
                    container_size = int(size_match.group(1))
            elif re.search(r'\[\d*\]', var_type) or ('*' in var_type and 'ptr' not in name.lower()):
                # Detect C-style arrays by type pattern [n] or pointer types that might be arrays
                is_container = True
                container_type = 'array'
                # Try to extract array size from type like "int [5]" or from value
                array_size_match = re.search(r'\[(\d+)\]', var_type)
                if array_size_match:
                    container_size = int(array_size_match.group(1))
                else:
                    # For pointer types, we might need to infer size from context
                    # This is harder to determine statically, may need runtime inspection
                    container_size = None
            
            variables.append(CdbVariable(
                name=name,
                value=clean_integer_value(value.strip()),
                type=var_type.strip() or "unknown",
                is_container=is_container,
                container_size=container_size,
                container_type=container_type
            ))

        # Collect simple assignment lines not already captured
        seen_names = {v.name for v in variables}
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith('prv '):
                continue
            if (line.endswith('>')
                    and line.count('>') == 1
                    and line.count('<') >= 1):
                # Likely an incomplete template type line, skip until merged
                continue
            m = cls.SIMPLE_ASSIGN_PATTERN.match(line)
            if m:
                name, value = m.groups()
                if name not in seen_names:
                    # Infer type heuristically for std::string
                    # and vector summaries
                    inferred_type = "unknown"
                    is_container = False
                    container_size = None
                    container_type = None
                    
                    if 'basic_string' in value or 'std::string' in value:
                        inferred_type = 'std::string'
                    elif 'size=' in value and '{' in value and '}' in value:
                        inferred_type = 'container'
                        is_container = True
                        # Extract size from value like "{ size=5 }"
                        size_match = re.search(r'size=(\d+)', value)
                        if size_match:
                            container_size = int(size_match.group(1))
                        # Determine container type from variable name or context
                        if 'vector' in name.lower() or 'std::vector' in value:
                            container_type = 'vector'
                        elif 'array' in name.lower():
                            container_type = 'array'
                        else:
                            container_type = 'container'
                    elif (re.search(r'0x[0-9a-fA-F]+', value) and 
                          ('arr' in name.lower() or 'array' in name.lower() or 
                           name.endswith('s') and not name.lower().endswith('ss'))):
                        # Detect potential arrays by name patterns and pointer values
                        # This is a heuristic for variables like "numbersArr" or "numbers" that might be arrays
                        inferred_type = 'array'
                        is_container = True
                        container_type = 'array'
                        # Size is unknown for simple assignments, will need runtime inspection
                        container_size = None
                    
                    variables.append(
                        CdbVariable(name=name, value=clean_integer_value(value.strip()),
                                    type=inferred_type, is_container=is_container,
                                    container_size=container_size,
                                    container_type=container_type))

        # Apply kind filter after collection if provided
        # (retain only filtered names present in structured matches)
        if kind_filter:
            filtered_names = {name for kind, var_type, name, value in matches
                              if kind == kind_filter}
            variables = [v for v in variables if v.name in filtered_names]

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
            logger.info(f"Starting CDB process for program: {program}")

            # Validate program exists
            if not os.path.exists(program):
                logger.error(f"Program file does not exist: {program}")
                return False

            # Check if cdb.exe is available
            cdb_path = shutil.which('cdb.exe')
            if not cdb_path:
                logger.error("cdb.exe not found in PATH. "
                             "Please ensure Windows Debugging Tools "
                             "are installed.")
                return False

            logger.info(f"Found cdb.exe at: {cdb_path}")

            # Add -y <exe_folder> to symbol search path
            exe_folder = os.path.dirname(os.path.abspath(program))
            # make sure the folder is ending with a double backslash
            exe_folder += '\\'
            cdb_command = ['cdb.exe', '-G', '-y', exe_folder]
            cdb_command.append(program)
            if args:
                cdb_command.extend(args)

            logger.info(f"CDB command: {' '.join(cdb_command)}")
            logger.info(f"Working directory: {cwd}")

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

            # Give the process a moment to start
            time.sleep(0.1)

            # Check if process is still running
            if self.process.poll() is not None:
                logger.error("CDB process exited immediately "
                             f"with return code: {self.process.poll()}")
                return False

            # Send initial setup commands
            logger.info("Sending initial setup commands...")
            self.send_command(".echo Setting up debugger...")

            # force (re)load symbols, as Cdb does not automatically do this
            self.send_command(".reload /f")
            # Enable source line support
            self.send_command('.lines -e')
            # enable source line stepping (otherwise, stepping command
            # in cdb will do assembly instruction stepping)
            self.send_command('l+t')

            # Cdb stops at entry, but this entry means nothing to the user
            # instead, break at main.
            # TODO: only break at main if specified by the user!
            self.send_command("bp main")
            self.send_command("g")

            # We're now stopped at the initial loader breakpoint
            # Get the initial stack trace to see where we are
            logger.info("Getting initial stack trace to verify position...")
            stack_output = self.send_command("k")
            logger.info(f"Initial stack: {stack_output}")

            vars = self.send_command("dv /i /t")
            logger.info(f"{vars}")

            logger.info(f"Successfully started CDB process for program: "
                        f"{program}")
            logger.info("Debugger is stopped at initial breakpoint, "
                        "ready for DAP setup")
            return True

        except Exception as e:
            logger.error(f"Failed to start CDB process: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
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
                # (any thread ID format: 0:000>, 1:000>, etc.)
                prompt_match = re.search(r'(\d+:\d+>)\s*$', buffer)
                if prompt_match:
                    prompt = prompt_match.group(1)
                    if self.current_command:
                        self.command_response = \
                            buffer.rstrip().removesuffix(prompt)
                        self.command_event.set()
                        buffer = ""
                    else:
                        # Unsolicited output (e.g., breakpoint hit)
                        logger.debug("Unsolicited output with prompt: "
                                     f"{repr(buffer[:100])}")
                        # Log CDB interaction - unsolicited output
                        cdb_logger.info(f"UNSOLICITED: {buffer.strip()}")
                        self.output_queue.put(buffer)
                        buffer = ""

                # Only process other events
                # if we're not waiting for a command response
                elif not self.current_command:
                    # Check for explicit breakpoint messages
                    if (('Breakpoint' in buffer
                            or 'breakpoint' in buffer.lower())
                            and len(buffer) > 10):
                        logger.info("Detected explicit breakpoint message: "
                                    f"{repr(buffer[:200])}")
                        # Log CDB interaction - breakpoint message
                        cdb_logger.info(f"BREAKPOINT: {buffer.strip()}")
                        self.output_queue.put(buffer)
                        buffer = ""

                    # Check for other break events
                    elif (('Break instruction exception' in buffer
                            or 'stopped at' in buffer.lower())
                          and len(buffer) > 50):
                        logger.info("Detected break event: "
                                    f"{repr(buffer[:100])}")
                        # Log CDB interaction - break event
                        cdb_logger.info(f"BREAK_EVENT: {buffer.strip()}")
                        self.output_queue.put(buffer)
                        buffer = ""

                    # Check if buffer is getting too long without a prompt
                    elif len(buffer) > 2000:
                        logger.debug("Buffer getting long, flushing: "
                                     f"{repr(buffer[:100])}")
                        self.output_queue.put(buffer)
                        buffer = ""

                # If we're waiting for a command response,
                # only check for buffer overflow
                elif self.current_command and len(buffer) > 5000:
                    logger.warning("Command response buffer getting "
                                   f"very long: {len(buffer)} chars")
                    # Don't clear the buffer, just log the warning

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
            # Log CDB interaction - input command
            cdb_logger.info(f"INPUT: {command}")
            self.process.stdin.write(command + '\n')
            self.process.stdin.flush()

            # Wait for response
            if self.command_event.wait(timeout):
                response = self.command_response
                self.current_command = None
                logger.debug(f"Command '{command}' response: "
                             f"{repr(response[:200])}")
                # Log CDB interaction - output response
                cdb_logger.info(f"OUTPUT: {response.strip()}")
                return response
            else:
                logger.warning(f"Command timeout: {command}")
                self.current_command = None

                # For continue commands,
                # timeout might mean the program is running
                if command.strip() == 'g':
                    logger.info("Continue command timed out - "
                                "program may be running or hit breakpoint")
                    # Try to break and see where we are
                    time.sleep(0.1)
                    self.process.stdin.write('\x03\n')  # Send Ctrl+C to break
                    self.process.stdin.flush()

                return ""

        except Exception as e:
            logger.error(f"Error sending command: {e}")
            return ""

    def get_unsolicited_output(self) -> Optional[str]:
        """Get any unsolicited output from CDB,
           concatenating all available chunks."""
        chunks = []
        try:
            while True:
                chunk = self.output_queue.get_nowait()
                if chunk:
                    chunks.append(chunk)
        except queue.Empty:
            pass
        if chunks:
            return ''.join(chunks)
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
        self.recent_exception = None  # Track recent exceptions

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

        logger.info(f"Attempting to set breakpoint {bp_id} at "
                    f"{file_path}:{line}")

        # Try different CDB breakpoint syntax variations
        commands_to_try = [
            f'bp `{file_path}:{line}`',  # Standard syntax with backticks
            # f'bp "{file_path}:{line}"',  # With quotes
            # f'bm {file_path}:{line}',    # Different breakpoint command
        ]

        verified = False
        response = ""

        for i, command in enumerate(commands_to_try):
            logger.info(f"Trying breakpoint command #{i+1}: {command}")
            response = self.communicator.send_command(command)
            logger.info(f"Breakpoint response: {repr(response)}")

            # Check for successful breakpoint setting - be more strict
            if response.strip():
                if ("error" in response.lower()
                        or "unable" in response.lower()
                        or "failed" in response.lower()
                        or "invalid" in response.lower()):
                    logger.warning(f"Breakpoint command failed: {response}")
                    continue
                elif ("breakpoint" in response.lower() or
                      response.strip().startswith("bp") or
                      "deferred" in response.lower()):
                    # Explicit success indicators
                    logger.info("Breakpoint command succeeded")
                    verified = True
                    break
                else:
                    # Unknown response - might be success or failure
                    logger.warning("Ambiguous breakpoint response: "
                                   f"{response}")
                    # Don't assume success, try next command
                    continue
            else:
                # Empty response might mean success in CDB
                logger.info("Empty response - might indicate success")
                verified = True
                break

        # Always verify by listing breakpoints, regardless of initial response
        logger.info("Verifying breakpoint by listing all breakpoints...")
        bl_response = self.communicator.send_command("bl")
        logger.info(f"Breakpoint list response: {repr(bl_response)}")

        # Parse the breakpoint list to see if our breakpoint is actually there
        bp_found = False
        if bl_response:
            lines = bl_response.split('\n')
            for bp_line in lines:
                # Look for our file and line in the breakpoint list
                # CDB format might be like:
                # "0 e Disable BreakAddress  Module!Function+Offset"
                if (str(line) in bp_line and
                        (file_path.split('\\')[-1] in bp_line
                         or file_path.split('/')[-1] in bp_line)):
                    logger.info(f"Found breakpoint in list: {bp_line.strip()}")
                    bp_found = True
                    break
                # Also check if the line number appears in the breakpoint info
                elif f":{line}" in bp_line or f"@{line}" in bp_line:
                    logger.info("Found line reference in breakpoint: "
                                f"{bp_line.strip()}")
                    bp_found = True
                    break

        if bp_found:
            logger.info("Breakpoint successfully verified in breakpoint list")
            verified = True
        else:
            logger.error("Breakpoint NOT found in breakpoint list "
                         "- setting failed!")
            verified = False

            # Try one more approach,
            # set breakpoint using function name if available
            logger.info("Attempting to set breakpoint "
                        "using function approach...")
            func_command = f"bp main+{line-1}"  # Rough estimate
            func_response = self.communicator.send_command(func_command)
            logger.info(f"Function breakpoint response: {repr(func_response)}")

            # Check again
            bl_response2 = self.communicator.send_command("bl")
            logger.info(f"Second breakpoint list: {repr(bl_response2)}")
            if bl_response2 and "main" in bl_response2:
                verified = True
                logger.info("Function-based breakpoint appears to have worked")

        self.breakpoints[bp_id] = {
            'file': file_path,
            'line': line,
            'verified': verified,
            'cdb_id': bp_id,
            'response': response
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

    def list_breakpoints(self) -> List[CdbBreakpoint]:
        """List all current breakpoints"""
        try:
            bl_output = self.communicator.send_command('bl')
            logger.debug(f"Breakpoint list output: {bl_output}")
            return self.parser.parse_breakpoints(bl_output)
        except Exception as e:
            logger.error(f"Error listing breakpoints: {e}")
            return []

    def continue_execution(self):
        """Continue program execution"""
        self.is_stopped = False
        self.was_continuing = True  # Flag to help detect breakpoint hits
        self.was_stepping = False
        logger.info("Continuing execution...")

        # Don't use timeout for continue - let it run until breakpoint/event
        logger.info("Sending continue command without timeout")
        try:
            self.communicator.process.stdin.write('g\n')
            self.communicator.process.stdin.flush()
            logger.info("Continue command sent, program should be running")
        except Exception as e:
            logger.error(f"Error sending continue command: {e}")
            self.was_continuing = False

    def get_current_location(self) -> Tuple[Optional[str], int]:
        """Get current source file and line number"""
        try:
            logger.debug("Getting current location...")

            # Get stack frame with source info - this is most reliable
            frame_output = self.communicator.send_command("k 1")
            logger.debug(f"Frame output: {frame_output}")

            import re
            # Format: "VisionSym!main [C:\Users\...\main.cxx @ 281]"
            if frame_output:
                match = re.search(r'\[([^@]+)\s*@\s*(\d+)\]', frame_output)
                if match:
                    # Fix double backslashes
                    file_path = match.group(1).strip().replace('\\\\', '\\')
                    line_num = int(match.group(2))
                    logger.info("Found location via frame output: "
                                f"{file_path}:{line_num}")
                    return file_path, line_num

            logger.warning("Could not determine current location "
                           "from CDB output")
            logger.debug(f"Frame output was: {repr(frame_output)}")
            # Removed ln_output reference (undefined variable)
            return None, 0

        except Exception as e:
            logger.error(f"Error getting current location: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None, 0

    def _step_until_line_changes(self, step_command, operation_name):
        """Helper method to step until we reach a different source line"""
        current_file, current_line = self.get_current_location()
        logger.debug(f"{operation_name} starting "
                     f"from {current_file}:{current_line}")

        max_steps = 50  # Safety limit to prevent infinite loops
        for step_count in range(1, max_steps + 1):
            self.communicator.send_command(step_command)
            new_file, new_line = self.get_current_location()
            logger.debug(f"After step {step_count}: {new_file}:{new_line}")

            # Stop if we've moved to a different line/file
            # or can't get location
            if (new_file != current_file or new_line != current_line
                    or not new_file or new_line <= 0):
                if new_file != current_file or new_line != current_line:
                    logger.debug(f"{operation_name} complete: "
                                 f"moved from {current_file}:{current_line} "
                                 f"to {new_file}:{new_line}")
                else:
                    logger.debug("Could not get new location, "
                                 f"stopping {operation_name}")
                break
        else:
            logger.warning(f"{operation_name} reached maximum steps "
                           f"({max_steps}) without changing line")

    def step_over(self):
        """Step over until we reach a different source line"""
        self.was_stepping = True
        self.communicator.send_command('p')
        # self._step_until_line_changes('pct', 'Step over')

    def step_into(self):
        """Step into until we reach a different source line"""
        self.was_stepping = True
        # stepping into will call an assembly jmp, but not
        # immediately move to the source line inside the function.
        # therefore, step into twice
        self.communicator.send_command('t')
        self.communicator.send_command('t')
        # self._step_until_line_changes('tct', 'Step into')

    def step_out(self):
        """Step out of current function"""
        self.was_stepping = True  # Track that we initiated a step
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

        # Use kn (numbered stack) for parsing,
        # it has the frame numbers that the parser expects
        response = self.communicator.send_command('kn')
        logger.debug(f"Numbered stack trace response: {response}")

        # Parse the stack trace using the numbered output
        frames = self.parser.parse_stack_trace(response)
        logger.debug(f"Parsed {len(frames)} frames from stack trace")

        # The frames should already have source information from the kn command
        # but let's verify and enhance if needed
        for i, frame in enumerate(frames):
            logger.debug(f"Frame {i}: {frame.name} at "
                         f"{frame.file}:{frame.line}")

            # If we don't have source info for this frame, try to get it
            if not frame.file or frame.line == 0:
                try:
                    # Switch to this frame and get source info
                    frame_cmd = f'.frame {i}'
                    self.communicator.send_command(frame_cmd)

                    # Get current location for this frame
                    frame_output = self.communicator.send_command('.frame')
                    logger.debug(f"Frame {i} output: {frame_output}")

                    # Parse for source file and line from frame output
                    import re
                    source_patterns = [
                        # [filename @ line]
                        r'\[([^@]+)\s*@\s*(\d+)\]',
                        # (filename:line)
                        r'\(([^)]+):(\d+)\)',
                        # path\file.ext : line
                        r'([a-zA-Z]:[^:\s]+\.[a-zA-Z]+)\s*:\s*(\d+)',
                    ]

                    for pattern in source_patterns:
                        match = re.search(pattern, frame_output)
                        if match:
                            frame.file = match.group(1).strip()
                            frame.line = int(match.group(2))
                            logger.debug(f"Enhanced frame {i}: "
                                         f"{frame.file}:{frame.line}")
                            break

                except Exception as e:
                    logger.debug("Could not enhance source info for frame "
                                 f"{i}: {e}")

        # Reset to frame 0
        self.communicator.send_command('.frame 0')

        return frames

    def get_local_variables(self, frame_id: int = 0) -> List[CdbVariable]:
        """Get local variables for specific frame"""
        # Switch to requested frame
        if frame_id > 0:
            self.communicator.send_command(f'.frame {frame_id}')

        # Send dv and then poll for additional unsolicited chunks
        # to build complete output
        raw = self.communicator.send_command('dv /i /t')
        logger.debug(f"Raw dv /i /t response: {repr(raw)}")
        combined = raw
        end_prompt_patterns = ('0:000>', '>')
        poll_start = time.time()
        # Collect for up to 0.4s or until we see a trailing prompt
        # AND some variable content
        while time.time() - poll_start < 0.4:
            chunk = self.communicator.get_unsolicited_output()
            if chunk:
                logger.debug(f"Unsolicited dv chunk: {repr(chunk)}")
                combined += chunk
                # Heuristic: break if we have both a prompt terminator
                # and at least one 'prv ' token
                if (any(combined.rstrip().endswith(p)
                        for p in end_prompt_patterns)
                        and ('prv ' in combined or '=' in combined)):
                    break
            else:
                time.sleep(0.02)

        # Restore frame 0
        if frame_id > 0:
            self.communicator.send_command('.frame 0')

        logger.debug(f"Combined dv output: {repr(combined)}")
        locals_list = self.parser.parse_variables(combined, "local")
        # If filter resulted in empty but combined output
        # has simple assignments, parse without filter
        if not locals_list and '=' in combined:
            logger.debug("Retrying parse without kind_filter "
                         "due to empty local list")
            locals_list = self.parser.parse_variables(combined, None)
        # Deduplicate by name
        seen = {}
        for var in locals_list:
            if var.name not in seen:
                seen[var.name] = var
        result = list(seen.values())
        logger.info(f"Parsed {len(result)} local variables: "
                    f"{[v.name for v in result]}")
        return result

    def get_arguments(self, frame_id: int = 0) -> List[CdbVariable]:
        """Get function arguments for specific frame"""
        if frame_id > 0:
            self.communicator.send_command(f'.frame {frame_id}')
        raw = self.communicator.send_command('dv /i /t')
        combined = raw
        poll_start = time.time()
        while time.time() - poll_start < 0.4:
            chunk = self.communicator.get_unsolicited_output()
            if chunk:
                logger.debug(f"Unsolicited param chunk: {repr(chunk)}")
                combined += chunk
                if (combined.rstrip().endswith('>')
                        and ('prv param' in combined
                             or 'argc' in combined or 'argv' in combined)):
                    break
            else:
                time.sleep(0.02)
        if frame_id > 0:
            self.communicator.send_command('.frame 0')
        params = self.parser.parse_variables(combined, 'param')
        if not params and ('argc' in combined or 'argv' in combined):
            all_vars = self.parser.parse_variables(combined, None)
            params = [v for v in all_vars if v.name in ('argc', 'argv')]
        unique = {}
        for v in params:
            if v.name not in unique:
                unique[v.name] = v
        result = list(unique.values())
        logger.info(f"Parsed {len(result)} param variables: "
                    f"{[v.name for v in result]}")
        return result

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

    def get_container_elements(self, container_name: str, container_type: str, size: int) -> List[CdbVariable]:
        """Get elements from a container (vector, array, etc.)"""
        elements = []
        
        if container_type == 'vector':
            # Use dx command to get structured vector information
            try:
                dx_response = self.communicator.send_command(f'dx {container_name}')
                logger.debug(f"dx response: {repr(dx_response)}")
                
                # Parse dx output to extract vector elements
                # Format: [0]              : 1 [Type: int]
                element_pattern = re.compile(r'^\s*\[(\d+)\]\s*:\s*(.+?)\s*\[Type:\s*(.+?)\]')
                
                for line in dx_response.split('\n'):
                    match = element_pattern.match(line)
                    if match:
                        index, value, element_type = match.groups()
                        
                        # Clean up the value (remove extra spaces and 0n prefix)
                        clean_value = clean_integer_value(value.strip())
                        clean_type = element_type.strip()
                        
                        elements.append(CdbVariable(
                            name=f'[{index}]',
                            value=clean_value,
                            type=clean_type
                        ))
                        
                        logger.debug(f"Parsed element [{index}]: {clean_value} ({clean_type})")
                
                logger.info(f"Successfully parsed {len(elements)} elements from dx output")
                    
            except Exception as e:
                logger.error(f"Error accessing vector elements for {container_name}: {e}")
        
        elif container_type == 'array':
            # Handle C-style arrays and pointer arrays
            try:
                # Try dx command first for structured output (works for some arrays)
                dx_response = self.communicator.send_command(f'dx {container_name}')
                logger.debug(f"dx response for array: {repr(dx_response)}")
                
                # Parse dx output to extract array elements
                # Format: [0]              : 2 [Type: int]
                element_pattern = re.compile(r'^\s*\[(\d+)\]\s*:\s*(.+?)\s*\[Type:\s*(.+?)\]')
                
                for line in dx_response.split('\n'):
                    match = element_pattern.match(line)
                    if match:
                        index, value, element_type = match.groups()
                        
                        # Clean up the value (remove extra spaces and 0n prefix)
                        clean_value = clean_integer_value(value.strip())
                        clean_type = element_type.strip()
                        
                        elements.append(CdbVariable(
                            name=f'[{index}]',
                            value=clean_value,
                            type=clean_type
                        ))
                        
                        logger.debug(f"Parsed array element [{index}]: {clean_value} ({clean_type})")
                
                # If dx didn't work or returned no elements, try alternative methods
                if not elements:
                    logger.debug("dx command didn't return array elements, trying dq/dd/db commands")
                    
                    # Get the array's base address
                    addr_response = self.communicator.send_command(f'? {container_name}')
                    logger.debug(f"Address response: {repr(addr_response)}")
                    
                    # Extract address from response
                    # Format might be: "Evaluate expression: 0x00000000004017a0 = 0x00000000`004017a0"
                    addr_match = re.search(r'0x[0-9a-fA-F]+`[0-9a-fA-F]+|0x[0-9a-fA-F]+', addr_response)
                    if addr_match:
                        base_address = addr_match.group(0)
                        logger.debug(f"Found array base address: {base_address}")
                        
                        # Determine element size and command based on likely type
                        # For now, assume int (4 bytes) - could be enhanced to detect type
                        element_size = 4  # bytes for int
                        memory_cmd = 'dd'  # dword (4 bytes) command
                        
                        # Read array elements using memory commands
                        memory_response = self.communicator.send_command(f'{memory_cmd} {base_address} L{size}')
                        logger.debug(f"Memory response: {repr(memory_response)}")
                        
                        # Parse memory dump output
                        # Format: "00000000`004017a0  00000002 00000004 00000008 00000010"
                        memory_lines = memory_response.split('\n')
                        element_index = 0
                        
                        for line in memory_lines:
                            # Skip empty lines and non-memory lines
                            if not line.strip() or ':' not in line:
                                continue
                                
                            # Split line into address and values
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                                
                            # Skip the address part (first element)
                            values = parts[1:]
                            
                            for value_hex in values:
                                if element_index >= size:
                                    break
                                    
                                try:
                                    # Convert hex to decimal
                                    decimal_value = int(value_hex, 16)
                                    
                                    elements.append(CdbVariable(
                                        name=f'[{element_index}]',
                                        value=str(decimal_value),
                                        type='int'  # Could be enhanced to detect actual type
                                    ))
                                    
                                    logger.debug(f"Parsed array element [{element_index}]: {decimal_value}")
                                    element_index += 1
                                    
                                except ValueError as ve:
                                    logger.debug(f"Could not parse hex value '{value_hex}': {ve}")
                                    continue
                            
                            if element_index >= size:
                                break
                    
                    else:
                        logger.warning(f"Could not determine address for array {container_name}")
                        
                        # Last resort: try to access individual elements directly
                        logger.debug("Trying direct element access as fallback")
                        for i in range(min(size, 20)):  # Limit to prevent excessive commands
                            try:
                                element_response = self.communicator.send_command(f'?? {container_name}[{i}]')
                                logger.debug(f"Element {i} response: {repr(element_response)}")
                                
                                # Parse element response
                                # Format might be: "int 0x2 (2)" or similar
                                if element_response.strip():
                                    # Try to extract the value
                                    value_match = re.search(r'\((\d+)\)|\s(\d+)$|:\s*(\d+)', element_response)
                                    if value_match:
                                        value = value_match.group(1) or value_match.group(2) or value_match.group(3)
                                        
                                        # Try to extract the type
                                        type_match = re.search(r'^(\w+)', element_response.strip())
                                        element_type = type_match.group(1) if type_match else 'unknown'
                                        
                                        elements.append(CdbVariable(
                                            name=f'[{i}]',
                                            value=clean_integer_value(value),
                                            type=element_type
                                        ))
                                        
                                        logger.debug(f"Direct access element [{i}]: {value} ({element_type})")
                                    
                            except Exception as elem_e:
                                logger.debug(f"Could not access element {i} directly: {elem_e}")
                                break  # Stop trying if we can't access elements
                
                logger.info(f"Successfully parsed {len(elements)} array elements")
                    
            except Exception as e:
                logger.error(f"Error accessing array elements for {container_name}: {e}")
        
        return elements

    def get_memory(self, address: str, size: int = 16) -> str:
        """Get memory contents"""
        response = self.communicator.send_command(f'db {address} L{size}')
        return response

    def check_for_events(self) -> Optional[Dict[str, Any]]:
        """Check for debugging events (breakpoints, exceptions, etc.)"""

        output = self.communicator.get_unsolicited_output()
        if not output:
            return None

        logger.debug(f"Checking unsolicited output: {repr(output[:200])}")

        # Check for exceptions first and track them
        if ('first chance' in output.lower()
                or 'second chance' in output.lower()
                or 'illegal instruction' in output.lower()
                or 'access violation' in output.lower()):
            logger.info("Detected exception - will be ignored: "
                        f"{output[:100]}...")
            # Don't treat exceptions as breakpoint hits
            return None

        # Parse output for events
        if ('Breakpoint' in output or 'breakpoint' in output.lower() or
                'stopped at' in output.lower()):
            logger.info("Detected possible breakpoint message in output")

            # Before declaring this a breakpoint,
            # let's verify we're actually at a real breakpoint
            # by checking the current location against our set breakpoints
            try:
                file_path, line_num = self.get_current_location()
                if file_path and line_num > 0:
                    # Check if this location matches any of our set breakpoints
                    breakpoint_hit = False
                    for bp_id, bp in self.breakpoints.items():
                        if (bp.get('file') and bp.get('line') and
                            file_path.lower().endswith(bp['file'].lower()) and
                                bp['line'] == line_num):
                            logger.info("Confirmed breakpoint hit at "
                                        f"{file_path}:{line_num} "
                                        "(BP ID: {bp_id})")
                            breakpoint_hit = True
                            break

                    if breakpoint_hit:
                        self.is_stopped = True
                        return {
                            'type': 'stopped',
                            'reason': 'breakpoint',
                            'threadId': self.current_thread_id or 1
                        }
                    else:
                        logger.info("Breakpoint message at "
                                    f"{file_path}:{line_num} - not a "
                                    "user breakpoint, ignoring")
                        return None
                else:
                    logger.warning("Could not get current location for "
                                   "breakpoint verification")
                    return None
            except Exception as e:
                logger.error(f"Error verifying breakpoint location: {e}")
                # Don't fall back to old behavior - if we can't verify,
                # don't treat it as a breakpoint
                return None
        elif ('Break instruction exception' in output or
              'Break exception' in output or
              'Int 3' in output):
            self.is_stopped = True
            logger.info("Detected break instruction")
            return {
                'type': 'stopped',
                'reason': 'step',
                'threadId': self.current_thread_id or 1
            }
        elif 'Access violation' in output or 'Exception' in output:
            self.is_stopped = True
            logger.info("Detected exception")
            return {
                'type': 'stopped',
                'reason': 'exception',
                'threadId': self.current_thread_id or 1
            }
        elif ('process exited' in output.lower()
                or 'exited with code' in output.lower()):
            logger.info("Process exited")
            return {
                'type': 'exited',
                'exitCode': 0
            }
        else:

            # Sometimes CDB doesn't send explicit breakpoint messages
            # If we see a prompt but were in continue state,
            # check if we might have hit a breakpoint
            if ('>' in output and len(output) < 50 and
                    hasattr(self, 'was_continuing') and self.was_continuing):
                logger.info("Detected possible breakpoint hit "
                            "(short prompt after continue)")

                # Before declaring this a breakpoint,
                # let's verify we're actually at a real breakpoint
                # by checking the current location against our set breakpoints
                try:
                    file_path, line_num = self.get_current_location()
                    if file_path and line_num > 0:
                        # Check if this location matches any
                        # of our set breakpoints
                        breakpoint_hit = False
                        for bp_id, bp in self.breakpoints.items():
                            if (bp.get('file')
                                    and bp.get('line')
                                    and file_path.lower().endswith(
                                        bp['file'].lower())
                                    and bp['line'] == line_num):
                                logger.info("Confirmed breakpoint hit at "
                                            f"{file_path}:{line_num} "
                                            "(BP ID: {bp_id})")
                                breakpoint_hit = True
                                break

                        if breakpoint_hit:
                            self.was_continuing = False
                            self.is_stopped = True
                            return {
                                'type': 'stopped',
                                'reason': 'breakpoint',
                                'threadId': self.current_thread_id or 1
                            }
                        else:
                            logger.info("Short prompt at "
                                        f"{file_path}:{line_num} - not a "
                                        "user breakpoint, ignoring")
                            self.was_continuing = False
                            return None
                except Exception as e:
                    logger.error(f"Error verifying breakpoint location: {e}")
                    # Fall back to old behavior if verification fails
                    self.was_continuing = False
                    self.is_stopped = True
                    return {
                        'type': 'stopped',
                        'reason': 'breakpoint',
                        'threadId': self.current_thread_id or 1
                    }

            logger.debug("No event detected in output")

        # Check if we were stepping and now have a prompt with instruction info
        if (hasattr(self, 'was_stepping') and self.was_stepping
                and ('0:000>' in output or '>' in output[-10:])
                and ('!main+' in output
                     or re.search(r'[0-9a-f]{8}`[0-9a-f]{8}', output))):
            logger.info("Detected step completion - stopped after stepping")
            self.was_stepping = False
            self.is_stopped = True
            return {
                'type': 'stopped',
                'reason': 'step',
                'threadId': self.current_thread_id or 1
            }

        return None

    def terminate(self):
        """Terminate debugging session"""
        self.communicator.terminate()
