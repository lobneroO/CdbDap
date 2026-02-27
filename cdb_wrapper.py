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
        # Only warnings/errors to stderr â€” DEBUG writes to stderr are slow
        # and cause noticeable pauses during high-frequency CDB interactions.
        logging.StreamHandler(sys.stderr)
    ]
)
logging.getLogger().handlers[1].setLevel(logging.WARNING)
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
    decimal format. Since we always want decimal view,
    we remove the "0n" prefix.

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
    BREAKPOINT_PATTERN = re.compile(
        r'^\s*(\d+):\s+([0-9a-f`]+)\s+.*?(@#\d+)?\s*(.*)$', re.MULTILINE)
    STACK_FRAME_PATTERN = re.compile(
        r'^(\d+)\s+([0-9a-f`]+)\s+([0-9a-f`]+)\s+(.+?)(?:\s+\[(.+?)\s+@\s+(\d+)\])?$',  # noqa: E501
        re.MULTILINE)
    # Extended variable pattern: allow angle brackets, commas,
    # colons for C++ template types
    # Allow optional leading whitespace to handle indented output
    VARIABLE_PATTERN = re.compile(
        r'^\s*prv\s+(\w+)\s+([\w\s\*\[\]<>:,]+)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$',  # noqa : E501
        re.MULTILINE
    )
    # Secondary simple assignment pattern (lines without 'prv' prefix)
    SIMPLE_ASSIGN_PATTERN = re.compile(
        r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$'
    )
    THREAD_PATTERN = re.compile(
        # CDB marks the currently-active thread with a '.' prefix:
        #   .  0  Id: 1234.5678 Suspend: 0 Teb: ... Unfrozen
        #      1  Id: 1234.5679 Suspend: 1 Teb: ... Unfrozen
        # The \.? makes the dot optional so both forms are matched.
        r'^\s*\.?\s*(\d+)\s+Id:\s+([0-9a-f.]+)\s+Suspend:\s+(\d+)\s+Teb:\s+([0-9a-f`]+)\s+(.*)$',  # noqa: E501
        re.MULTILINE)

    @classmethod
    def _is_struct_or_class_type(cls, var_type: str, value: str) -> bool:
        """
        Determine if a variable is a struct or class type.
        
        Args:
            var_type: The type string from CDB (e.g., "Point", "struct Point", "class Rectangle")
            value: The value string from CDB (e.g., "{x=10 y=20}")
            
        Returns:
            True if this appears to be a struct or class type, False otherwise
        """
        var_type = var_type.strip()
        value = value.strip()
        
        logger.debug(f"_is_struct_or_class_type: type='{var_type}', value='{value}'")
        
        # Check for explicit struct/class keywords
        if var_type.startswith('struct ') or var_type.startswith('class '):
            logger.debug("Found explicit struct/class keyword")
            return True
        
        # Check for aggregate initializer patterns in value (indicates compound type)
        # Format: {member1=value1 member2=value2 ...}
        if (value.startswith('{') and value.endswith('}') and 
            '=' in value and len(value) > 2):
            logger.debug("Found aggregate initializer pattern")
            return True
        
        # Check for custom type names (not primitive types)
        # Primitive types: int, char, float, double, bool, void, etc.
        primitive_types = {
            'int', 'char', 'float', 'double', 'bool', 'void', 'long', 'short',
            'unsigned', 'signed', 'size_t', 'wchar_t', 'int8_t', 'int16_t', 
            'int32_t', 'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t'
        }
        
        # Remove pointer/reference markers and array brackets for type check
        clean_type = var_type.replace('*', '').replace('&', '').replace('const ', '').strip()
        clean_type = re.sub(r'\s*\[\d*\]\s*', '', clean_type)  # Remove array brackets
        
        logger.debug(f"Clean type: '{clean_type}'")
        
        # Check for value patterns that indicate struct/class types
        # When a struct/class doesn't have explicit keyword, the value often shows (TypeName)
        if value and value.startswith('(') and value.endswith(')'):
            # Extract type name from parentheses
            paren_type = value[1:-1].strip()
            if paren_type == clean_type:
                logger.debug(f"Value pattern ({paren_type}) matches type, identified as struct/class")
                return True
        
        # If it's not a primitive type and not a standard library container, 
        # it's likely a custom struct/class
        if (clean_type not in primitive_types and 
            not clean_type.startswith('std::') and
            not clean_type.startswith('basic_') and
            # Exclude pointers to primitives
            not any(prim in clean_type.lower() for prim in primitive_types)):
            logger.debug(f"Type '{clean_type}' identified as custom struct/class")
            return True
        
        logger.debug(f"Type '{clean_type}' not identified as struct/class")    
        return False

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
            elif (re.search(r'\[\d*\]', var_type)
                  or ('*' in var_type and 'ptr' not in name.lower())):
                # Detect C-style arrays by type pattern [n]
                # or pointer types that might be arrays
                is_container = True
                container_type = 'array'
                # Try to extract array size from type like "int [5]"
                # or from value
                array_size_match = re.search(r'\[(\d+)\]', var_type)
                if array_size_match:
                    container_size = int(array_size_match.group(1))
                else:
                    # For pointer types, we might need
                    # to infer size from context
                    # This is harder to determine statically,
                    # may need runtime inspection
                    container_size = None
            elif cls._is_struct_or_class_type(var_type, value):
                # Detect custom struct/class types
                is_container = True
                container_type = 'struct' if 'struct' in var_type.lower() else 'class'
                container_size = None  # Structs/classes don't have a "size" in the traditional sense

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
                        # Determine container type
                        # from variable name or context
                        if 'vector' in name.lower() or 'std::vector' in value:
                            container_type = 'vector'
                        elif 'array' in name.lower():
                            container_type = 'array'
                        else:
                            container_type = 'container'
                    elif (re.search(r'0x[0-9a-fA-F]+', value) and
                          ('arr' in name.lower()
                            or 'array' in name.lower()
                            or name.endswith('s')
                            and not name.lower().endswith('ss'))):
                        # Detect potential arrays by name patterns
                        # and pointer values
                        # This is a heuristic for variables like "numbersArr"
                        # or "numbers" that might be arrays
                        inferred_type = 'array'
                        is_container = True
                        container_type = 'array'
                        # Size is unknown for simple assignments,
                        # will need runtime inspection
                        container_size = None

                    variables.append(
                        CdbVariable(name=name,
                                    value=clean_integer_value(value.strip()),
                                    type=inferred_type,
                                    is_container=is_container,
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

        # CDB wraps output at ~80 columns, which can split a hex TEB address
        # across two lines, e.g.:
        #   .  0  Id: abac.7904 Suspend: 1 Teb: 00000065`5
        #   9ae7000 Unfrozen
        # Join continuation lines: wherever a hex character is immediately
        # followed by a newline and then more hex characters, merge them.
        output = re.sub(r'([0-9a-fA-F])\n\s*([0-9a-fA-F])', r'\1\2', output)

        matches = cls.THREAD_PATTERN.findall(output)

        for match in matches:
            thread_id, thread_name, suspend_count, teb, state = match
            # CDB appends the thread name in double-quotes when one is set:
            #   Unfrozen "Main Thread"
            # Extract it if present; otherwise leave name empty so the
            # caller can try an alternative method (e.g. dx @$curthread.Name).
            name = ""
            quoted = re.search(r'"([^"]+)"', state)
            if quoted:
                name = quoted.group(1)
            threads.append(CdbThread(
                id=int(thread_id),
                name=name,
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
                universal_newlines=True,
                # CREATE_NEW_PROCESS_GROUP is required so that
                # os.kill(pid, CTRL_BREAK_EVENT) targets only
                # the CDB process group and not our own process.
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
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

            # Prevent CDB from wrapping output lines (default is 80 cols).
            # NOTE: .outwidth is not supported by all CDB versions; if it
            # fails the parse_threads() method handles wrapped lines via
            # a regex pre-processing step.
            self.send_command('.outwidth 200')

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
                    # Log once at the 5000-char threshold, then stay silent
                    if len(buffer) == 5001:
                        logger.debug("Command response buffer large "
                                     f"(>5000 chars) for '{self.current_command}'"
                                     " â€” CDB may be emitting ModLoad output")

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
            except Exception:
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
        # Cache of CDB thread index -> name, populated lazily and cleared
        # whenever execution resumes so new threads get fresh names.
        self._thread_name_cache: Dict[int, str] = {}
        # Per-stop stack cache: CDB thread index -> List[CdbFrame].
        # Populated by prefetch_all_stacks() after each stop so that
        # stackTrace requests for any thread are served instantly without
        # an extra CDB round-trip.  Cleared on every resume.
        self._stack_cache: Dict[int, List['CdbFrame']] = {}

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
        # Clear caches so new/renamed threads are picked up fresh at the
        # next stop, and stale stack frames are never served.
        self._thread_name_cache.clear()
        self._stack_cache.clear()
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
        """Get current source file and line number.

        Uses the full call stack ('k') and returns the first (shallowest)
        frame that has source-file information, skipping CRT / OS frames
        that have no [file @ line] annotation.
        """
        try:
            logger.debug("Getting current location...")

            # Request the full stack so we can walk past CRT-internal
            # frames (e.g. ucrtbased!fputc_nolock) to find user code.
            frame_output = self.communicator.send_command("k")
            logger.debug(f"Frame output: {frame_output}")

            import re
            # Format: "module!function [C:\path\file.ext @ 42]"
            if frame_output:
                for match in re.finditer(
                        r'\[([^@\]]+)\s*@\s*(\d+)\]', frame_output):
                    file_path = match.group(1).strip().replace('\\\\', '\\')
                    line_num = int(match.group(2))
                    logger.info("Found location via frame output: "
                                f"{file_path}:{line_num}")
                    return file_path, line_num

            logger.warning("Could not determine current location "
                           "from CDB output")
            logger.debug(f"Frame output was: {repr(frame_output)}")
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
        self._stack_cache.clear()
        self.communicator.send_command('p')
        # self._step_until_line_changes('pct', 'Step over')

    def step_into(self):
        """Step into until we reach a different source line"""
        self.was_stepping = True
        self._stack_cache.clear()
        # stepping into will call an assembly jmp, but not
        # immediately move to the source line inside the function.
        # therefore, step into twice
        self.communicator.send_command('t')
        self.communicator.send_command('t')
        # self._step_until_line_changes('tct', 'Step into')

    def step_out(self):
        """Step out of current function"""
        self.was_stepping = True  # Track that we initiated a step
        self._stack_cache.clear()
        self.communicator.send_command('gu')

    def pause(self):
        """Pause execution by sending CTRL_BREAK to the CDB process group.

        CDB does not poll stdin while the target is running (it is waiting
        for a Windows debug event), so writing '.break\n' to its stdin pipe
        has no effect.  The only reliable out-of-band interrupt is a real
        OS-level signal via GenerateConsoleCtrlEvent, which Python exposes
        as os.kill(pid, signal.CTRL_BREAK_EVENT).

        CDB must have been started with CREATE_NEW_PROCESS_GROUP so that the
        event is delivered only to the CDB process group and not to our own
        Python process.
        """
        import signal as _signal
        logger.info("Pausing execution via CTRL_BREAK_EVENT...")
        try:
            os.kill(self.communicator.process.pid,
                    _signal.CTRL_BREAK_EVENT)
            logger.info("Sent CTRL_BREAK_EVENT to CDB process group")
        except Exception as e:
            logger.error(f"os.kill CTRL_BREAK_EVENT failed: {e} â€” "
                         "falling back to .break command")
            self.communicator.process.stdin.write('.break\n')
            self.communicator.process.stdin.flush()

        # Use send_command with a generous timeout as the settling mechanism.
        # After CTRL_BREAK_EVENT, CDB emits all pending ModLoad messages
        # before it issues its next prompt.  send_command absorbs all of
        # that output naturally as part of the command response and only
        # returns once the prompt has appeared, so subsequent commands get
        # a clean channel.  Simultaneously this switches context to thread 0
        # (the main/user thread) so stack queries target the right thread.
        logger.info("Waiting for CDB to settle after break (sending ~0s)...")
        self.communicator.send_command('~0s', timeout=15.0)
        self.current_thread_id = 0

        # Clear thread name cache â€” threads may have been created or destroyed
        # while the program was running.
        self._thread_name_cache.clear()

        self._stack_cache.clear()
        self.is_stopped = True
        logger.info("Pause complete, debugger should be at prompt")

    def prefetch_all_stacks(self) -> None:
        """Batch-fetch every thread's stack trace in one CDB round-trip.

        CDB's ``~*kn`` runs ``kn`` for all threads simultaneously and emits
        their stacks in sequence.  Parsing the combined output and storing the
        results in ``_stack_cache`` means that any subsequent
        ``get_stack_trace(N)`` call returns immediately without additional CDB
        commands — critical for DAP clients (e.g. nvim-dap) that do not
        proactively request all thread stacks after a stop event.
        """
        try:
            logger.info("Prefetching all thread stacks via ~*kn...")
            output = self.communicator.send_command('~*kn', timeout=30.0)
            if not output:
                logger.warning("~*kn returned empty output")
                return
            self._stack_cache = self._parse_all_stacks(output)
            logger.info(
                f"Prefetched stacks for {len(self._stack_cache)} threads: "
                + str({tid: len(frames)
                       for tid, frames in self._stack_cache.items()})
            )
        except Exception as e:
            logger.error(f"prefetch_all_stacks failed: {e}")

    def _parse_all_stacks(
            self, output: str) -> Dict[int, List[CdbFrame]]:
        """Parse the combined output of ``~*kn`` into a per-thread dict."""
        # Unwrap continuation lines that CDB wraps at ~80 columns.
        output = re.sub(
            r'([0-9a-fA-F`])\n\s*([0-9a-fA-F])', r'\1\2', output)

        # Locate all thread-header lines so we can split by thread.
        thread_headers = list(
            self.parser.THREAD_PATTERN.finditer(output))
        if not thread_headers:
            logger.warning("_parse_all_stacks: no thread headers found")
            return {}

        cache: Dict[int, List[CdbFrame]] = {}
        for i, m in enumerate(thread_headers):
            thread_id = int(m.group(1))
            # Section runs from end of this header to start of the next.
            start = m.end()
            end = (thread_headers[i + 1].start()
                   if i + 1 < len(thread_headers) else len(output))
            section = output[start:end]
            frames = self.parser.parse_stack_trace(section)
            cache[thread_id] = frames
            logger.debug(
                f"  thread {thread_id}: {len(frames)} frames cached")
        return cache

    def get_stack_trace(self, thread_id: int = None) -> List[CdbFrame]:
        """Get the stack trace for *thread_id*.

        Returns frames from ``_stack_cache`` if prefetch_all_stacks() has
        already been called for this stop (the common case).  Falls back to
        a live ``~Nkn`` query when the cache is empty (e.g. before the first
        prefetch, or for a thread that appeared after the prefetch ran).
        """
        # Determine which thread to query.
        if thread_id is None:
            thread_id = self.current_thread_id

        # Serve from the prefetch cache when available.
        if thread_id in self._stack_cache:
            frames = self._stack_cache[thread_id]
            logger.debug(
                f"get_stack_trace: serving {len(frames)} cached frames "
                f"for thread {thread_id}")
            return frames

        # Fall back to a live query.
        cmd = f'~{thread_id}kn'
        response = self.communicator.send_command(cmd)
        logger.debug(f"Stack trace for thread {thread_id}: {response}")

        frames = self.parser.parse_stack_trace(response)
        logger.debug(f"Parsed {len(frames)} frames for thread {thread_id}")
        for i, frame in enumerate(frames):
            logger.debug(f"  Frame {i}: {frame.name} at "
                         f"{frame.file}:{frame.line}")

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

    # Frame name patterns that identify threads owned by CDB / the Windows
    # debugging subsystem rather than by the debuggee's own code.
    _CDB_FRAME_PATTERNS = re.compile(
        r'DbgUiRemoteBreakin'       # CDB's remote-breakin thread
        r'|DbgUiWaitStateChange'    # Debug event wait loop
        r'|RtlDebugSystemBreakPoint'  # ntdll system breakpoint helper
        r'|DbgBreakPoint',          # Generic debug breakpoint shim
        re.IGNORECASE
    )

    def _is_cdb_thread(self, thread_id: int) -> bool:
        """Return True if *thread_id*'s stack consists only of Windows
        debugging-subsystem frames, indicating that this thread was created
        by CDB (or the OS on CDB's behalf) and is not part of the debuggee's
        own logic.

        Detection is based on the cached ``_stack_cache`` populated by
        ``prefetch_all_stacks``; if no cache entry exists the method returns
        False (conservative: don't mislabel threads we can't inspect).
        """
        frames = self._stack_cache.get(thread_id)
        if not frames:
            return False
        return any(
            self._CDB_FRAME_PATTERNS.search(f.name)
            for f in frames
            if f.name
        )

    def get_threads(self) -> List[CdbThread]:
        """Get thread list with names where available."""
        response = self.communicator.send_command('~')
        threads = self.parser.parse_threads(response)

        # CDB thread 0 is always the main thread (ran main()).
        # For other threads, try dx @$curthread.Name once per thread per stop;
        # results are cached in _thread_name_cache to avoid slow repeated
        # round-trips on every threads request.
        saved_thread = self.current_thread_id
        current_cdb_thread = saved_thread

        for thread in threads:
            if thread.id == 0:
                thread.name = "Main Thread"
                continue

            # Use cached name if available
            if thread.id in self._thread_name_cache:
                thread.name = self._thread_name_cache[thread.id]
                continue

            # Check whether this is a CDB-internal thread (e.g. the remote
            # breakin thread injected by the Windows debugging subsystem).
            # We detect this by looking for well-known CDB frame names in the
            # prefetched stack cache — no extra CDB round-trip required.
            if self._is_cdb_thread(thread.id):
                thread.name = f"[CDB] Thread {thread.id + 1}"
                self._thread_name_cache[thread.id] = thread.name
                continue

            if not thread.name:
                try:
                    if current_cdb_thread != thread.id:
                        self.communicator.send_command(f'~{thread.id}s')
                        current_cdb_thread = thread.id
                    name_out = self.communicator.send_command(
                        'dx @$curthread.Name')
                    # Output when name is set:
                    #   @$curthread.Name : "WorkerThread" [Type: char *]
                    # Output when no name is set (just the property, no value):
                    #   @$curthread.Name
                    m = re.search(
                        r'@\$curthread\.Name\s*:\s*"([^"]+)"', name_out)
                    if m:
                        thread.name = m.group(1)
                except Exception as e:
                    logger.debug(f"Could not get name for thread "
                                 f"{thread.id}: {e}")

            # Fall back: use a 1-based label matching the DAP thread id
            if not thread.name:
                thread.name = f"Thread {thread.id + 1}"

            # Cache whatever name we resolved
            self._thread_name_cache[thread.id] = thread.name

        # Restore original CDB thread context if we changed it
        if current_cdb_thread != saved_thread:
            self.communicator.send_command(f'~{saved_thread}s')
        self.current_thread_id = saved_thread

        return threads

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

    def get_container_elements(
            self, container_name: str,
            container_type: str, size: int) -> List[CdbVariable]:
        """Get elements from a container (vector, array, etc.)"""
        elements = []

        if container_type == 'vector':
            # Use dx command to get structured vector information
            try:
                dx_response = \
                    self.communicator.send_command(f'dx {container_name}')
                logger.debug(f"dx response: {repr(dx_response)}")

                # Parse dx output to extract vector elements
                # Format: [0]              : 1 [Type: int]
                element_pattern = re.compile(
                    r'^\s*\[(\d+)\]\s*:\s*(.+?)\s*\[Type:\s*(.+?)\]')

                for line in dx_response.split('\n'):
                    match = element_pattern.match(line)
                    if match:
                        index, value, element_type = match.groups()

                        # Clean up the value
                        # (remove extra spaces and 0n prefix)
                        clean_value = clean_integer_value(value.strip())
                        clean_type = element_type.strip()

                        elements.append(CdbVariable(
                            name=f'[{index}]',
                            value=clean_value,
                            type=clean_type
                        ))

                        logger.debug(f"Parsed element [{index}]: "
                                     f"{clean_value} ({clean_type})")

                logger.info(f"Successfully parsed {len(elements)} "
                            "elements from dx output")

            except Exception as e:
                logger.error("Error accessing vector elements for "
                             f"{container_name}: {e}")

        elif container_type == 'array':
            # Handle C-style arrays and pointer arrays
            try:
                # Try dx command first for structured output
                # (works for some arrays)
                dx_response = self.communicator.send_command(
                    f'dx {container_name}')
                logger.debug(f"dx response for array: {repr(dx_response)}")

                # Parse dx output to extract array elements
                # Format: [0]              : 2 [Type: int]
                element_pattern = re.compile(
                    r'^\s*\[(\d+)\]\s*:\s*(.+?)\s*\[Type:\s*(.+?)\]')

                for line in dx_response.split('\n'):
                    match = element_pattern.match(line)
                    if match:
                        index, value, element_type = match.groups()

                        # Clean up the value
                        # (remove extra spaces and 0n prefix)
                        clean_value = clean_integer_value(value.strip())
                        clean_type = element_type.strip()

                        elements.append(CdbVariable(
                            name=f'[{index}]',
                            value=clean_value,
                            type=clean_type
                        ))

                        logger.debug(f"Parsed array element [{index}]: "
                                     f"{clean_value} ({clean_type})")

                logger.info(f"Successfully parsed {len(elements)} "
                            "array elements")

            except Exception as e:
                logger.error("Error accessing array elements for "
                             f"{container_name}: {e}")

        elif container_type in ['struct', 'class']:
            # Handle struct and class member inspection
            try:
                # Use dx command to get structured object information
                dx_response = self.communicator.send_command(f'dx {container_name}')
                logger.debug(f"dx response for {container_type}: {repr(dx_response)}")

                # Parse dx output to extract struct/class members
                # Format examples:
                # [+0x000] x                : 10 [Type: int]
                # [+0x004] y                : 20 [Type: int] 
                # [+0x000] width            : 100 [Type: int]
                # [+0x004] height           : 50 [Type: int]
                # [+0x008] topLeft          [Type: Point]
                member_pattern = re.compile(
                    r'^\s*\[.*?\]\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::\s*(.+?))?\s*\[Type:\s*(.+?)\]\s*$')

                for line in dx_response.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                        
                    match = member_pattern.match(line)
                    if match:
                        member_name, value, member_type = match.groups()

                        # Handle cases where value is None (no colon-separated value)
                        if value is None:
                            clean_value = f"({member_type.strip()})"  # Show type as placeholder
                        else:
                            # Clean up the value (remove extra spaces and 0n prefix)
                            clean_value = clean_integer_value(value.strip())
                        clean_type = member_type.strip()

                        # Check if this member is itself a struct/class that can be expanded
                        is_container = False
                        container_size = None
                        container_type_inner = None
                        
                        logger.debug(f"Checking if member {member_name} is struct/class: type='{clean_type}', value='{clean_value}'")
                        if self.parser._is_struct_or_class_type(clean_type, clean_value):
                            is_container = True
                            container_type_inner = 'struct' if 'struct' in clean_type.lower() else 'class'
                            logger.debug(f"Identified {member_name} as {container_type_inner}")
                        else:
                            logger.debug(f"Member {member_name} not identified as struct/class")

                        elements.append(CdbVariable(
                            name=member_name,
                            value=clean_value,
                            type=clean_type,
                            is_container=is_container,
                            container_size=container_size,
                            container_type=container_type_inner
                        ))

                        logger.debug(f"Parsed {container_type} member {member_name}: "
                                   f"{clean_value} ({clean_type})")

                logger.info(f"Successfully parsed {len(elements)} "
                          f"{container_type} members")

            except Exception as e:
                logger.error(f"Error accessing {container_type} members for "
                           f"{container_name}: {e}")

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

        # The CDB prompt embedded in unsolicited output encodes the active
        # thread: "N:frame>" e.g. "1:000>".  Extract it so that
        # current_thread_id is accurate before we build the stop event.
        # This is critical when a breakpoint fires on a non-main thread:
        # without this update the stop event would report the wrong thread,
        # and get_stack_trace would skip the necessary thread switch.
        prompt_thread_match = re.search(r'(\d+):\d+>', output)
        if prompt_thread_match:
            detected = int(prompt_thread_match.group(1))
            if detected != self.current_thread_id:
                logger.debug(
                    f"Updating current_thread_id: "
                    f"{self.current_thread_id} → {detected} "
                    "(inferred from CDB prompt in unsolicited output)"
                )
                self.current_thread_id = detected

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
                            'threadId': self.current_thread_id
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
                'threadId': self.current_thread_id
            }
        elif 'Access violation' in output or 'Exception' in output:
            self.is_stopped = True
            logger.info("Detected exception")
            return {
                'type': 'stopped',
                'reason': 'exception',
                'threadId': self.current_thread_id
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
                                'threadId': self.current_thread_id
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
                        'threadId': self.current_thread_id
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
                'threadId': self.current_thread_id
            }

        return None

    def terminate(self):
        """Terminate debugging session"""
        self.communicator.terminate()
