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
from typing import Dict, List, Any, Optional, Tuple, NamedTuple
from dataclasses import dataclass

# Configure logging
log_file = os.path.join(os.path.dirname(__file__), 'socket_dap_debug.log')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='a'),  # append mode to add to existing log
        logging.StreamHandler(sys.stderr)
    ]
)
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
                frame_id, child_sp, ret_addr, function, file_path, line_str = match.groups()
                
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
                logger.debug(f"Parsed frame: {frame.name} at {frame.file}:{frame.line}")
            else:
                logger.debug(f"Stack line didn't match pattern: {repr(line)}")

        logger.debug(f"Parsed {len(frames)} frames total")
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
            logger.info(f"Starting CDB process for program: {program}")
            
            # Validate program exists
            if not os.path.exists(program):
                logger.error(f"Program file does not exist: {program}")
                return False
            
            # Check if cdb.exe is available
            cdb_path = shutil.which('cdb.exe')
            if not cdb_path:
                logger.error("cdb.exe not found in PATH. Please ensure Windows Debugging Tools are installed.")
                return False
            
            logger.info(f"Found cdb.exe at: {cdb_path}")

            # Don't use -g flag, we want to stop at initial breakpoint to allow setup
            cdb_command = ['cdb.exe', '-G', '-cf', '-cfr']
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
                logger.error(f"CDB process exited immediately with return code: {self.process.poll()}")
                return False

            # Send initial setup commands
            logger.info("Sending initial setup commands...")
            self.send_command(".echo Setting up debugger...")
            self.send_command(".symopt+0x100")  # Enable source line support
            
            # Check symbol and source line availability
            logger.info("Checking debug symbol availability...")
            sym_output = self.send_command("lm vm VisionSym*")  # List modules with verbose info
            logger.info(f"Symbol info: {sym_output}")
            
            # Try to load symbols if needed
            self.send_command(".reload /f")  # Force reload symbols
            
            # We're now stopped at the initial loader breakpoint
            # Get the initial stack trace to see where we are
            logger.info("Getting initial stack trace to verify position...")
            stack_output = self.send_command("k")
            logger.info(f"Initial stack: {stack_output}")

            logger.info(f"Successfully started CDB process for program: {program}")
            logger.info("Debugger is stopped at initial breakpoint, ready for DAP setup")
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
                if (buffer.endswith('0:000> ') or buffer.endswith('> ') or 
                    buffer.endswith('0:000>') or buffer.rstrip().endswith('0:000>')):
                    if self.current_command:
                        self.command_response = buffer
                        self.command_event.set()
                    else:
                        # Unsolicited output (e.g., breakpoint hit)
                        logger.debug(f"Unsolicited output with prompt: {repr(buffer[:100])}")
                        self.output_queue.put(buffer)
                    buffer = ""
                
                # Check for explicit breakpoint messages
                elif (('Breakpoint' in buffer or 'breakpoint' in buffer.lower()) and 
                      len(buffer) > 10):
                    logger.info(f"Detected explicit breakpoint message: {repr(buffer[:200])}")
                    if not self.current_command:
                        self.output_queue.put(buffer)
                        buffer = ""
                
                # Check for other break events
                elif (('Break instruction exception' in buffer or 
                       'stopped at' in buffer.lower()) and len(buffer) > 50):
                    logger.info(f"Detected break event: {repr(buffer[:100])}")
                    if not self.current_command:
                        self.output_queue.put(buffer)
                        buffer = ""
                
                # Check if buffer is getting too long without a prompt
                elif len(buffer) > 2000:
                    logger.debug(f"Buffer getting long, flushing: {repr(buffer[:100])}")
                    if not self.current_command:
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
                logger.debug(f"Command '{command}' response: {repr(response[:200])}")
                return response
            else:
                logger.warning(f"Command timeout: {command}")
                self.current_command = None
                
                # For continue commands, timeout might mean the program is running
                if command.strip() == 'g':
                    logger.info("Continue command timed out - program may be running or hit breakpoint")
                    # Try to break and see where we are
                    time.sleep(0.1)
                    self.process.stdin.write('\x03\n')  # Send Ctrl+C to break
                    self.process.stdin.flush()
                
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

        logger.info(f"Attempting to set breakpoint {bp_id} at {file_path}:{line}")
        
        # Try different CDB breakpoint syntax variations
        commands_to_try = [
            f'bp `{file_path}:{line}`',  # Standard syntax with backticks
            f'bp "{file_path}:{line}"',  # With quotes
            f'bm {file_path}:{line}',    # Different breakpoint command
        ]
        
        verified = False
        response = ""
        
        for i, command in enumerate(commands_to_try):
            logger.info(f"Trying breakpoint command #{i+1}: {command}")
            response = self.communicator.send_command(command)
            logger.info(f"Breakpoint response: {repr(response)}")
            
        for i, command in enumerate(commands_to_try):
            logger.info(f"Trying breakpoint command #{i+1}: {command}")
            response = self.communicator.send_command(command)
            logger.info(f"Breakpoint response: {repr(response)}")
            
            # Check for successful breakpoint setting - be more strict
            if response.strip():
                if ("error" in response.lower() or "unable" in response.lower() or 
                    "failed" in response.lower() or "invalid" in response.lower()):
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
                    logger.warning(f"Ambiguous breakpoint response: {response}")
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
                # CDB format might be like: "0 e Disable BreakAddress  Module!Function+Offset"
                if (str(line) in bp_line and 
                    (file_path.split('\\')[-1] in bp_line or file_path.split('/')[-1] in bp_line)):
                    logger.info(f"Found breakpoint in list: {bp_line.strip()}")
                    bp_found = True
                    break
                # Also check if the line number appears in the breakpoint info
                elif f":{line}" in bp_line or f"@{line}" in bp_line:
                    logger.info(f"Found line reference in breakpoint: {bp_line.strip()}")
                    bp_found = True
                    break
        
        if bp_found:
            logger.info("Breakpoint successfully verified in breakpoint list")
            verified = True
        else:
            logger.error("Breakpoint NOT found in breakpoint list - setting failed!")
            verified = False
            
            # Try one more approach - set breakpoint using function name if available
            logger.info("Attempting to set breakpoint using function approach...")
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

    def go_to_main_entry(self):
        """Move from initial loader breakpoint to main function entry"""
        logger.info("Moving from loader breakpoint to main entry point...")
        
        # Check current stack to confirm we're at loader breakpoint
        stack_output = self.communicator.send_command("k")
        logger.info(f"Current stack before going to main: {stack_output}")
        
        if "ntdll!" in stack_output and ("Ldr" in stack_output or "DbgBreak" in stack_output):
            logger.info("Confirmed at loader breakpoint, going to main...")
            # Set temporary breakpoint at main and continue
            self.communicator.send_command("bp main")
            self.communicator.send_command("g")
            
            # Give it a moment to reach main
            time.sleep(0.2)
            
            # Check where we ended up
            new_stack = self.communicator.send_command("k")
            logger.info(f"Stack after going to main: {new_stack}")
            
            # Clear the temporary main breakpoint
            self.communicator.send_command("bc 0")  # Clear breakpoint 0 (main)
            
            self.is_stopped = True  # Mark as stopped at main
        else:
            logger.info("Not at loader breakpoint, skipping go-to-main")
    
    def get_current_location(self) -> Tuple[Optional[str], int]:
        """Get current source file and line number"""
        try:
            logger.debug("Getting current location...")
            
            # Method 1: Use 'k=1' to get stack with source info for current frame
            kstack_output = self.communicator.send_command("k=1 1")
            logger.debug(f"Stack with source info: {kstack_output}")
            
            # Method 2: Use '.lines' to enable line number information, then get current frame
            self.communicator.send_command(".lines -e")
            frame_output = self.communicator.send_command("k 1")
            logger.debug(f"Frame output with lines enabled: {frame_output}")
            
            # Method 3: Use 'ln' (list nearest) to get symbol information
            ln_output = self.communicator.send_command("ln .")
            logger.debug(f"List nearest output: {ln_output}")
            
            # Method 4: Try to get the source line directly using 'lsa'
            source_output = self.communicator.send_command("lsa .")
            logger.debug(f"List source around: {source_output}")
            
            # Method 5: Use '.frame' to get detailed frame info
            frame_detailed = self.communicator.send_command(".frame")
            logger.debug(f"Detailed frame info: {frame_detailed}")
            
            # Try to parse various outputs for source information
            import re
            
            # Parse k=1 output first (most reliable)
            if kstack_output:
                # Look for patterns in stack output with source info
                # Format might be like: "VisionSym!main+0x123 [c:\path\file.cpp @ 285]"
                source_patterns = [
                    r'\[([^@]+)\s*@\s*(\d+)\]',  # [filename @ line]
                    r'\(([^)]+):(\d+)\)',  # (filename:line)
                    r'([a-zA-Z]:[^:\s]+\.[a-zA-Z]+)\s*:\s*(\d+)',  # path\file.ext : line
                ]
                
                for pattern in source_patterns:
                    match = re.search(pattern, kstack_output)
                    if match:
                        file_path = match.group(1).strip()
                        line_num = int(match.group(2))
                        logger.info(f"Found location via stack command: {file_path}:{line_num}")
                        return file_path, line_num
            
            # Parse ln output
            if ln_output:
                # ln output format: (address) module!function+offset | (filename:line)
                source_patterns = [
                    r'\[([^@]+)\s*@\s*(\d+)\]',  # [filename @ line]
                    r'\(([^)]+):(\d+)\)',  # (filename:line)
                    r'([a-zA-Z]:[^:\s]+\.[a-zA-Z]+)\s*:\s*(\d+)',  # path\file.ext : line
                ]
                
                for pattern in source_patterns:
                    match = re.search(pattern, ln_output)
                    if match:
                        file_path = match.group(1).strip()
                        line_num = int(match.group(2))
                        logger.info(f"Found location via ln command: {file_path}:{line_num}")
                        return file_path, line_num
            
            # Parse source output (lsa) for line numbers
            if source_output:
                # Look for current line indicators in source output
                lines = source_output.split('\n')
                for line in lines:
                    line = line.strip()
                    # Look for ">" indicator showing current line
                    if '>' in line and ':' in line:
                        # Format might be: "> 285: code here"
                        match = re.match(r'>\s*(\d+):', line)
                        if match:
                            line_num = int(match.group(1))
                            logger.info(f"Found line number from source listing: {line_num}")
                            # We have the line but need to find the file
                            # Try to extract file from other commands
                            for cmd_output in [kstack_output, ln_output, frame_detailed]:
                                if cmd_output:
                                    file_match = re.search(r'([a-zA-Z]:[^:\s]+\.[a-zA-Z]+)', cmd_output)
                                    if file_match:
                                        file_path = file_match.group(1).strip()
                                        logger.info(f"Found file from other output: {file_path}")
                                        return file_path, line_num
                            # If we have line but no file, still return the line
                            return None, line_num
            
            logger.warning("Could not determine current location from any CDB command")
            return None, 0
            
        except Exception as e:
            logger.error(f"Error getting current location: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None, 0

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

        # Enable line number information first
        self.communicator.send_command(".lines -e")
        
        # Use kn (numbered stack) for parsing - it has the frame numbers that the parser expects
        response = self.communicator.send_command('kn')
        logger.debug(f"Numbered stack trace response: {response}")
        
        # Parse the stack trace using the numbered output
        frames = self.parser.parse_stack_trace(response)
        logger.debug(f"Parsed {len(frames)} frames from stack trace")
        
        # The frames should already have source information from the kn command
        # but let's verify and enhance if needed
        for i, frame in enumerate(frames):
            logger.debug(f"Frame {i}: {frame.name} at {frame.file}:{frame.line}")
            
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
                        r'\[([^@]+)\s*@\s*(\d+)\]',  # [filename @ line]
                        r'\(([^)]+):(\d+)\)',  # (filename:line)
                        r'([a-zA-Z]:[^:\s]+\.[a-zA-Z]+)\s*:\s*(\d+)',  # path\file.ext : line
                    ]
                    
                    for pattern in source_patterns:
                        match = re.search(pattern, frame_output)
                        if match:
                            frame.file = match.group(1).strip()
                            frame.line = int(match.group(2))
                            logger.debug(f"Enhanced frame {i}: {frame.file}:{frame.line}")
                            break
                    
                except Exception as e:
                    logger.debug(f"Could not enhance source info for frame {i}: {e}")
        
        # Reset to frame 0
        self.communicator.send_command('.frame 0')
        
        return frames

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

        logger.debug(f"Checking unsolicited output: {repr(output[:200])}")

        # Parse output for events
        if ('Breakpoint' in output or 'breakpoint' in output.lower() or 
            'stopped at' in output.lower()):
            self.is_stopped = True
            logger.info("Detected breakpoint hit")
            return {
                'type': 'stopped',
                'reason': 'breakpoint',
                'threadId': self.current_thread_id or 1
            }
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
        elif 'process exited' in output.lower() or 'exited with code' in output.lower():
            logger.info("Process exited")
            return {
                'type': 'exited',
                'exitCode': 0
            }
        else:
            # Sometimes CDB doesn't send explicit breakpoint messages
            # If we see a prompt but were in continue state, check if we might have hit a breakpoint
            if ('>' in output and len(output) < 50 and 
                hasattr(self, 'was_continuing') and self.was_continuing):
                logger.info("Detected possible breakpoint hit (short prompt after continue)")
                self.was_continuing = False
                self.is_stopped = True
                return {
                    'type': 'stopped', 
                    'reason': 'breakpoint',
                    'threadId': self.current_thread_id or 1
                }
            
            logger.debug("No event detected in output")

        return None

    def terminate(self):
        """Terminate debugging session"""
        self.communicator.terminate()

