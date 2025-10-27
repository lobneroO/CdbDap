#!/usr/bin/env python3
"""
Socket-based DAP server with file-based port communication
"""

import sys
import json
import threading
import subprocess
import re
import os
import logging
import socket
import time
import signal
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Configure logging
log_file = os.path.join(os.path.dirname(__file__), 'socket_dap_debug.log')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, mode='w'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger(__name__)

logger.info("Socket DAP Server starting up...")

try:
    from cdb_wrapper import EnhancedCdbDebugger, CdbFrame, CdbVariable, CdbThread
    logger.info("Successfully imported CDB wrapper")
except ImportError as e:
    logger.error(f"Failed to import CDB wrapper: {e}")
    sys.exit(1)

# ... (include all the dataclass definitions from your original file) ...

@dataclass
class Source:
    name: Optional[str] = None
    path: Optional[str] = None
    sourceReference: Optional[int] = None

@dataclass
class Breakpoint:
    id: int
    verified: bool
    line: int
    source: Optional[Source] = None
    message: Optional[str] = None

@dataclass
class StackFrame:
    id: int
    name: str
    line: int
    column: int
    source: Optional[Source] = None

@dataclass
class Thread:
    id: int
    name: str

@dataclass
class Variable:
    name: str
    value: str
    type: Optional[str] = None
    variablesReference: int = 0

class SocketDAPServer:
    """Socket-based Debug Adapter Protocol Server"""

    def __init__(self, port: int = 0):
        logger.info("Initializing Socket DAP Server...")
        self.seq = 1
        self.port = port
        self.socket = None
        self.client_socket = None
        self.running = True
        
        # Map breakpoint IDs to their source locations
        self.breakpoint_locations = {}  # bp_id -> (file_path, line)
        
        try:
            self.debugger = EnhancedCdbDebugger()
            logger.info("Successfully created CDB debugger instance")
        except Exception as e:
            logger.error(f"Failed to create CDB debugger: {e}")
            raise

        self.event_thread = None
        self.is_running = False
        self.capabilities = {
            'supportsConfigurationDoneRequest': True,
            'supportsFunctionBreakpoints': False,
            'supportsConditionalBreakpoints': False,
            'supportsHitConditionalBreakpoints': False,
            'supportsEvaluateForHovers': True,
            'exceptionBreakpointFilters': [],
            'supportsStepBack': False,
            'supportsSetVariable': False,
            'supportsRestartFrame': False,
            'supportsGotoTargetsRequest': False,
            'supportsStepInTargetsRequest': False,
            'supportsCompletionsRequest': False,
            'completionTriggerCharacters': [],
            'supportsModulesRequest': False,
            'additionalModuleColumns': [],
            'supportedChecksumAlgorithms': [],
            'supportsRestartRequest': False,
            'supportsExceptionOptions': False,
            'supportsValueFormattingOptions': False,
            'supportsExceptionInfoRequest': False,
            'supportTerminateDebuggee': True,
            'supportSuspendDebuggee': True,
            'supportsDelayedStackTraceLoading': False,
            'supportsLoadedSourcesRequest': False,
            'supportsLogPoints': False,
            'supportsTerminateThreadsRequest': False,
            'supportsSetExpression': False,
            'supportsTerminateRequest': True,
            'supportsDataBreakpoints': False,
            'supportsReadMemoryRequest': False,
            'supportsWriteMemoryRequest': False,
            'supportsDisassembleRequest': False
        }
        logger.info("Socket DAP Server initialization completed")

    def start_server(self):
        """Start the socket server and write port to file"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(1.0)  # Add timeout for accept()
        
        # Bind to localhost with automatic port selection if port=0
        # TODO: for testing, just use 13000 like lldb does
        self.port = 13000
        self.socket.bind(('localhost', self.port))
        actual_port = self.socket.getsockname()[1]
        self.port = actual_port

        self.socket.listen(1)
        logger.info(f"Socket DAP Server listening on port {self.port}")

        # Write port to file for client to read
        port_file = os.path.join(os.path.dirname(__file__), 'dap_server_port.txt')
        try:
            with open(port_file, 'w') as f:
                f.write(str(self.port))
            logger.info(f"Port written to {port_file}")
        except Exception as e:
            logger.error(f"Failed to write port file: {e}")

        # Also print to stdout (with flush)
        print(f"DAP Server listening on port {self.port}")
        sys.stdout.flush()

        return actual_port

    def wait_for_connection(self):
        """Wait for client connection with timeout"""
        logger.info("Waiting for client connection...")
        
        while self.running:
            try:
                self.client_socket, client_address = self.socket.accept()
                logger.info(f"Client connected from {client_address}")
                return True
            except socket.timeout:
                # Check if we should continue waiting
                continue
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                return False

        return False

    def get_next_seq(self) -> int:
        """Get next sequence number"""
        seq = self.seq
        self.seq += 1
        return seq

    def send_message(self, message: Dict[str, Any]):
        """Send message to client via socket"""
        try:
            content = json.dumps(message, separators=(',', ':'))
            headers = f'Content-Length: {len(content)}\r\n\r\n'
            output = headers + content
            
            self.client_socket.send(output.encode('utf-8'))
            logger.debug(f"Sent message: {message}")
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    def send_response(self, request_seq: int, command: str,
                      success: bool = True, message: str = None,
                      body: Dict[str, Any] = None):
        """Send response to client"""
        response = {
            'command': command,
            'request_seq': request_seq,
            'success': success,
            'seq': self.get_next_seq(),
            'type': 'response'
        }

        if message:
            response['message'] = message
        if body:
            response['body'] = body

        self.send_message(response)

    def send_event(self, event: str, body: Dict[str, Any] = None):
        """Send event to client"""
        message = {
            'event': event,
            'seq': self.get_next_seq(),
            'type': 'event'
        }

        if body:
            message['body'] = body

        self.send_message(message)

    def handle_initialize(self, request: Dict[str, Any]):
        """Handle initialize request"""
        logger.info("*** Handling initialize request ***")
        try:
            self.send_response(
                request['seq'],
                'initialize',
                body=self.capabilities
            )
            self.send_event('initialized')
            logger.info("*** Initialize request completed successfully ***")
        except Exception as e:
            logger.error(f"Error handling initialize: {e}")

    def handle_disconnect(self, request: Dict[str, Any]):
        """Handle disconnect request"""
        logger.info("Handling disconnect request")
        self.is_running = False
        self.running = False  # Stop the main loop
        if self.debugger:
            try:
                self.debugger.stop()
            except Exception as e:
                logger.error(f"Error stopping debugger: {e}")
        self.send_response(request['seq'], 'disconnect')

    def handle_launch(self, request: Dict[str, Any]):
        """Handle launch request"""
        logger.info("Handling launch request")
        logger.info(f"Launch request arguments: {request.get('arguments', {})}")
        
        args = request.get('arguments', {})
        program = args.get('program')

        if not program:
            error_msg = 'No program specified in launch arguments'
            logger.error(error_msg)
            self.send_response(request['seq'], 'launch',
                               False, error_msg)
            return

        logger.info(f"Attempting to launch program: {program}")
        
        # Convert relative path to absolute if needed
        if not os.path.isabs(program):
            cwd = args.get('cwd', os.getcwd())
            program = os.path.join(cwd, program)
            logger.info(f"Converted to absolute path: {program}")

        try:
            success = self.debugger.start(
                program=program,
                args=args.get('args', []),
                cwd=args.get('cwd'),
            )

            if success:
                self.is_running = True
                logger.info("Debugger started successfully, sending launch response")
                self.send_response(request['seq'], 'launch')
                # Don't send stopped event here - we'll send it after configurationDone
                # when we've moved from loader breakpoint to main
                logger.info("Waiting for configurationDone to move to main entry point")
            else:
                error_msg = f'Failed to start debugger for program: {program}'
                logger.error(error_msg)
                self.send_response(request['seq'], 'launch',
                                   False, error_msg)
        except Exception as e:
            error_msg = f"Error in handle_launch: {e}"
            logger.error(error_msg)
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            self.send_response(request['seq'], 'launch', False, error_msg)

    def handle_set_breakpoints(self, request: Dict[str, Any]):
        """Handle setBreakpoints request"""
        logger.info("Handling setBreakpoints request")
        args = request.get('arguments', {})
        source = args.get('source', {})
        file_path = source.get('path')
        breakpoints = args.get('breakpoints', [])

        if not file_path:
            self.send_response(request['seq'], 'setBreakpoints', False, 'No file path provided')
            return

        try:
            result_breakpoints = []
            for bp in breakpoints:
                line = bp.get('line')
                if line:
                    try:
                        bp_id = self.debugger.set_breakpoint(file_path, line)
                        # Store breakpoint location for later reference
                        self.breakpoint_locations[bp_id] = (file_path, line)
                        logger.info(f"Stored breakpoint {bp_id} at {file_path}:{line}")
                        
                        result_breakpoints.append(Breakpoint(
                            id=bp_id,
                            verified=True,
                            line=line,
                            source=Source(path=file_path, name=os.path.basename(file_path))
                        ))
                    except Exception as e:
                        logger.error(f"Failed to set breakpoint at {file_path}:{line}: {e}")
                        result_breakpoints.append(Breakpoint(
                            id=0,
                            verified=False,
                            line=line,
                            source=Source(path=file_path, name=os.path.basename(file_path)),
                            message=str(e)
                        ))

            self.send_response(request['seq'], 'setBreakpoints', body={
                'breakpoints': [asdict(bp) for bp in result_breakpoints]
            })
        except Exception as e:
            logger.error(f"Error in handle_set_breakpoints: {e}")
            self.send_response(request['seq'], 'setBreakpoints', False, str(e))

    def handle_configuration_done(self, request: Dict[str, Any]):
        """Handle configurationDone request"""
        logger.info("Handling configurationDone request")
        # Lightweight: acknowledge configuration and emit a single stopped event for current position.
        if self.debugger and self.is_running and self.debugger.is_stopped:
            try:
                file_path, line_num = self.debugger.get_current_location()
                logger.info(f"configurationDone current location: {file_path}:{line_num}")
                reason = 'entry'
                for bp_id, (bp_file, bp_line) in self.breakpoint_locations.items():
                    if file_path and bp_file and file_path.lower().endswith(os.path.basename(bp_file).lower()) and bp_line == line_num:
                        reason = 'breakpoint'
                        break
                stopped_event = {
                    'reason': reason,
                    'threadId': 1,
                    'allThreadsStopped': True
                }
                if file_path and line_num > 0:
                    stopped_event['source'] = {
                        'name': os.path.basename(file_path),
                        'path': file_path
                    }
                    stopped_event['line'] = line_num
                    stopped_event['column'] = 1
                self.send_event('stopped', stopped_event)
            except Exception as e:
                logger.error(f"Error fetching current location in configurationDone: {e}")
        self.send_response(request['seq'], 'configurationDone')

    # Restored handler functions (lost in previous patch) --------------------
    def handle_continue(self, request: Dict[str, Any]):
        """Handle continue request"""
        logger.info("Handling continue request")
        try:
            self.debugger.continue_execution()
            self.send_response(request['seq'], 'continue', body={'allThreadsContinued': True})
        except Exception as e:
            logger.error(f"Error in handle_continue: {e}")
            self.send_response(request['seq'], 'continue', False, str(e))

    def handle_next(self, request: Dict[str, Any]):
        """Handle next (step over) request"""
        logger.info("Handling next request")
        try:
            self.debugger.step_over()
            self.send_response(request['seq'], 'next')
        except Exception as e:
            logger.error(f"Error in handle_next: {e}")
            self.send_response(request['seq'], 'next', False, str(e))

    def handle_step_in(self, request: Dict[str, Any]):
        """Handle stepIn request"""
        logger.info("Handling stepIn request")
        try:
            self.debugger.step_into()
            self.send_response(request['seq'], 'stepIn')
        except Exception as e:
            logger.error(f"Error in handle_step_in: {e}")
            self.send_response(request['seq'], 'stepIn', False, str(e))

    def handle_step_out(self, request: Dict[str, Any]):
        """Handle stepOut request"""
        logger.info("Handling stepOut request")
        try:
            self.debugger.step_out()
            self.send_response(request['seq'], 'stepOut')
        except Exception as e:
            logger.error(f"Error in handle_step_out: {e}")
            self.send_response(request['seq'], 'stepOut', False, str(e))

    def handle_pause(self, request: Dict[str, Any]):
        """Handle pause request"""
        logger.info("Handling pause request")
        try:
            self.debugger.pause()
            self.send_response(request['seq'], 'pause')
        except Exception as e:
            logger.error(f"Error in handle_pause: {e}")
            self.send_response(request['seq'], 'pause', False, str(e))

    def handle_threads(self, request: Dict[str, Any]):
        logger.info("Handling threads request")
        try:
            threads = self.debugger.get_threads()
            thread_list = [Thread(id=t.id, name=t.name) for t in threads]
            if not thread_list:
                thread_list = [Thread(id=1, name='Main Thread')]
            self.send_response(request['seq'], 'threads', body={
                'threads': [asdict(t) for t in thread_list]
            })
        except Exception as e:
            logger.error(f"Error getting threads: {e}")
            self.send_response(request['seq'], 'threads', body={
                'threads': [asdict(Thread(id=1, name='Main Thread'))]
            })

    def handle_stack_trace(self, request: Dict[str, Any]):
        """Handle stackTrace request"""
        logger.info("Handling stackTrace request")
        args = request.get('arguments', {})
        thread_id = args.get('threadId', 1)

        try:
            frames = self.debugger.get_stack_trace(thread_id)
            stack_frames = []
            for i, frame in enumerate(frames):
                stack_frames.append(StackFrame(
                    id=i,
                    name=frame.name,
                    line=frame.line,
                    column=0,
                    source=Source(
                        path=frame.file,
                        name=os.path.basename(frame.file) if frame.file else None
                    ) if frame.file else None
                ))

            self.send_response(request['seq'], 'stackTrace', body={
                'stackFrames': [asdict(f) for f in stack_frames]
            })
        except Exception as e:
            logger.error(f"Error getting stack trace: {e}")
            self.send_response(request['seq'], 'stackTrace', False, str(e))

    def handle_scopes(self, request: Dict[str, Any]):
        """Handle scopes request"""
        logger.info("Handling scopes request")
        args = request.get('arguments', {})
        frame_id = args.get('frameId', 0)

        scopes = [
            {'name': 'Locals', 'variablesReference': 1000 + frame_id, 'expensive': False},
            {'name': 'Arguments', 'variablesReference': 2000 + frame_id, 'expensive': False}
        ]

        self.send_response(request['seq'], 'scopes', body={'scopes': scopes})

    def handle_variables(self, request: Dict[str, Any]):
        """Handle variables request"""
        logger.info("Handling variables request")
        args = request.get('arguments', {})
        var_ref = args.get('variablesReference', 0)

        try:
            if var_ref >= 1000 and var_ref < 2000:
                frame_id = var_ref - 1000
                variables = self.debugger.get_local_variables(frame_id)
            elif var_ref >= 2000:
                frame_id = var_ref - 2000
                variables = self.debugger.get_arguments(frame_id)
            else:
                variables = []

            var_list = []
            for var in variables:
                var_list.append(Variable(
                    name=var.name,
                    value=var.value,
                    type=var.type,
                    variablesReference=0
                ))

            self.send_response(request['seq'], 'variables', body={
                'variables': [asdict(v) for v in var_list]
            })
        except Exception as e:
            logger.error(f"Error getting variables: {e}")
            self.send_response(request['seq'], 'variables', body={'variables': []})

    def handle_evaluate(self, request: Dict[str, Any]):
        """Handle evaluate request"""
        logger.info("Handling evaluate request")
        args = request.get('arguments', {})
        expression = args.get('expression', '')

        try:
            result = self.debugger.evaluate_expression(expression)
            self.send_response(request['seq'], 'evaluate', body={
                'result': str(result),
                'variablesReference': 0
            })
        except Exception as e:
            logger.error(f"Error evaluating expression: {e}")
            self.send_response(request['seq'], 'evaluate', False, str(e))

    def handle_set_exception_breakpoints(self, request: Dict[str, Any]):
        """Handle setExceptionBreakpoints request (no-op)"""
        logger.info("Handling setExceptionBreakpoints request")
        # You can implement real exception breakpoints if your debugger supports it.
        # For now, just respond with an empty list.
        self.send_response(request['seq'], 'setExceptionBreakpoints', body={
            'breakpoints': []
        })

    def handle_terminate(self, request: Dict[str, Any]):
        """Handle terminate request"""
        logger.info("Handling terminate request")
        self.is_running = False
        self.running = False
        if self.debugger:
            try:
                self.debugger.terminate()
            except Exception as e:
                logger.error(f"Error terminating debugger: {e}")
        self.send_response(request['seq'], 'terminate')

    def run(self):
        """Main message loop using socket"""
        logger.info("Starting Socket DAP Server message loop...")

        handlers = {
            'initialize': self.handle_initialize,
            'launch': self.handle_launch,
            'setBreakpoints': self.handle_set_breakpoints,
            'configurationDone': self.handle_configuration_done,
            'continue': self.handle_continue,
            'next': self.handle_next,
            'stepIn': self.handle_step_in,
            'stepOut': self.handle_step_out,
            'pause': self.handle_pause,
            'threads': self.handle_threads,
            'stackTrace': self.handle_stack_trace,
            'scopes': self.handle_scopes,
            'variables': self.handle_variables,
            'evaluate': self.handle_evaluate,
            'disconnect': self.handle_disconnect,
            'terminate': self.handle_terminate,
            'setExceptionBreakpoints': self.handle_set_exception_breakpoints,
        }

        buffer = b""

        try:
            logger.info("Reading from socket...")
            self.client_socket.settimeout(1.0)  # Add timeout for recv()

            while self.running:
                try:
                    # Check for debugging events (breakpoints, exceptions, etc.)
                    if self.debugger and self.is_running:
                        event = self.debugger.check_for_events()
                        if event:
                            logger.info(f"Debugger event detected: {event}")
                            if event['type'] == 'stopped':
                                # Get current location for the stopped event
                                try:
                                    file_path, line_num = self.debugger.get_current_location()
                                    stopped_body = {
                                        'reason': event['reason'],
                                        'threadId': event['threadId'],
                                        'allThreadsStopped': True
                                    }
                                    
                                    # Add source location if available
                                    if file_path and line_num > 0:
                                        stopped_body['source'] = {
                                            'name': os.path.basename(file_path),
                                            'path': file_path
                                        }
                                        stopped_body['line'] = line_num
                                        stopped_body['column'] = 1
                                        logger.info(f"Using detected source location: {file_path}:{line_num}")
                                    else:
                                        # Fallback: If we can't get source from CDB but this is a breakpoint,
                                        # try to use our stored breakpoint locations
                                        if event['reason'] == 'breakpoint':
                                            logger.info("No source detected from CDB, checking breakpoint map...")
                                            # Try to find which breakpoint was hit by checking the debugger's breakpoint list
                                            try:
                                                current_bp_list = self.debugger.list_breakpoints()
                                                logger.info(f"Current breakpoints from debugger: {current_bp_list}")
                                                
                                                # Look for a breakpoint that matches our stored locations
                                                for bp_id, (bp_file, bp_line) in self.breakpoint_locations.items():
                                                    logger.info(f"Checking stored breakpoint {bp_id}: {bp_file}:{bp_line}")
                                                    # For now, use the first breakpoint location as fallback
                                                    # In a more sophisticated version, we could parse CDB output
                                                    # to determine exactly which breakpoint was hit
                                                    if self.breakpoint_locations:
                                                        fallback_file, fallback_line = next(iter(self.breakpoint_locations.values()))
                                                        stopped_body['source'] = {
                                                            'name': os.path.basename(fallback_file),
                                                            'path': fallback_file
                                                        }
                                                        stopped_body['line'] = fallback_line
                                                        stopped_body['column'] = 1
                                                        logger.info(f"Using fallback breakpoint location: {fallback_file}:{fallback_line}")
                                                        break
                                            except Exception as fallback_e:
                                                logger.error(f"Error in breakpoint fallback: {fallback_e}")
                                    
                                    self.send_event('stopped', stopped_body)
                                except Exception as e:
                                    logger.error(f"Error getting location for stopped event: {e}")
                                    # Send basic stopped event without location
                                    self.send_event('stopped', {
                                        'reason': event['reason'],
                                        'threadId': event['threadId'],
                                        'allThreadsStopped': True
                                    })
                            elif event['type'] == 'exited':
                                self.send_event('exited', {
                                    'exitCode': event['exitCode']
                                })
                                self.is_running = False

                    # Read data from socket
                    data = self.client_socket.recv(4096)
                    if not data:
                        logger.info("Client disconnected")
                        break

                    buffer += data
                    logger.debug(f"Received {len(data)} bytes, buffer now {len(buffer)} bytes")

                    # Process complete messages in buffer
                    while True:
                        # Look for Content-Length header
                        if b'Content-Length:' not in buffer:
                            break

                        # Find header end
                        header_end = buffer.find(b'\r\n\r\n')
                        if header_end == -1:
                            break

                        # Parse headers
                        header_text = buffer[:header_end].decode('utf-8')
                        content_start = header_end + 4

                        content_length = 0
                        for line in header_text.split('\r\n'):
                            if line.startswith('Content-Length:'):
                                content_length = int(line.split(':', 1)[1].strip())
                                break

                        logger.debug(f"Parsed Content-Length: {content_length}")

                        # Check if we have complete message
                        if len(buffer) < content_start + content_length:
                            logger.debug(f"Need more data: have {len(buffer)}, need {content_start + content_length}")
                            break

                        # Extract content
                        content_bytes = buffer[content_start:content_start + content_length]
                        content = content_bytes.decode('utf-8')
                        logger.debug(f"Extracted content: {repr(content)}")

                        # Remove processed message from buffer
                        buffer = buffer[content_start + content_length:]

                        # Parse and handle JSON
                        try:
                            request = json.loads(content)
                            logger.info(f"*** Successfully parsed request: {request.get('command', 'unknown')} ***")

                            command = request.get('command')
                            if command in handlers:
                                logger.info(f"*** Calling handler for: {command} ***")
                                handlers[command](request)
                                logger.info(f"*** Handler completed for: {command} ***")
                            else:
                                logger.warning(f"Unknown command: {command}")
                                self.send_response(
                                    request.get('seq', 0),
                                    command or 'unknown',
                                    False,
                                    f"Unknown command: {command}"
                                )

                        except json.JSONDecodeError as e:
                            logger.error(f"JSON decode error: {e}")
                            logger.error(f"Content: {repr(content)}")
                            continue

                except socket.timeout:
                    # Continue the loop, check if we should still be running
                    continue
                except Exception as e:
                    logger.error(f"Error in socket loop: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    break

        except Exception as e:
            logger.error(f"Socket server error: {e}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up resources"""
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        if self.socket:
            self.socket.close()

        # Clean up port file
        port_file = os.path.join(os.path.dirname(__file__), 'dap_server_port.txt')
        try:
            if os.path.exists(port_file):
                os.remove(port_file)
        except:
            pass

        logger.info("Socket DAP Server stopped")


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C)"""
    print("\nReceived interrupt signal, shutting down...")
    sys.exit(0)


def main():
    """Main entry point"""
    # Set up signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    server = SocketDAPServer()

    try:
        port = server.start_server()
        if server.wait_for_connection():
            server.run()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        server.cleanup()


if __name__ == '__main__':
    main()
