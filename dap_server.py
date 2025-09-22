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

    def run(self):
        """Main message loop using socket"""
        logger.info("Starting Socket DAP Server message loop...")

        handlers = {
            'initialize': self.handle_initialize,
            'disconnect': self.handle_disconnect,
        }

        buffer = b""

        try:
            logger.info("Reading from socket...")
            self.client_socket.settimeout(1.0)  # Add timeout for recv()
            
            while self.running:
                try:
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
