#!/usr/bin/env python3
"""
Test script to verify the DAP server's vector expansion functionality
"""

import json
import socket
import threading
import time
import sys
import os

def send_dap_message(sock, message):
    """Send a DAP message over the socket"""
    content = json.dumps(message)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    full_message = header + content
    sock.send(full_message.encode('utf-8'))
    print(f"SENT: {message}")

def receive_dap_message(sock):
    """Receive a DAP message from the socket"""
    # Read headers
    headers = b""
    while b"\r\n\r\n" not in headers:
        chunk = sock.recv(1)
        if not chunk:
            return None
        headers += chunk
    
    # Parse content-length
    header_str = headers.decode('utf-8')
    content_length = 0
    for line in header_str.split('\r\n'):
        if line.startswith('Content-Length:'):
            content_length = int(line.split(':')[1].strip())
            break
    
    # Read content
    content = b""
    while len(content) < content_length:
        chunk = sock.recv(content_length - len(content))
        if not chunk:
            return None
        content += chunk
    
    message = json.loads(content.decode('utf-8'))
    print(f"RECEIVED: {json.dumps(message, indent=2)}")
    return message

def test_dap_vector_expansion():
    """Test DAP server vector expansion"""
    # Connect to DAP server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', 13000))
        print("Connected to DAP server")
        
        seq = 1
        
        # Initialize
        send_dap_message(sock, {
            "seq": seq,
            "type": "request",
            "command": "initialize",
            "arguments": {
                "clientID": "test-client",
                "clientName": "Vector Test Client",
                "adapterID": "cdb-dap",
                "pathFormat": "path",
                "linesStartAt1": True,
                "columnsStartAt1": True,
                "locale": "en-us"
            }
        })
        seq += 1
        
        # Wait for initialize response
        response = receive_dap_message(sock)
        if not response or response.get('command') != 'initialize':
            print("Failed to initialize")
            return False
        
        # Launch
        program_path = r"c:\Users\tim1lobn\Dev\CdbDap\test_program\build\Debug\test_program.exe"
        send_dap_message(sock, {
            "seq": seq,
            "type": "request", 
            "command": "launch",
            "arguments": {
                "program": program_path,
                "stopAtEntry": True
            }
        })
        seq += 1
        
        # Wait for launch response and events
        while True:
            msg = receive_dap_message(sock)
            if not msg:
                break
            if msg.get('type') == 'event' and msg.get('event') == 'stopped':
                print("Program stopped, ready to set breakpoint")
                break
        
        # Set breakpoint at line 25
        send_dap_message(sock, {
            "seq": seq,
            "type": "request",
            "command": "setBreakpoints", 
            "arguments": {
                "source": {"path": r"c:\Users\tim1lobn\Dev\CdbDap\test_program\test_program.cpp"},
                "breakpoints": [{"line": 25}]
            }
        })
        seq += 1
        
        # Wait for breakpoint response
        response = receive_dap_message(sock)
        
        # Continue
        send_dap_message(sock, {
            "seq": seq,
            "type": "request",
            "command": "continue",
            "arguments": {"threadId": 1}
        })
        seq += 1
        
        # Wait for continue response and stopped event
        while True:
            msg = receive_dap_message(sock)
            if not msg:
                break
            if msg.get('type') == 'event' and msg.get('event') == 'stopped' and msg.get('body', {}).get('reason') == 'breakpoint':
                print("Hit breakpoint!")
                break
        
        # Get stack trace
        send_dap_message(sock, {
            "seq": seq,
            "type": "request",
            "command": "stackTrace",
            "arguments": {"threadId": 1}
        })
        seq += 1
        
        # Wait for stack trace response
        stack_response = receive_dap_message(sock)
        
        # Get scopes (should include locals)
        frame_id = stack_response['body']['stackFrames'][0]['id']
        send_dap_message(sock, {
            "seq": seq,
            "type": "request",
            "command": "scopes",
            "arguments": {"frameId": frame_id}
        })
        seq += 1
        
        # Wait for scopes response
        scopes_response = receive_dap_message(sock)
        
        # Get local variables
        locals_ref = None
        for scope in scopes_response['body']['scopes']:
            if scope['name'] == 'Locals':
                locals_ref = scope['variablesReference']
                break
        
        if locals_ref:
            send_dap_message(sock, {
                "seq": seq,
                "type": "request",
                "command": "variables",
                "arguments": {"variablesReference": locals_ref}
            })
            seq += 1
            
            # Wait for variables response
            vars_response = receive_dap_message(sock)
            
            # Look for the numbers vector
            numbers_ref = None
            for var in vars_response['body']['variables']:
                print(f"Variable: {var['name']} = {var['value']} (ref: {var.get('variablesReference', 0)})")
                if var['name'] == 'numbers' and var.get('variablesReference', 0) > 0:
                    numbers_ref = var['variablesReference']
                    print(f"Found expandable numbers vector with reference: {numbers_ref}")
            
            # Expand the numbers vector
            if numbers_ref:
                send_dap_message(sock, {
                    "seq": seq,
                    "type": "request",
                    "command": "variables",
                    "arguments": {"variablesReference": numbers_ref}
                })
                seq += 1
                
                # Wait for vector elements response
                elements_response = receive_dap_message(sock)
                
                print("Vector elements:")
                for element in elements_response['body']['variables']:
                    print(f"  {element['name']}: {element['value']} ({element.get('type', 'unknown')})")
                
                print("✅ Vector expansion test PASSED!")
                return True
            else:
                print("❌ Numbers vector not found or not expandable")
                return False
        else:
            print("❌ Local variables scope not found")
            return False
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    print("Starting DAP vector expansion test...")
    print("Make sure the DAP server is running on port 13000")
    time.sleep(2)  # Give time to start server
    test_dap_vector_expansion()