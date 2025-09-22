#!/usr/bin/env python3
"""
Fixed test client for socket-based DAP server
"""

import sys
import os
import json
import subprocess
import socket
import time

def test_socket_dap_fixed():
    """Test the socket-based DAP server with file-based port communication"""
    print("=== FIXED SOCKET DAP TEST ===")
    
    # Start the socket server
    server_script = os.path.join(os.path.dirname(__file__), '..', 'dap_server.py')
    port_file = os.path.join(os.path.dirname(__file__), '..', 'dap_server_port.txt')
    
    print(f"Starting socket DAP server: {server_script}")
    
    # Clean up old port file
    if os.path.exists(port_file):
        os.remove(port_file)
    
    process = subprocess.Popen(
        [sys.executable, server_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for port file to be created
    port = None
    for attempt in range(10):
        time.sleep(1)
        
        if os.path.exists(port_file):
            try:
                with open(port_file, 'r') as f:
                    port = int(f.read().strip())
                print(f"✅ Server started on port {port}")
                break
            except Exception as e:
                print(f"Error reading port file: {e}")
        
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"❌ Server process died. STDERR: {stderr}")
            return False
        
        print(f"Attempt {attempt + 1}: Waiting for port file...")
    
    if port is None:
        print("❌ Could not get port from server")
        process.terminate()
        return False
    
    # Connect to the server
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('localhost', port))
        print(f"✅ Connected to server on port {port}")
    except Exception as e:
        print(f"❌ Could not connect to server: {e}")
        process.terminate()
        return False
    
    # Send initialize request
    try:
        request = {
            'seq': 1,
            'type': 'request',
            'command': 'initialize',
            'arguments': {
                'clientID': 'socket-client',
                'clientName': 'Socket Test Client',
                'adapterID': 'cdb-cpp'
            }
        }
        
        content = json.dumps(request, separators=(',', ':'))
        message = f'Content-Length: {len(content)}\r\n\r\n{content}'
        
        print(f"Sending initialize request ({len(content)} bytes)")
        
        sock.send(message.encode('utf-8'))
        print("✅ Message sent")
        
        # Read response
        sock.settimeout(15)
        buffer = b""
        
        while True:
            data = sock.recv(1024)
            if not data:
                print("❌ Server closed connection")
                break
            
            buffer += data
            print(f"Received {len(data)} bytes, buffer now {len(buffer)} bytes")
            
            # Check for complete response
            if b'Content-Length:' in buffer and b'\r\n\r\n' in buffer:
                header_end = buffer.find(b'\r\n\r\n')
                header_text = buffer[:header_end].decode('utf-8')
                
                content_length = 0
                for line in header_text.split('\r\n'):
                    if line.startswith('Content-Length:'):
                        content_length = int(line.split(':', 1)[1].strip())
                        break
                
                content_start = header_end + 4
                if len(buffer) >= content_start + content_length:
                    content = buffer[content_start:content_start + content_length].decode('utf-8')
                    print(f"✅ Received complete response: {content}")
                    
                    try:
                        response = json.loads(content)
                        if response.get('success'):
                            print("✅ Initialize succeeded!")
                            return True
                        else:
                            print(f"❌ Initialize failed: {response}")
                            return False
                    except json.JSONDecodeError as e:
                        print(f"❌ Invalid JSON response: {e}")
                        return False
        
    except Exception as e:
        print(f"❌ Error during communication: {e}")
        return False
    finally:
        sock.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    
    print("❌ No valid response received")
    return False

if __name__ == '__main__':
    success = test_socket_dap_fixed()
    print(f"\nResult: {'SUCCESS' if success else 'FAILED'}")
    sys.exit(0 if success else 1)
