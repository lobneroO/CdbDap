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

def _read_messages(sock, timeout=30):
    """Generator yielding parsed DAP messages from socket."""
    sock.settimeout(1)
    buffer = b""
    start = time.time()
    while time.time() - start < timeout:
        try:
            data = sock.recv(4096)
            if not data:
                break
            buffer += data
            while True:
                header_end = buffer.find(b"\r\n\r\n")
                if header_end == -1:
                    break
                header = buffer[:header_end].decode('utf-8', errors='replace')
                content_length = 0
                for line in header.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        try:
                            content_length = int(line.split(':',1)[1].strip())
                        except ValueError:
                            content_length = 0
                        break
                total_len = header_end + 4 + content_length
                if len(buffer) < total_len:
                    break
                content = buffer[header_end+4:header_end+4+content_length].decode('utf-8', errors='replace')
                buffer = buffer[total_len:]
                try:
                    msg = json.loads(content)
                    yield msg
                except json.JSONDecodeError:
                    yield {"type":"malformed","raw":content}
        except socket.timeout:
            continue
        except Exception as e:
            print(f"Socket read error: {e}")
            break

def _send(sock, obj):
    data = json.dumps(obj, separators=(',',':'))
    msg = f"Content-Length: {len(data)}\r\n\r\n{data}".encode('utf-8')
    sock.sendall(msg)

def _find_executable():
    """Locate test_program executable using common build paths."""
    root = os.path.join(os.path.dirname(__file__), '..', 'test_program')
    candidates = [
        os.path.join(root, 'build', 'Debug', 'test_program.exe'),
        os.path.join(root, 'Debug', 'test_program.exe'),
        os.path.join(root, 'test_program.exe')
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.abspath(c)
    return None

def test_locals_and_params_at_line_22():
    """Full DAP flow: initialize, set breakpoint line 22, launch, gather locals & params."""
    server_script = os.path.join(os.path.dirname(__file__), '..', 'dap_server.py')
    port_file = os.path.join(os.path.dirname(__file__), '..', 'dap_server_port.txt')

    if os.path.exists(port_file):
        os.remove(port_file)

    proc = subprocess.Popen([sys.executable, server_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Wait for port
    port = None
    for _ in range(15):
        time.sleep(0.5)
        if os.path.exists(port_file):
            try:
                with open(port_file,'r') as f:
                    port = int(f.read().strip())
                break
            except:
                pass
        if proc.poll() is not None:
            print("Server exited early")
            stdout, stderr = proc.communicate()
            print(stderr)
            return False
    if port is None:
        print("Failed to obtain port file")
        proc.terminate(); return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(('localhost', port))

    seq = 1
    def next_seq():
        nonlocal seq; v = seq; seq += 1; return v

    # Initialize
    _send(sock, {"seq":next_seq(),"type":"request","command":"initialize","arguments":{}})

    exe = _find_executable()
    if not exe:
        print("Executable not found. Build test_program first.")
        sock.close(); proc.terminate(); return False
    source_path = os.path.join(os.path.dirname(__file__), '..', 'test_program', 'test_program.cpp')
    if not os.path.exists(source_path):
        print("Source file not found", source_path)
        sock.close(); proc.terminate(); return False

    # Set breakpoint line 22
    _send(sock, {"seq":next_seq(),"type":"request","command":"setBreakpoints","arguments":{ "source": {"path": os.path.abspath(source_path)}, "breakpoints":[{"line":22}] }})
    # Launch
    _send(sock, {"seq":next_seq(),"type":"request","command":"launch","arguments":{"program": exe}})
    # configurationDone
    _send(sock, {"seq":next_seq(),"type":"request","command":"configurationDone","arguments":{}})
    # Explicit continue after configurationDone to reach user breakpoint line 22
    _send(sock, {"seq":next_seq(),"type":"request","command":"continue","arguments":{"threadId":1}})

    stopped = None
    locals_vars = []
    param_vars = []
    frames = []
    scopes = []
    thread_id = 1

    # Allow multiple stops: first could be entry/main; continue until we stop at line 22
    for msg in _read_messages(sock, timeout=40):
        if msg.get('type') == 'event' and msg.get('event') == 'stopped':
            evt_body = msg.get('body', {})
            evt_line = evt_body.get('line')
            thread_id = evt_body.get('threadId',1)
            if evt_line != 22:
                # Not our target line, request continue again
                _send(sock, {"seq":next_seq(),"type":"request","command":"continue","arguments":{"threadId":thread_id}})
                continue
            stopped = msg
            # At target breakpoint, request stackTrace
            _send(sock, {"seq":next_seq(),"type":"request","command":"stackTrace","arguments":{"threadId": thread_id}})
        elif msg.get('type') == 'response' and msg.get('command') == 'stackTrace' and msg.get('success', True):
            frames = msg.get('body', {}).get('stackFrames', [])
            if frames:
                # Request scopes for top frame
                _send(sock, {"seq":next_seq(),"type":"request","command":"scopes","arguments":{"frameId": frames[0]['id']}})
        elif msg.get('type') == 'response' and msg.get('command') == 'scopes' and msg.get('success', True):
            scopes = msg.get('body', {}).get('scopes', [])
            for sc in scopes:
                _send(sock, {"seq":next_seq(),"type":"request","command":"variables","arguments":{"variablesReference": sc['variablesReference']}})
        elif msg.get('type') == 'response' and msg.get('command') == 'variables':
            vars_list = msg.get('body', {}).get('variables', [])
            # Distinguish by reference range heuristic (matching dap_server implementation: locals >=1000<2000, args>=2000)
            req_seq = msg.get('request_seq')
            # We don't have direct variablesReference here; just aggregate by name presence
            names = [v['name'] for v in vars_list]
            # Use scope names previously collected
            if any(sc['variablesReference'] >=1000 and sc['variablesReference']<2000 for sc in scopes):
                locals_vars.extend(vars_list)
            if any(sc['variablesReference']>=2000 for sc in scopes):
                param_vars.extend(vars_list)
        # Stop when we have locals & params collected
        if stopped and locals_vars and param_vars:
            break

    sock.close(); proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    local_names = {v['name'] for v in locals_vars}
    param_names = {v['name'] for v in param_vars}
    print("Collected locals:", local_names)
    print("Collected params:", param_names)

    expected_locals = {"number","pi","message"}
    expected_params = {"argc","argv"}
    missing_locals = expected_locals - local_names
    missing_params = expected_params - param_names
    if missing_locals or missing_params:
        print("❌ Missing locals:", missing_locals, "Missing params:", missing_params)
        return False
    print("✅ All expected locals and params present at line 22")
    return True

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
    # Run extended test
    success = test_locals_and_params_at_line_22()
    print(f"\nResult: {'SUCCESS' if success else 'FAILED'}")
    sys.exit(0 if success else 1)
