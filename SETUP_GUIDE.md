# CDB DAP Implementation - Complete Setup Guide

## ?? Quick Start

### 1. Prerequisites
- Windows 10/11
- Visual Studio or Visual Studio Build Tools
- Windows Debugging Tools (includes cdb.exe)
- Python 3.7+
- CMake 3.16 or higher
- Neovim, VS Code or whatever your DAP client of choice is

### 2. Install Windows Debugging Tools
Download and install from Microsoft:
- Windows SDK (includes debugging tools)
- Or download "Debugging Tools for Windows" standalone

Ensure `cdb.exe` is in your PATH.

### 3. Verify Installationpython launcher.py --check

### 4. Start debugging
Given the neovim config in the README file, the DAP Server does not automatically start.
To do so, start up dap_server.py, then connect to the DAP Server with your client.

## ?? Development
### 1. Build Test Program
Navigate to the test_program directory and build using CMake:cd test_program
```
mkdir build
cd build
cmake ..
cmake --build . --config Debug
```
Or use the convenient build target:cd test_program
```
mkdir build
cd build
cmake ..
cmake --build . --target test_program
```

### 2. Start DAP Server and Client
As described in Quick Start, start dap_server.py as the server and then connect to it
with your DAP client of choice.

## ?? Usage Examples

### Standalone Usage# Start DAP server (for IDE communication)
python launcher.py

# Start with verbose logging
python launcher.py --verbose

# Check dependencies
python launcher.py --check
### VS Code Integration
1. Open your C++ project in VS Code
2. Copy the `.vscode` folder to your project
3. Update `launch.json` with your executable path
4. Press F5 to start debugging

### Custom Integration
The DAP server can be integrated with any DAP-compatible editor:from dap_server import DAPServer

server = DAPServer()
server.run()  # Communicates via stdin/stdout
## ?? Configuration

### Debug Configuration Example{
    "name": "Debug C++ Program",
    "type": "cdb-cpp",
    "request": "launch",
    "program": "${workspaceFolder}/test_program/build/Debug/test_program.exe",
    "args": ["arg1", "arg2"],
    "cwd": "${workspaceFolder}/test_program/build",
    "stopOnEntry": false,
    "environment": []
}
### Build Configuration
The test program uses CMake for building. Ensure your C++ program is compiled with debug information. The provided CMakeLists.txt automatically configures debug symbols:

## ?? Testing

### Run All Testspython test_dap.py
### Manual Testing
1. Build test program:cd test_program
mkdir build && cd build
cmake ..
cmake --build . --config Debug2. Start DAP server: `python launcher.py`
3. Use DAP client to send requests

### CMake Build Targets
The test program CMakeLists.txt provides several convenient targets:

- **`test_program`** - Build the executable
- **`run`** - Build and run the program
- **`clean-intermediate`** - Clean intermediate build files
- **`help-usage`** - Display usage information

Example usage:cd test_program/build
cmake --build . --target run           # Build and run
cmake --build . --target help-usage    # Show help
ctest                                   # Run tests

### Common Issues
1. **CDB not found**: Add Windows Debugging Tools to PATH
2. **Permission errors**: Run as Administrator for system debugging
3. **Symbol loading**: Ensure PDB files are available. They are expected to reside next to the .exe you're debugging.

