# CDB DAP Server

A Debug Adapter Protocol (DAP) implementation for C++ debugging using Microsoft's Console Debugger (CDB).

## Overview

This implementation provides a DAP server that bridges between debug clients (like VS Code) and the Windows Console Debugger (CDB) to enable debugging of C++ applications on Windows.

## Features

- **Full DAP Support**: Implements the Debug Adapter Protocol specification
- **CDB Integration**: Uses Microsoft's CDB for actual debugging operations
- **Breakpoint Management**: Set, remove, and manage breakpoints
- **Stack Trace Inspection**: View call stacks and navigate frames
- **Variable Inspection**: Examine local and global variables
- **Step Debugging**: Step over, into, and out of functions
- **Expression Evaluation**: Evaluate expressions in the debugger context
- **Multi-threading Support**: Debug multi-threaded applications
- **CMake Build System**: Modern CMake-based build configuration

## Requirements

- Windows operating system
- Microsoft Debugging Tools for Windows (includes cdb.exe)
- Python 3.7 or higher
- CMake 3.16 or higher (for using the test_program only)
- Visual Studio Code or another DAP-compatible editor/IDE

## Installation

1. Install Microsoft Debugging Tools for Windows:
   - Download from Microsoft's website or install Windows SDK
   - Ensure `cdb.exe` is in your PATH

2. Install CMake (if you want to use test_dap.py):
   - Download from [cmake.org](https://cmake.org/download/)
   - Ensure `cmake` is in your PATH

3. Clone or download this repository

4. Install Python dependencies (optional):pip install -r requirements.txt
## Usage

### Building the Test Program

The test program is located in the `test_program/` directory and uses CMake for building:
cd test_program
mkdir build
cd build
cmake ..
cmake --build . --config Debug
This will create a debug-enabled executable with all necessary symbols for debugging.

### With VS Code

1. Copy the `.vscode` directory to your C++ project
2. Modify the `launch.json` configuration:
   - Set the correct path to your executable
   - For the test program, use: `"program": "${workspaceFolder}/test_program/build/Debug/test_program.exe"`
   - Adjust other settings as needed
3. Start debugging by pressing F5 or using the Debug menu

### Standalone Usage

Run the DAP server directly:
python dap_server.py
The server will listen for DAP messages on stdin/stdout.

## Configuration

### Launch Configuration

Example `launch.json` configuration for the test program:
{
    "name": "Debug Test Program",
    "type": "cppdbg",
    "request": "launch",
    "program": "${workspaceFolder}/test_program/build/Debug/test_program.exe",
    "args": [],
    "stopAtEntry": false,
    "cwd": "${workspaceFolder}/test_program/build",
    "environment": []
}
### Build Configuration

The test program includes a comprehensive CMakeLists.txt that handles:

- **Debug Information**: Automatically generates debug symbols (`/Zi` on MSVC, `-g` on GCC/Clang)
- **Build Types**: Debug, Release, and RelWithDebInfo configurations
- **Cross-platform**: Works on Windows (MSVC) and Linux (GCC/Clang)
- **Parallel Compilation**: Enables `/MP` flag on MSVC for faster builds

The included VS Code `tasks.json` provides build tasks using CMake:
{
    "label": "CMake Build Debug",
    "type": "shell",
    "command": "cmake",
    "args": [
        "--build", 
        "${workspaceFolder}/test_program/build",
        "--config", "Debug"
    ],
    "group": "build"
}
## Architecture

### Components

1. **DAPServer**: Main server class handling DAP protocol
2. **CdbDebugger**: Interface to CDB debugger process
3. **EnhancedCdbDebugger**: Advanced CDB wrapper with better parsing
4. **CdbOutputParser**: Parses CDB output for structured information
5. **CdbCommunicator**: Handles low-level CDB process communication

### Communication Flow
VS Code <-> DAP Protocol <-> DAPServer <-> CdbDebugger <-> CDB.exe
## Supported DAP Requests

- `initialize` - Initialize the debug adapter
- `launch` - Launch a program for debugging
- `attach` - Attach to an existing process
- `setBreakpoints` - Set/remove breakpoints
- `configurationDone` - Configuration complete
- `continue` - Continue execution
- `next` - Step over
- `stepIn` - Step into
- `stepOut` - Step out
- `pause` - Pause execution
- `threads` - Get thread list
- `stackTrace` - Get stack trace
- `scopes`
