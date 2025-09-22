# CDB DAP Implementation - Complete Setup Guide

This directory contains a complete Debug Adapter Protocol (DAP) implementation for C++ debugging using Microsoft's Console Debugger (CDB).

## ??? Architecture Overview

The implementation consists of several key components:

### Core Components
- **`dap_server.py`** - Main DAP protocol server
- **`cdb_wrapper.py`** - Enhanced CDB interface with better parsing
- **`launcher.py`** - Convenient launcher with dependency checking
- **`test_dap.py`** - Comprehensive test suite

### Configuration Files
- **`.vscode/launch.json`** - VS Code debug configurations
- **`.vscode/tasks.json`** - Build task for C++ compilation
- **`package.json`** - VS Code extension manifest

### Test Files
- **`test_program/`** - Test program directory
  - **`test_program.cpp`** - Sample C++ program for testing
  - **`CMakeLists.txt`** - CMake build configuration

## ?? Quick Start

### 1. Prerequisites
- Windows 10/11
- Visual Studio or Visual Studio Build Tools
- Windows Debugging Tools (includes cdb.exe)
- Python 3.7+
- CMake 3.16 or higher
- VS Code (optional, for IDE integration)

### 2. Install Windows Debugging Tools
Download and install from Microsoft:
- Windows SDK (includes debugging tools)
- Or download "Debugging Tools for Windows" standalone

Ensure `cdb.exe` is in your PATH.

### 3. Verify Installationpython launcher.py --check
### 4. Build Test Program
Navigate to the test_program directory and build using CMake:cd test_program
mkdir build
cd build
cmake ..
cmake --build . --config Debug
Or use the convenient build target:cd test_program
mkdir build
cd build
cmake ..
cmake --build . --target test_program
### 5. Test the Implementationpython test_dap.py
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

**For Visual Studio/MSVC:**set(CMAKE_CXX_FLAGS_DEBUG "/Zi /EHsc /Od /MDd /RTC1")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG")
**For manual compilation:**cl.exe /Zi /EHsc test_program.cpp
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
### Test Coverage
- ? Initialize/Launch/Attach
- ? Breakpoint management
- ? Stack trace inspection
- ? Variable examination
- ? Expression evaluation
- ? Step debugging (over/into/out)
- ? Thread management
- ? Event handling

## ?? File StructureCdbDap/
??? dap_server.py           # Main DAP server
??? cdb_wrapper.py          # Enhanced CDB interface
??? launcher.py             # Launcher script
??? test_dap.py            # Test suite
??? requirements.txt       # Python dependencies
??? README.md              # Documentation
??? SETUP_GUIDE.md         # This file
??? package.json           # VS Code extension
??? .vscode/
?   ??? launch.json        # Debug configurations
?   ??? tasks.json         # Build tasks
??? test_program/
    ??? test_program.cpp   # Sample C++ program
    ??? CMakeLists.txt     # CMake configuration
    ??? build/             # Build output directory (created during build)
## ?? Debugging the Debugger

### Log Files
- `dap_debug.log` - DAP server debug information
- Check VS Code Debug Console for client-side issues

### Common Issues
1. **CDB not found**: Add Windows Debugging Tools to PATH
2. **Permission errors**: Run as Administrator for system debugging
3. **Symbol loading**: Ensure PDB files are available
4. **Breakpoints not hit**: Verify source paths and compilation flags
5. **CMake not found**: Install CMake and add to PATH

### Verbose Loggingpython launcher.py --verbose --log-file debug.log
## ?? Features Implemented

### DAP Protocol Support
- ? Complete DAP message handling
- ? Request/Response/Event pattern
- ? JSON message format
- ? Content-Length headers

### Debugging Features
- ? Launch and attach to processes
- ? Source-level debugging
- ? Breakpoint management
- ? Stack frame navigation
- ? Local variable inspection
- ? Expression evaluation
- ? Step debugging controls
- ? Multi-threading support

### CDB Integration
- ? CDB process management
- ? Command/response handling
- ? Output parsing and interpretation
- ? Error handling and recovery
- ? Event detection (breakpoints, exceptions)

### Build System
- ? CMake-based build system
- ? Cross-platform compatibility (Windows/Linux)
- ? Automatic debug symbol generation
- ? Multiple build configurations (Debug/Release/RelWithDebInfo)
- ? Parallel compilation support
- ? Custom build targets

## ?? Extending the Implementation

### Adding New Features
1. Extend `DAPServer` class with new request handlers
2. Add corresponding CDB functionality to `EnhancedCdbDebugger`
3. Update capabilities in `DAPServer.__init__()`
4. Add tests to `test_dap.py`

### Custom CDB Commandsdef custom_command(self, cmd: str) -> str:
    return self.communicator.send_command(cmd)
### Additional Parsing
Extend `CdbOutputParser` with new regex patterns and parsing methods.

### Custom Build Configurations
Modify `test_program/CMakeLists.txt` to add custom compiler flags or targets:
# Custom debug configuration
set(CMAKE_CXX_FLAGS_CUSTOM_DEBUG "-g -O0 -DDEBUG_VERBOSE")

# Custom target
add_custom_target(debug-verbose
    COMMAND test_program --verbose
    DEPENDS test_program
    COMMENT "Running test_program in verbose mode"
)
## ?? References
- [Debug Adapter Protocol](https://microsoft.github.io/debug-adapter-protocol/)
- [CDB Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/cdb-command-line-options)
- [VS Code Debugging](https://code.visualstudio.com/docs/editor/debugging)
- [CMake Documentation](https://cmake.org/documentation/)

## ?? Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Submit a pull request

## ?? License
This implementation is provided as-is for educational and development purposes.

---

? **You now have a complete DAP implementation for C++ debugging with CDB!**

Start by running `python launcher.py --check` to verify everything is set up correctly, then build the test program with CMake.