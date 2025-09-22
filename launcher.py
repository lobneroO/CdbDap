#!/usr/bin/env python3
"""
Launcher script for the CDB DAP server.
This script provides a convenient way to start the debugger server.
"""

import sys
import os
import argparse
import subprocess
import logging


def check_dependencies():
    """Check if required dependencies are available"""
    errors = []

    # Check for CDB
    try:
        # Use -version instead of -? as it returns exit code 0
        result = subprocess.run(['cdb.exe', '-version'],
                                capture_output=True,
                                text=True,
                                timeout=5)
        if result.returncode != 0:
            # Fallback to -? and check output content
            result = subprocess.run(['cdb.exe', '-?'],
                                    capture_output=True,
                                    text=True,
                                    timeout=5)
            if 'Microsoft' not in result.stdout \
               and 'cdb' not in result.stdout.lower():
                errors.append("CDB is not working properly")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        errors.append("CDB (cdb.exe) not found in PATH. "
                      + "Please install Windows Debugging Tools.")
    except Exception as e:
        errors.append(f"Error checking CDB: {e}")

    # Check Python version
    if sys.version_info < (3, 7):
        errors.append("Python 3.7 or higher is required")

    return errors


def main():
    parser = argparse.ArgumentParser(
        description='CDB Debug Adapter Protocol Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launcher.py                    # Start DAP server (for IDE integration)
  python launcher.py --check           # Check dependencies
  python launcher.py --verbose         # Start with verbose logging
        """
    )

    parser.add_argument('--check', action='store_true',
                        help='Check dependencies and exit')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--log-file', default='dap_debug.log',
                        help='Log file path (default: dap_debug.log)')

    args = parser.parse_args()

    # Configure logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(args.log_file),
            logging.StreamHandler(sys.stderr)
        ]
    )

    logger = logging.getLogger(__name__)

    if args.check:
        print("Checking dependencies...")
        errors = check_dependencies()

        if errors:
            print("? Dependency check failed:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        else:
            print("? All dependencies are satisfied")
            print("Ready to start debugging!")
            sys.exit(0)

    # Check dependencies before starting
    errors = check_dependencies()
    if errors:
        logger.error("Dependency check failed:")
        for error in errors:
            logger.error(f"  - {error}")
        sys.exit(1)

    logger.info("Starting CDB DAP Server...")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Working directory: {os.getcwd()}")

    # Import and start the server
    try:
        from dap_server import DAPServer
        server = DAPServer()
        server.run()
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

