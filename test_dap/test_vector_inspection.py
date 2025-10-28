#!/usr/bin/env python3
"""
Test script to verify vector inspection functionality
"""

import os
import sys
import time

# Add parent directory to path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from cdb_wrapper import EnhancedCdbDebugger
import logging

# Configure logging to see what's happening
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_vector_inspection():
    """Test vector element inspection"""
    debugger = EnhancedCdbDebugger()
    
    # Start debugging the test program
    program_path = r"c:\Users\tim1lobn\Dev\CdbDap\test_program\build\Debug\test_program.exe"
    
    if not os.path.exists(program_path):
        print(f"Test program not found at: {program_path}")
        return False
    
    print(f"Starting debugger with program: {program_path}")
    
    if not debugger.start(program_path):
        print("Failed to start program")
        return False
    
    # Set a breakpoint where the vector is initialized
    print("Setting breakpoint at line 25 (after vector initialization)...")
    bp_result = debugger.set_breakpoint("test_program.cpp", 25)
    print(f"Breakpoint result: {bp_result}")
    
    # Continue execution to hit the breakpoint
    print("Continuing execution to hit breakpoint...")
    debugger.continue_execution()
    
    # Give it time to hit the breakpoint
    time.sleep(2)
    
    # Check if we're at a breakpoint
    event = debugger.check_for_events()
    print(f"Event after continue: {event}")
    
    # Get local variables
    print("Getting local variables...")
    variables = debugger.get_local_variables()
    
    print(f"Found {len(variables)} variables:")
    for var in variables:
        print(f"  {var.name}: {var.value} (type: {var.type}, is_container: {getattr(var, 'is_container', False)})")
        
        # If this is the numbers vector, try to expand it
        if var.name == 'numbers' and getattr(var, 'is_container', False):
            print(f"  Expanding vector {var.name} with size {getattr(var, 'container_size', 'unknown')}...")
            elements = debugger.get_container_elements(
                var.name, 
                getattr(var, 'container_type', 'vector'), 
                getattr(var, 'container_size', 0)
            )
            print(f"  Found {len(elements)} elements:")
            for elem in elements:
                print(f"    {elem.name}: {elem.value} (type: {elem.type})")
    
    # Stop the debugger
    debugger.stop()
    return True

if __name__ == "__main__":
    try:
        test_vector_inspection()
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()