#!/usr/bin/env python3
"""
Test script to verify array inspection functionality
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

def test_array_inspection():
    """Test array element inspection"""
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
    
    # Set a breakpoint after the array is initialized
    print("Setting breakpoint at line 30 (after array initialization and loop)...")
    bp_result = debugger.set_breakpoint("test_program.cpp", 30)
    print(f"Breakpoint result: {bp_result}")
    
    # Continue execution to hit the breakpoint
    print("Continuing execution to hit breakpoint...")
    debugger.continue_execution()
    
    # Give it time to hit the breakpoint
    time.sleep(2)
    
    # Check if we're at a breakpoint
    event = debugger.check_for_events()
    if event and event.get('type') == 'stopped':
        print("✓ Hit breakpoint successfully")
        
        # Get local variables to find the array
        print("\nGetting local variables...")
        locals_vars = debugger.get_local_variables()
        
        print(f"Found {len(locals_vars)} local variables:")
        for var in locals_vars:
            print(f"  {var.name}: {var.value} (type: {var.type}, container: {var.is_container})")
            if var.is_container and var.container_type == 'array':
                print(f"    └─ Container type: {var.container_type}, size: {var.container_size}")
        
        # Look for the numbersArr array specifically
        array_var = None
        for var in locals_vars:
            if 'numbersArr' in var.name or ('arr' in var.name.lower() and var.is_container):
                array_var = var
                break
        
        if array_var:
            print(f"\n✓ Found array variable: {array_var.name}")
            print(f"  Type: {array_var.type}")
            print(f"  Is container: {array_var.is_container}")
            print(f"  Container type: {array_var.container_type}")
            print(f"  Container size: {array_var.container_size}")
            
            # Try to get array elements
            print(f"\nGetting elements from array '{array_var.name}'...")
            expected_size = 5  # numbersArr has 5 elements: {2, 4, 8, 16, 32}
            elements = debugger.get_container_elements(array_var.name, 'array', expected_size)
            
            if elements:
                print(f"✓ Successfully retrieved {len(elements)} array elements:")
                for element in elements:
                    print(f"  {element.name}: {element.value} (type: {element.type})")
                
                # Verify the expected values
                expected_values = ['2', '4', '8', '16', '32']
                if len(elements) == len(expected_values):
                    all_correct = True
                    for i, (element, expected) in enumerate(zip(elements, expected_values)):
                        if element.value != expected:
                            print(f"✗ Element {i} mismatch: expected {expected}, got {element.value}")
                            all_correct = False
                    
                    if all_correct:
                        print("✓ All array elements have correct values!")
                    else:
                        print("✗ Some array elements have incorrect values")
                else:
                    print(f"✗ Expected {len(expected_values)} elements, got {len(elements)}")
            else:
                print("✗ Failed to retrieve any array elements")
        else:
            print("✗ Could not find numbersArr or any array variable")
            print("Available variables:")
            for var in locals_vars:
                print(f"  - {var.name} (container: {var.is_container})")
    else:
        print("✗ Failed to hit breakpoint")
        if event:
            print(f"Event received: {event}")
    
    # Clean up
    debugger.terminate()
    return True

if __name__ == "__main__":
    print("Testing array inspection functionality...")
    try:
        success = test_array_inspection()
        if success:
            print("\nArray inspection test completed.")
        else:
            print("\nArray inspection test failed.")
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()