#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdb_wrapper import EnhancedCdbDebugger

def test_argc_argv():
    """Test function to manually check if argc/argv are properly categorized"""
    
    # Initialize debugger
    debugger = EnhancedCdbDebugger()
    
    try:
        # Start debugging the test program with arguments
        test_program = os.path.join(os.path.dirname(__file__), 'test_program', 'build', 'Debug', 'test_program.exe')
        if not os.path.exists(test_program):
            print(f"Test program not found: {test_program}")
            return
            
        print(f"Starting debug session with: {test_program}")
        debugger.start(test_program, [])
        
        # Set a breakpoint at main using function name instead
        print("Setting breakpoint at main function...")
        # Use CDB command directly
        response = debugger.communicator.send_command('bp main')
        print(f"Breakpoint response: {response}")
        
        # Continue to hit the breakpoint
        print("Continuing to main...")
        debugger.continue_execution()
        
        # Get current stack frame
        print("Getting stack frames...")
        frames = debugger.get_stack_trace()
        if frames:
            print(f"Current frame: {frames[0].name}")
            
            # Get arguments
            print("\n=== ARGUMENTS ===")
            arguments = debugger.get_arguments(0)
            for arg in arguments:
                print(f"  {arg.name} ({arg.type}) = {arg.value} [parameter: {arg.is_parameter}]")
            
            # Get local variables  
            print("\n=== LOCAL VARIABLES ===")
            locals_vars = debugger.get_local_variables(0)
            for var in locals_vars:
                print(f"  {var.name} ({var.type}) = {var.value} [parameter: {var.is_parameter}]")
            
            # Get raw CDB output for comparison
            print("\n=== RAW CDB OUTPUT ===")
            raw_output = debugger.communicator.send_command('dv /t /v /i')
            print(raw_output)
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        debugger.terminate()

if __name__ == "__main__":
    test_argc_argv()