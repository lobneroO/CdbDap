#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdb_wrapper import EnhancedCdbDebugger
import time

def test_argc_argv():
    """Test debugging with argc/argv parameters"""
    
    program_path = r"C:\Users\lobner\Dev\CdbDap\test_program\build\Debug\test_program_with_args.exe"
    
    # Check if the program exists
    if not os.path.exists(program_path):
        print(f"Error: Test program not found at {program_path}")
        return False
    
    print(f"Starting debug session with: {program_path}")
    
    try:
        # Create debugger instance
        debugger = EnhancedCdbDebugger()
        
        # Start debugging the program
        debugger.start(program_path)
        
        print("Setting breakpoint at main function...")
        # Set breakpoint at the main function (approximate line number)
        debugger.set_breakpoint(r"C:\Users\lobner\Dev\CdbDap\test_program\test_program_with_args.cpp", 5)
        
        print("Continuing to main...")
        debugger.continue_execution()
        
        # Wait a bit for the program to reach the breakpoint
        time.sleep(1)
        
        print("Getting stack frames...")
        frames = debugger.get_stack_trace()
        
        if frames:
            current_frame = frames[0]
            print(f"Current frame: {current_frame.name}")
            
            # Test getting arguments (should include argc and argv)
            print("\n=== ARGUMENTS ===")
            args = debugger.get_arguments()
            for arg in args:
                print(f"  {arg.name} ({arg.type if arg.type else 'unknown'}) = {arg.value} [parameter: {arg.is_parameter}]")
            
            print(f"\nFound {len(args)} function arguments")
            
            # Check specifically for argc and argv
            arg_names = [arg.name for arg in args]
            if 'argc' in arg_names:
                print("✓ Found argc parameter")
            else:
                print("✗ argc parameter NOT found")
                
            if 'argv' in arg_names:
                print("✓ Found argv parameter")
            else:
                print("✗ argv parameter NOT found")
            
            # Test getting local variables
            print("\n=== LOCAL VARIABLES ===")
            locals_vars = debugger.get_local_variables()
            for var in locals_vars:
                print(f"  {var.name} ({var.type if var.type else 'unknown'}) = {var.value} [parameter: {var.is_parameter}]")
            
            print(f"\nFound {len(locals_vars)} local variables")
            
            # Check for previously missing variables
            local_names = [var.name for var in locals_vars]
            missing_vars = ['numLoaded', 'index', 'numbers', 'message']
            for var_name in missing_vars:
                if var_name in local_names:
                    print(f"✓ Found local variable: {var_name}")
                else:
                    print(f"✗ Local variable NOT found: {var_name}")
            
            # Test raw CDB output for debugging
            print("\n=== RAW CDB OUTPUT ===")
            raw_output = debugger.send_command("dv /t /v /i")
            print("Raw dv output preview:")
            print(raw_output[:500] + "..." if len(raw_output) > 500 else raw_output)
            
        else:
            print("No stack frames found!")
            return False
            
    except Exception as e:
        print(f"Error during debugging: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        try:
            debugger.cleanup()
        except:
            pass
    
    return True

if __name__ == "__main__":
    test_argc_argv()