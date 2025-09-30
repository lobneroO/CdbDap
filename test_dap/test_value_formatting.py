#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdb_wrapper import CdbOutputParser

def test_value_formatting():
    """Test the new value formatting for CDB numbers"""
    
    print("=== TESTING VALUE FORMATTING ===\n")
    
    # Sample CDB output with various number formats
    test_output = """prv local  000000ec`9fcffb00 int numLoaded = 0n42
prv local  000000ec`9fcffb08 int sum = 0n1855743806
prv local  000000ec`9fcffb10 int index = 0n10
prv local  000000ec`9fcffb18 int zero = 0n0
prv local  000000ec`9fcffb20 int * ptr = 0x00007fff`12345678
prv local  000000ec`9fcffb28 double pi = 3.14159
message = "Hello World"
invalid = 0nABC
0:000>"""

    parser = CdbOutputParser()
    variables = parser.parse_variables(test_output)
    
    print("Parsed variables with formatted values:")
    for var in variables:
        print(f"  {var.name} = {var.value}")
    
    # Test specific cases
    expected_values = {
        'numLoaded': '42',     # Should be cleaned from 0n42
        'sum': '1855743806',   # Should be cleaned from 0n1855743806  
        'index': '10',         # Should be cleaned from 0n10
        'zero': '0',           # Should be cleaned from 0n0
        'ptr': '0x00007fff`12345678',  # Hex should remain unchanged
        'pi': '3.14159',       # Decimal should remain unchanged
        'message': '"Hello World"',    # String should remain unchanged
        'invalid': '0nABC',    # Invalid 0n format should remain unchanged
    }
    
    print(f"\n=== VERIFICATION ===")
    success = True
    for var in variables:
        if var.name in expected_values:
            expected = expected_values[var.name]
            if var.value == expected:
                print(f"✅ {var.name}: '{var.value}' (correct)")
            else:
                print(f"❌ {var.name}: got '{var.value}', expected '{expected}'")
                success = False
    
    return success

if __name__ == "__main__":
    success = test_value_formatting()
    print(f"\n{'✅ SUCCESS' if success else '❌ FAILED'}: Value formatting test")