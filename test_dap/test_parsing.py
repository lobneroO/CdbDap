import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cdb_wrapper import CdbOutputParser

def test_variable_parsing():
    """Test the variable parsing with mock data"""
    
    # Sample CDB output that represents the actual format
    mock_output = """numbers = { size=4611650844328767752 }
prv local  000000ec`9fcffb00 int * ref = 0x00000000`00000000
prv local  000000ec`9fcffa60 class std::basic_string<char,std::char_traits<char>,std::allocator<char> 
> 
message = "Hello World"
prv local  000000ec`9fcffb08 int sum = 0n1855743806
numLoaded = 42
index = 10
0:000>"""

    # Create a mock CdbOutputParser to test the parsing
    parser = CdbOutputParser()
    
    # Test parse_variables method directly
    variables = parser.parse_variables(mock_output)
    
    print("Parsed variables:")
    for var in variables:
        print(f"  {var.name} ({var.type if var.type else 'unknown'}) = {var.value} [parameter: {var.is_parameter}]")
    
    # Check if we found the previously missing variables
    variable_names = [var.name for var in variables]
    
    print(f"\nFound {len(variables)} variables total")
    print(f"Variable names: {variable_names}")
    
    # Test specific cases
    missing_vars = ['numLoaded', 'index']
    for var_name in missing_vars:
        if var_name in variable_names:
            print(f"✓ Found previously missing variable: {var_name}")
        else:
            print(f"✗ Still missing variable: {var_name}")

if __name__ == "__main__":
    test_variable_parsing()