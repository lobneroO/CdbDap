#include <iostream>

int main(int argc, char* argv[]) {
    std::cout << "Program started with " << argc << " arguments:" << std::endl;
    
    for (int i = 0; i < argc; i++) {
        std::cout << "argv[" << i << "] = " << argv[i] << std::endl;
    }
    
    // Add some local variables for testing
    int local_var1 = 100;
    const char* local_var2 = "This is a local variable";
    
    std::cout << "Local variable 1: " << local_var1 << std::endl;
    std::cout << "Local variable 2: " << local_var2 << std::endl;
    
    return 0;
}