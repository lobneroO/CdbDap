#include <iostream>
#include <vector>
#include <string>

int main(int argc, char* argv[]) {
    // Variables for testing
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    std::string message = "Hello World";
    int* ref = nullptr;
    int sum = 0;
    int numLoaded = 42;
    int index = 10;
    
    // Print argc and argv for verification
    std::cout << "argc: " << argc << std::endl;
    for (int i = 0; i < argc; ++i) {
        std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
    }
    
    // Simple calculation to give variables meaningful values
    for (int num : numbers) {
        sum += num;
    }
    
    std::cout << "Sum: " << sum << std::endl;
    std::cout << "Message: " << message << std::endl;
    std::cout << "NumLoaded: " << numLoaded << std::endl;
    std::cout << "Index: " << index << std::endl;
    
    return 0;
}