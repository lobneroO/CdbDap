#include <iostream>
#include <vector>
#include <string>

int fibonacci(int n) {
    bool printN = false;
    if (n <= 1) {
        return n;
    }
    if(printN) {
        std::cout << std::to_string(n) << std::endl;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

int main(int argc, char** argv) {
    std::cout << "C++ Debug Test Program" << std::endl;
    
    // Test variables of different types
    int number = 42;
    double pi = 3.14159;
    std::string message = "Hello, Debugger!";
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    int* numbersPtr = new int[5];
    int numbersArr[] = {2, 4, 8, 16, 32};
    int twoDim[2][2] = {{1, 2}, {4, 8}};
    for (int i = 0; i < 5; i++) {
        numbersPtr[i] = i % 2 == 0 ? numbers[i] : numbersArr[i];
    }
    
    std::cout << "Number: " << number << std::endl;
    std::cout << "Pi: " << pi << std::endl;
    std::cout << "Message: " << message << std::endl;
    
    // Print vector contents
    std::cout << "Vector contents: ";
    for (size_t i = 0; i < numbers.size(); ++i) {
        std::cout << numbers[i];
        if (i < numbers.size() - 1) {
            std::cout << ", ";
        }
    }
    std::cout << std::endl;
    
    // Test function calls and recursion
    std::cout << "Fibonacci sequence:" << std::endl;
    for (int i = 0; i < 10; ++i) {
        int fib = fibonacci(i);
        std::cout << "fib(" << i << ") = " << fib << std::endl;
    }
    
    // Test pointer and references
    int* ptr = &number;
    int& ref = number;
    
    std::cout << "Pointer value: " << *ptr << std::endl;
    std::cout << "Reference value: " << ref << std::endl;
    
    // Test loop for stepping
    int sum = 0;
    for (int i = 1; i <= 10; ++i) {
        sum += i;
        std::cout << "Sum up to " << i << ": " << sum << std::endl;
    }
    
    std::cout << "Program completed successfully!" << std::endl;
    return 0;
}
