#include <iostream>
#include <queue>
#include <vector>
#include <string>
#include <cmath>

// Simple struct for testing member inspection
struct Point {
    int x;
    int y;
    double distance() const {
        return sqrt(x * x + y * y);
    }
};

struct Node {
    Node(int val) : val(val) {}
    Node(Node* next, int val) : next(next), val(val) {}
    Node* next = nullptr;
    int val = 0;
};

// Simple class for testing member inspection
class Rectangle {
public:
    int width;
    int height;
    Point topLeft;
    
    Rectangle(int w, int h, Point tl) : width(w), height(h), topLeft(tl) {}
    
    int area() const {
        return width * height;
    }
};

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
    
    // Test struct and class objects
    Point p1 = {10, 20};
    Point p2 = {-5, 15};
    Rectangle rect(100, 50, p1);

    Node n1(1);
    Node n2(&n1, 2);
    Node n3(&n2, 3);
    
    // Test variables of different types
    int number = 42;
    double pi = 3.14159;
    std::string message = "Hello, Debugger!";
    std::queue<std::string> stringQueue;
    stringQueue.push("first");
    stringQueue.push("second");
    stringQueue.push("third");
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
