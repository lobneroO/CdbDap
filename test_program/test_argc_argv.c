#include <stdio.h>

int main(int argc, char* argv[]) {
    printf("Program started with %d arguments:\n", argc);
    
    int i;
    for (i = 0; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    
    // Add some local variables for testing
    int local_var1 = 100;
    const char* local_var2 = "This is a local variable";
    
    printf("Local variable 1: %d\n", local_var1);
    printf("Local variable 2: %s\n", local_var2);
    
    return 0;
}