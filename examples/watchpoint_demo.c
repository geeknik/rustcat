#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Simple program to demonstrate watchpoints
int main() {
    int counter = 0;
    int *ptr = &counter;
    
    printf("Counter address: %p\n", (void*)ptr);
    printf("Press Ctrl+C to exit\n");
    
    // Loop forever, modifying the counter value
    while (1) {
        // Increment counter
        (*ptr)++;
        
        // Print current value
        printf("Counter value: %d\n", counter);
        
        // Sleep to slow down the loop
        sleep(1);
    }
    
    return 0;
} 