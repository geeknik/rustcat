#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global variables for testing memory inspection
int global_int = 42;
char global_string[] = "Hello, RUSTCAT!";
float global_float = 3.14159;
double global_double = 2.71828;

// Structure for testing complex memory inspection
typedef struct {
    int id;
    char name[32];
    float value;
} TestStruct;

TestStruct test_structs[3] = {
    {1, "First", 1.1},
    {2, "Second", 2.2},
    {3, "Third", 3.3}
};

// Function with predictable stack layout for testing
void test_function(int a, int b, char *c) {
    int local_var = a + b;
    char buffer[64];
    
    // Prevent buffer overflow
    strncpy(buffer, c, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf("Local var: %d, Buffer: %s\n", local_var, buffer);
}

// Recursive function for testing stack traces
int factorial(int n) {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

// Function that allocates memory
void *allocate_memory(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    // Initialize memory with a pattern for easy recognition in debugger
    memset(ptr, 0xAB, size);
    return ptr;
}

// Function that has a deliberate bug (null pointer dereference)
void crash_function() {
    int *ptr = NULL;
    *ptr = 42; // Crash here
}

int main(int argc, char *argv[]) {
    printf("RUSTCAT Test Program\n");
    printf("Global int: %d\n", global_int);
    printf("Global string: %s\n", global_string);
    
    // Allocate some memory
    char *heap_buffer = (char *)allocate_memory(128);
    sprintf(heap_buffer, "This is heap memory at %p", (void *)heap_buffer);
    
    // Call test function
    test_function(10, 20, "Test string");
    
    // Compute factorial
    int fact = factorial(5);
    printf("Factorial of 5: %d\n", fact);
    
    // Test for various memory layouts and alignments
    TestStruct *dynamic_struct = (TestStruct *)allocate_memory(sizeof(TestStruct));
    dynamic_struct->id = 42;
    strncpy(dynamic_struct->name, "Dynamic", sizeof(dynamic_struct->name) - 1);
    dynamic_struct->name[sizeof(dynamic_struct->name) - 1] = '\0';
    dynamic_struct->value = 4.2;
    
    printf("Dynamic struct: id=%d, name=%s, value=%f\n", 
           dynamic_struct->id, dynamic_struct->name, dynamic_struct->value);
    
    // Clean up
    free(heap_buffer);
    free(dynamic_struct);
    
    // Uncomment to test crash handling
    // if (argc > 1 && strcmp(argv[1], "--crash") == 0) {
    //     crash_function();
    // }
    
    printf("Test complete\n");
    return 0;
} 