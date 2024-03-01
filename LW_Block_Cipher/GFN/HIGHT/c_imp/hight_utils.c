#include "hight_utils.h"

void stringToByte(u8* byteArray, const char* hexString) {
    size_t length = strlen(hexString);
    for (size_t i = 0; i < length; i+=2) {
        sscanf(&hexString[i], "%2hhx", &byteArray[(length / 2 - 1) - (i / 2)]);
    }
}

u64 measure_cycles(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    u32 ui;
    u64 start, end;
    const u64 num = 10000;
    func(dst, src, MK);

    // Measure the start time
    start = __rdtscp(&ui); // Serializing read of time stamp counter

    // Execute the function being measured
    for (u64 i = 0; i < num; i++)
        func(dst, src, MK);

    // Measure the end time
    end = __rdtscp(&ui); // Another serializing read

    return (end - start) / num; // Return the difference, which is the cycle count
}

#if 0
u64 measure_keySchedule_cycle(void (*func)(u8*, u8*, const u8*), u8* WK, u8* SK, const u8* MK) {
    u64 start, end;
    const u64 num_runs = 10000;
    func(WK, SK, MK);

    start = rdtsc();
    for (int i = 0; i < num_runs; i++)
        func(WK, SK, MK);
    end = rdtsc();
    
    return (end - start) / num_runs;
}

double measure_keySchedule_time(void (*func)(u8*, u8*, const u8*), u8* WK, u8* SK, const u8* MK) {
    struct timespec start, end;
    double cpu_time_used;
    const double num_runs = 10000;
    
    func(WK, SK, MK);
    clock_gettime(1, &start);
    for (int i = 0; i < num_runs; i++) {
        func(WK, SK, MK);
    }
    clock_gettime(1, &end);
    
    cpu_time_used = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    return cpu_time_used / num_runs;
}

u64 measure_encryption_cycle(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    u64 start, end;
    const u64 num_runs = 10000;
    func(dst, src, MK);

    start = rdtsc();
    for (int i = 0; i < num_runs; i++)
        func(dst, src, MK);
    end = rdtsc();
    
    return (end - start) / num_runs;
}

double measure_encryption_time(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    struct timespec start, end;
    double cpu_time_used;
    const double num_runs = 10000;
    
    func(dst, src, MK);
    clock_gettime(1, &start);
    for (int i = 0; i < num_runs; i++) {
        func(dst, src, MK);
    }
    clock_gettime(1, &end);
    
    cpu_time_used = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    return cpu_time_used / num_runs;
}

// Function to measure CPU time used by a function
void measure_cpu_time(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    struct timespec start, end;
    const long num_runs = 10000;

    func(dst, src, MK);
    // Start time
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);

    // Call the function
    for (i32 i = 0; i < num_runs; i++) {
        func(dst, src, MK);
    }

    // End time
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    // Calculate and print the CPU time used in nanoseconds
    long ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    printf("CPU time used: %ld ns\n", ns / num_runs);
}

// Function to measure memory usage of a function
void measure_memory_usage(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    struct rusage usage_start, usage_end;
    const long num_runs = 10000;
    
    func(dst, src, MK);
    // Start memory usage
    getrusage(RUSAGE_SELF, &usage_start);

    // Call the function
    for (i32 i = 0; i < num_runs; i++) {
        func(dst, src, MK);
    }
    // End memory usage
    getrusage(RUSAGE_SELF, &usage_end);

    // Calculate and print the memory used in kilobytes
    long mem_used = usage_end.ru_maxrss - usage_start.ru_maxrss; // This is the resident set size; it might not change for small allocations
    printf("Memory used: %ld KB\n", mem_used / num_runs);
}

static size_t total_allocated = 0;
static size_t total_freed = 0;

void* custom_malloc(size_t size) {
    total_allocated += size;
    return malloc(size);
}

void custom_free(void* ptr, size_t size) {
    if (ptr != NULL) {
        total_freed += size;
        free(ptr);
    }
}

char* base_stack_address;

void start_stack_measure() {
    char stack;
    base_stack_address = &stack;
}

size_t end_stack_measure() {
    char stack;
    return base_stack_address - &stack; // Calculate the difference
}

void measure_total_memory_usage(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK) {
    // Static memory - calculated manually or via linker map
    // size_t static_memory = calculate_static_memory();  // Implement this based on your data
    size_t static_memory = 0;

    // Dynamic memory - reset counters
    total_allocated = 0;
    total_freed = 0;

    // Stack memory - measure
    start_stack_measure();
    func(dst, src, MK);  // Call the target function
    size_t stack_memory = end_stack_measure();

    // Dynamic memory used
    size_t dynamic_memory = total_allocated - total_freed;

    // Total estimated memory usage
    size_t total_memory = static_memory + dynamic_memory + stack_memory;
    printf("Total memory used: Static = %zu, Dynamic = %zu, Stack = %zu, Total = %zu bytes\n", 
            static_memory, dynamic_memory, stack_memory, total_memory);
}
#endif