#include "hight_config.h"

#ifndef _HIGHT_UTILS_H
#define _HIGHT_UTILS_H

// Read Time-Stamp Counter
// static inline u64 rdtsc(void) {
//     u32 lo, hi;
    
//     __asm__ __volatile__ (
//       "rdtsc" : "=a" (lo), "=d" (hi)
//     );
    
//     return ((u64)hi << 32) | lo;
// }

static inline void assign_rand(u8* dst, size_t wordLen) {
    // Cast the destination pointer to a pointer to u8 (unsigned 8-bit integer)
    u8* p = (u8*)dst;
    
    // Calculate the total number of bytes to be filled
    u32 cnt = wordLen * sizeof(u8);

    // Loop until all bytes are filled
    while (cnt > 0) {
        *p = rand() & 0xff; // Assign a random byte (0 to 255) to the current location pointed by p
        p++;                // Move to the next byte
        cnt--;
    }
}

void stringToByte(u8* byteArray, const char* hexString);

u64 measure_cycles(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);

// u64 measure_keySchedule_cycle(void (*func)(u8*, u8*, const u8*), u8* WK, u8* SK, const u8* MK);
// double measure_keySchedule_time(void (*func)(u8*, u8*, const u8*), u8* WK, u8* SK, const u8* MK);

// u64 measure_encryption_cycle(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);
// double measure_encryption_time(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);

// void measure_cpu_time(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);
// void measure_memory_usage(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);

// void* custom_malloc(size_t size);
// void custom_free(void* ptr, size_t size);
// void start_stack_measure();
// size_t end_stack_measure();
// void measure_total_memory_usage(void (*func)(u8*, const u8*, const u8*), u8* dst, const u8* src, const u8* MK);

#endif /* _HIGHT_UTILS_H */