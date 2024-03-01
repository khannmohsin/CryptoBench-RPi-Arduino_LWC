#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <ctype.h>
#include <unistd.h>
#include <x86intrin.h>

#ifndef _HIGHT_CONFIG_H
#define _HIGHT_CONFIG_H

typedef int8_t i8;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#endif /* _HIGHT_CONFIG_H */