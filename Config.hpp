#pragma once

#if defined(_MSC_VER)
    #define ACCEL_FORCEINLINE __forceinline
    #define ACCEL_UNREACHABLE() __assume(0)
#elif defined(__GNUC__)
    #define ACCEL_FORCEINLINE __attribute__((always_inline)) inline
    #define ACCEL_UNREACHABLE() __builtin_unreachable()
#else
#error "Unknown compiler"
#endif
