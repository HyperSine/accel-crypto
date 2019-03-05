#pragma once

#if defined(_MSC_VER)
    #define ACCEL_FORCEINLINE __forceinline
    #define ACCEL_UNREACHABLE() __assume(0)
    #define ACCEL_SSE2_AVAILABLE (_M_IX86_FP >= 2 || _M_AMD64)
    #define ACCEL_AVX2_AVALIABLE __AVX2__
#elif defined(__GNUC__)
    #define ACCEL_FORCEINLINE __attribute__((always_inline)) inline
    #define ACCEL_UNREACHABLE() __builtin_unreachable()
    #define ACCEL_SSE2_AVAILABLE __SSE2__
    #define ACCEL_AVX2_AVALIABLE __AVX2__
#else
#error "Unknown compiler"
#endif
