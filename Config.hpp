#pragma once

#if defined(_MSC_VER)
    #define ACCEL_FORCEINLINE __forceinline
    #define ACCEL_UNREACHABLE() __assume(0)
    #define ACCEL_SSE2_AVAILABLE (_M_IX86_FP >= 2 || _M_AMD64)
    #define ACCEL_AESNI_AVAILABLE ACCEL_SSE2_AVAILABLE
    #define ACCEL_AVX2_AVALIABLE __AVX2__
#elif defined(__GNUC__)
    #define ACCEL_FORCEINLINE __attribute__((always_inline)) inline
    #define ACCEL_UNREACHABLE() __builtin_unreachable()
    #define ACCEL_SSE2_AVAILABLE __SSE2__
    #define ACCEL_AESNI_AVAILABLE __AES__
    #define ACCEL_AVX2_AVALIABLE __AVX2__
#else
#error "Unknown compiler"
#endif

namespace accel {

#if defined(ACCEL_CONFIG_OPTION_DISABLE_CXX_EXCEPTION)
    constexpr bool ConfigOptionDisableCxxException = true;
    #define ACCEL_NOEXCEPT 
#else
    constexpr bool ConfigOptionDisableCxxException = false;
    #define ACCEL_NOEXCEPT noexcept
#endif

}


