#pragma once

#if defined(_MSC_VER)
    #define ACCEL_FORCEINLINE __forceinline
    #define ACCEL_UNREACHABLE() __assume(0)

    #define ACCEL_SSE2_AVAILABLE (_M_IX86_FP >= 2 || _M_AMD64)
    #define ACCEL_SSE3_AVAILABLE ACCEL_SSE2_AVAILABLE
    #define ACCEL_SSSE3_AVAILABLE ACCEL_SSE2_AVAILABLE
    #define ACCEL_AESNI_AVAILABLE ACCEL_SSE2_AVAILABLE
    #define ACCEL_AVX_AVAILABLE __AVX__
    #define ACCEL_AVX2_AVAILABLE __AVX2__
#elif defined(__GNUC__)
    #define ACCEL_FORCEINLINE __attribute__((always_inline)) inline
    #define ACCEL_UNREACHABLE() __builtin_unreachable()

    #define ACCEL_SSE2_AVAILABLE __SSE2__
    #define ACCEL_SSE3_AVAILABLE __SSE3__
    #define ACCEL_SSSE3_AVAILABLE __SSSE3__
    #define ACCEL_AESNI_AVAILABLE __AES__
    #define ACCEL_AVX_AVAILABLE __AVX__
    #define ACCEL_AVX2_AVAILABLE __AVX2__
#else
#error "Unknown compiler"
#endif

#define ACCEL_NODISCARD [[nodiscard]]
#define ACCEL_DEPRECATED(msg) [[deprecated(msg)]]

namespace accel {

#if ACCEL_SSE2_AVAILABLE
    constexpr bool CpuFeatureSSE2Available = true;
#else
    constexpr bool CpuFeatureSSE2Available = false;
#endif

#if ACCEL_SSE3_AVAILABLE
    constexpr bool CpuFeatureSSE3Available = true;
#else
    constexpr bool CpuFeatureSSE3Available = false;
#endif

#if ACCEL_SSSE3_AVAILABLE
    constexpr bool CpuFeatureSSSE3Available = true;
#else
    constexpr bool CpuFeatureSSSE3Available = false;
#endif

#if ACCEL_AESNI_AVAILABLE
    constexpr bool CpuFeatureAESNIAvailable = true;
#else
    constexpr bool CpuFeatureAESNIAvailable = false;
#endif

#if ACCEL_AVX_AVAILABLE
    constexpr bool CpuFeatureAVXAvailable = true;
#else
    constexpr bool CpuFeatureAVXAvailable = false;
#endif

#if ACCEL_AVX2_AVAILABLE
    constexpr bool CpuFeatureAVX2Available = true;
#else
    constexpr bool CpuFeatureAVX2Available = false;
#endif

    // +----------------------------------------+
    // |    Definitions for endianness          |
    // +----------------------------------------+
#define ACCEL_ENDIANNESS_LITTLE 1
#define ACCEL_ENDIANNESS_BIG    2

    enum class Endianness {
        LittleEndian = 1,
        BigEndian = 2
    };

#if defined(ACCEL_CONFIG_OPTION_BIG_ENDIAN)
    constexpr Endianness NativeEndianness = Endianness::BigEndian;
    #define ACCEL_ENDIANNESS_NATIVE ACCEL_ENDIANNESS_BIG
#else
    constexpr Endianness NativeEndianness = Endianness::LittleEndian;
    #define ACCEL_ENDIANNESS_NATIVE ACCEL_ENDIANNESS_LITTLE
#endif

#if defined(ACCEL_CONFIG_OPTION_DISABLE_CXX_EXCEPTION)
    constexpr bool ConfigOptionDisableCxxException = true;
    #define ACCEL_NOEXCEPT 
#else
    constexpr bool ConfigOptionDisableCxxException = false;
    #define ACCEL_NOEXCEPT noexcept
#endif

}


