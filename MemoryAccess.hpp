#pragma once
#include "Config.hpp"
#include "Intrinsic.hpp"
#include <type_traits>

namespace accel {

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAs(const void* Address) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            if constexpr (accel::CpuFeatureSSE3Available) {
                return _mm_lddqu_si128(reinterpret_cast<const __m128i*>(Address));
            } else {
                return _mm_loadu_si128(reinterpret_cast<const __m128i*>(Address));
            }
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            if constexpr (accel::CpuFeatureAVXAvailable) {
                return _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(Address));
            } else {
                return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Address));
            }
        } else {
            return *reinterpret_cast<const __Type*>(Address);
        }
    }

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAsAligned(const void* Address) ACCEL_NOEXCEPT {
        return *reinterpret_cast<const __Type*>(Address);   
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAs(void* Address, const __Type& Value) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            _mm_storeu_si128(reinterpret_cast<const __m128i*>(Address), Value);
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            _mm256_storeu_si256(reinterpret_cast<const __m256i*>(Address), Value);
        } else {
            *reinterpret_cast<const __Type*>(Address) = Value;
        }
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAsAligned(void* Address, const __Type& Value) ACCEL_NOEXCEPT {
        *reinterpret_cast<const __Type*>(Address) = Value;
    }

}

