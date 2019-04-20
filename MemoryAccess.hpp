#pragma once
#include "Config.hpp"
#include <stddef.h>
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
    __Type MemoryReadAs(const void* Address, size_t Offset) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            if constexpr (accel::CpuFeatureSSE3Available) {
                return _mm_lddqu_si128(reinterpret_cast<const __m128i*>(reinterpret_cast<const char*>(Address) + Offset));
            } else {
                return _mm_loadu_si128(reinterpret_cast<const __m128i*>(reinterpret_cast<const char*>(Address) + Offset));
            }
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            if constexpr (accel::CpuFeatureAVXAvailable) {
                return _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(reinterpret_cast<const char*>(Address) + Offset));
            } else {
                return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(reinterpret_cast<const char*>(Address) + Offset));
            }
        } else {
            return *reinterpret_cast<const __Type*>(reinterpret_cast<const char*>(Address) + Offset);
        }
    }

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAs(const void* Address, size_t Scale, size_t Index) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            if constexpr (accel::CpuFeatureSSE3Available) {
                return _mm_lddqu_si128(reinterpret_cast<const __m128i*>(reinterpret_cast<const char*>(Address) + Scale * Index));
            } else {
                return _mm_loadu_si128(reinterpret_cast<const __m128i*>(reinterpret_cast<const char*>(Address) + Scale * Index));
            }
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            if constexpr (accel::CpuFeatureAVXAvailable) {
                return _mm256_lddqu_si256(reinterpret_cast<const __m256i*>(reinterpret_cast<const char*>(Address) + Scale * Index));
            } else {
                return _mm256_loadu_si256(reinterpret_cast<const __m256i*>(reinterpret_cast<const char*>(Address) + Scale * Index));
            }
        } else {
            return *reinterpret_cast<const __Type*>(reinterpret_cast<const char*>(Address) + Scale * Index);
        }
    }

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAsAligned(const void* Address) ACCEL_NOEXCEPT {
        return *reinterpret_cast<const __Type*>(Address);   
    }

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAsAligned(const void* Address, size_t Offset) ACCEL_NOEXCEPT {
        return *reinterpret_cast<const __Type*>(reinterpret_cast<const char*>(Address) + Offset);
    }

    template<typename __Type>
    ACCEL_NODISCARD
    ACCEL_FORCEINLINE
    __Type MemoryReadAsAligned(const void* Address, size_t Scale, size_t Index) ACCEL_NOEXCEPT {
        return *reinterpret_cast<const __Type*>(reinterpret_cast<const char*>(Address) + Scale * Index);
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAs(void* Address, const __Type& Value) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(Address), Value);
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(Address), Value);
        } else {
            *reinterpret_cast<__Type*>(Address) = Value;
        }
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAs(void* Address, size_t Offset, const __Type& Value) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(reinterpret_cast<char*>(Address) + Offset), Value);
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(reinterpret_cast<char*>(Address) + Offset), Value);
        } else {
            *reinterpret_cast<__Type*>(reinterpret_cast<char*>(Address) + Offset) = Value;
        }
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAs(void* Address, size_t Scale, size_t Index, const __Type& Value) ACCEL_NOEXCEPT {
        if constexpr (std::is_same<__Type, __m128i>::value) {
            _mm_storeu_si128(reinterpret_cast<__m128i*>(reinterpret_cast<char*>(Address) + Scale * Index), Value);
        } else if constexpr (std::is_same<__Type, __m256i>::value) {
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(reinterpret_cast<char*>(Address) + Scale * Index), Value);
        } else {
            *reinterpret_cast<__Type*>(reinterpret_cast<char*>(Address) + Scale * Index) = Value;
        }
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAsAligned(void* Address, const __Type& Value) ACCEL_NOEXCEPT {
        *reinterpret_cast<__Type*>(Address) = Value;
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAsAligned(void* Address, size_t Offset, const __Type& Value) ACCEL_NOEXCEPT {
        *reinterpret_cast<__Type*>(reinterpret_cast<char*>(Address) + Offset) = Value;
    }

    template<typename __Type>
    ACCEL_FORCEINLINE
    void MemoryWriteAsAligned(void* Address, size_t Scale, size_t Index, const __Type& Value) ACCEL_NOEXCEPT {
        *reinterpret_cast<__Type*>(reinterpret_cast<char*>(Address) + Scale * Index) = Value;
    }

}

