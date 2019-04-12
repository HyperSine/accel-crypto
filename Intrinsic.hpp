#pragma once
#include <stddef.h>
#include <stdint.h>
#include <type_traits>
#include <limits.h>
#include "Config.hpp"

#if defined(_MSC_VER)
#include <intrin.h>

namespace accel {

    //
    //  Begin ByteSwap
    //
    template<typename __IntegerType>
    __IntegerType ByteSwap(__IntegerType x) noexcept {
        static_assert(std::is_integral<__IntegerType>::value, 
                      "ByteSwap failure! Not a integer type.");

        if constexpr (sizeof(x) == 2) {
            return _byteswap_ushort(static_cast<uint16_t>(x));
        } else if constexpr (sizeof(x) == 4) {
            return _byteswap_ulong(static_cast<uint32_t>(x));
        } else if constexpr (sizeof(x) == 8) {
            return _byteswap_uint64(static_cast<uint64_t>(x));
        } else {
            static_assert(sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8, 
                          "ByteSwap failure! Unsupported integer type.");
            ACCEL_UNREACHABLE();
        }
    }

    //
    //  Begin RotateShiftLeft
    //
    template<typename __IntegerType>
    __IntegerType RotateShiftLeft(__IntegerType x, unsigned shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value, 
                      "RotateShiftLeft failure! Not a integer type.");

        if constexpr (sizeof(x) == 1) {
            return _rotl8(static_cast<uint8_t>(x), shift);
        } else if constexpr (sizeof(x) == 2) {
            return _rotl16(static_cast<uint16_t>(x), shift);
        } else if constexpr (sizeof(x) == 4) {
            return _rotl(static_cast<uint32_t>(x), shift);
        } else if constexpr (sizeof(x) == 8) {
            return _rotl64(static_cast<uint64_t>(x), shift);
        } else {
            static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                          "RotateShiftLeft failure! Unsupported integer type.");
            ACCEL_UNREACHABLE();
        }
    }

    //
    //  Begin RotateShiftRight
    //

    template<typename __IntegerType>
    __IntegerType RotateShiftRight(__IntegerType x, int shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "RotateShiftRight failure! Not a integer type.");

        if constexpr (sizeof(x) == 1) {
            return _rotr8(static_cast<uint8_t>(x), shift);
        } else if constexpr (sizeof(x) == 2) {
            return _rotr16(static_cast<uint16_t>(x), shift);
        } else if constexpr (sizeof(x) == 4) {
            return _rotr(static_cast<uint32_t>(x), shift);
        } else if constexpr (sizeof(x) == 8) {
            return _rotr64(static_cast<uint64_t>(x), shift);
        } else {
            static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                          "RotateShiftRight failure! Unsupported integer type.");
            ACCEL_UNREACHABLE();
        }
    }

    template<typename __IntegerType>
    void* RepeatSaveTo(void* p, __IntegerType v, size_t times) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "RepeatSaveTo failure! Not a integer type.");

        if constexpr (sizeof(__IntegerType) == 1) {
            __stosb(reinterpret_cast<unsigned char*>(p), v, times);
        }
        
        if constexpr (sizeof(__IntegerType) == 2) {
            __stosw(reinterpret_cast<unsigned short*>(p), v, times);
        }
        
        if constexpr (sizeof(__IntegerType) == 4) {
            __stosd(reinterpret_cast<unsigned long*>(p), v, times);
        }
        
#if defined(_M_X64)
        if constexpr (sizeof(__IntegerType) == 8) {
            __stosq(reinterpret_cast<unsigned __int64*>(p), v, times);
        }

        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                      "RepeatSaveTo failure! Unsupported integer type.");
#else
        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4,
                      "RepeatSaveTo failure! Unsupported integer type.");
#endif

        return p;
    }

    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    size_t PopulationCount(__IntegerType x) noexcept {
        //
        // Make sure __IntegerType is integral
        //
        static_assert(std::is_integral<__IntegerType>::value,
                      "PopulationCounter failure! Not a integer type.");
        //
        // Only 1, 2, 4, 8-bytes-long integers are supported.
        //
        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                      "PopulationCounter failure! Unsupported integer type.");

        if constexpr (sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2) {
            return __popcnt16(x);
        }

        if constexpr (sizeof(__IntegerType) == 4) {
            return __popcnt(x);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
#if defined(_M_X64)
            return __popcnt64(x);
#else
            return __popcnt(static_cast<unsigned __int32>(x)) + __popcnt(static_cast<unsigned __int32>(x >> 32));
#endif
        }

        ACCEL_UNREACHABLE();
    }
}

#elif defined(__GNUC__)
#include <x86intrin.h>

namespace accel {

    //
    //  Begin ByteSwap
    //
    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    __IntegerType ByteSwap(__IntegerType x) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "ByteSwap failure! Not a integer type.");
        static_assert(sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                      "ByteSwap failure! Unsupported integer type.");

        if constexpr (sizeof(__IntegerType) == 2) {
            return __builtin_bswap16(x);
        }

        if constexpr (sizeof(__IntegerType) == 4) {
            return __builtin_bswap32(x);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
            return __builtin_bswap64(x);
        }

        ACCEL_UNREACHABLE();
    }

    //
    //  Begin RotateShiftLeft
    //
    //  The following code will be optimized by `rol` assembly code
    //
    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    __IntegerType RotateShiftLeft(__IntegerType x, unsigned shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "RotateShiftLeft failure! Not a integer type.");
        shift %= sizeof(__IntegerType) * CHAR_BIT;
        if (shift == 0)
            return x;
        else
            return (x << shift) | (x >> (sizeof(__IntegerType) * CHAR_BIT - shift));
    }

    //
    //  Begin RotateShiftRight
    //
    //  The following code will be optimized by `ror` assembly code
    //
    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    __IntegerType RotateShiftRight(__IntegerType x, unsigned shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "RotateShiftRight failure! Not a integer type.");
        shift %= sizeof(__IntegerType) * CHAR_BIT;
        if (shift == 0)
            return x;
        else
            return (x >> shift) | (x << (sizeof(__IntegerType) * 8 - shift));
    }

    template<typename __IntegerType>
    void* RepeatSaveTo(void* p, __IntegerType v, size_t times) noexcept {
        static_assert(std::is_integral<__IntegerType>::value,
                      "RepeatSaveTo failure! Not a integer type.");

        if constexpr (sizeof(__IntegerType) == 1) {
            asm volatile("rep stosb;"
                         :
                         : "D"(p), "a"(v), "c"(times)
                         :);
        }

        if constexpr (sizeof(__IntegerType) == 2) {
            asm volatile("rep stosw;"
                         :
                         : "D"(p), "a"(v), "c"(times)
                         :);
        }

        if constexpr (sizeof(__IntegerType) == 4) {
            asm volatile("rep stosd;"
                         :
                         : "D"(p), "a"(v), "c"(times)
                         :);
        }

#if defined(_M_X64) || defined(__x86_64__)
        if constexpr (sizeof(__IntegerType) == 8) {
            asm volatile("rep stosq;"
                         :
                         : "D"(p), "a"(v), "c"(times)
                         :);
        }

        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                      "RepeatSaveTo failure! Unsupported integer type.");
#else
        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4,
                      "RepeatSaveTo failure! Unsupported integer type.");
#endif

        return p;
    }

    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    __IntegerType PopulationCount(__IntegerType x) noexcept {
        //
        // Make sure __IntegerType is integral
        //
        static_assert(std::is_integral<__IntegerType>::value,
                      "PopulationCounter failure! Not a integer type.");
        //
        // Only 1, 2, 4, 8-bytes-long integers are supported.
        //
        static_assert(sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4 || sizeof(__IntegerType) == 8,
                      "PopulationCounter failure! Unsupported integer type.");

        if constexpr (sizeof(__IntegerType) == 1 || sizeof(__IntegerType) == 2 || sizeof(__IntegerType) == 4) {
            return __builtin_popcount(x);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
            return __builtin_popcountll(x);
        }

        ACCEL_UNREACHABLE();
    }

    //
    //  Begin AddCarry
    //
    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    uint8_t AddCarry(uint8_t carry, __IntegerType a, __IntegerType b, __IntegerType* p_c) {
        static_assert(std::is_integral<__IntegerType>::value, "AddCarry failure! Not a integer type.");
        static_assert(sizeof(__IntegerType) == 4 ||
                      sizeof(__IntegerType) == 8, "AddCarry failure! Unsupported integer type.");

        if (sizeof(__IntegerType) == 4) {
            return _addcarry_u32(carry, a, b, p_c);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
#if defined(_M_X64) || defined(__x86_64__)
            return _addcarry_u64(carry, a, b, p_c);
#else
            static_assert(sizeof(__IntegerType) != 8, "AddCarry failure! Unsupported integer type.");
#endif
        }

        ACCEL_UNREACHABLE();
    }

    //
    //  Begin SubBorrow
    //
    template<typename __IntegerType>
    ACCEL_FORCEINLINE
    uint8_t SubBorrow(uint8_t borrow, __IntegerType a, __IntegerType b, __IntegerType* p_c) {
        static_assert(std::is_integral<__IntegerType>::value, "SubBorrow failure! Not a integer type.");
        static_assert(sizeof(__IntegerType) == 4 ||
                      sizeof(__IntegerType) == 8, "SubBorrow failure! Unsupported integer type.");

        if (sizeof(__IntegerType) == 4) {
            return _subborrow_u32(borrow, a, b, p_c);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
#if defined(_M_X64) || defined(__x86_64__)
            return _subborrow_u64(borrow, a, b, p_c);
#else
            static_assert(sizeof(__IntegerType) != 8, "SubBorrow failure! Unsupported integer type.");
#endif
        }

        ACCEL_UNREACHABLE();
    }

    
}

#else
#error "Unknown compiler"
#endif



