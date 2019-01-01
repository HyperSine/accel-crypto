#pragma once
#include <stddef.h>
#include <stdint.h>
#include <type_traits>
#include <limits.h>

#if defined(_MSC_VER)
#include <intrin.h>

#ifdef __unreachable
#error "__unreachable has been defined."
#else
#define __unreachable() __assume(0)
#endif

namespace accel {

    //
    //  Begin ByteSwap
    //
    template<typename __IntegerType>
    __IntegerType ByteSwap(__IntegerType x) noexcept;

    template<>
    __forceinline
    int16_t ByteSwap(int16_t x) noexcept {
        return _byteswap_ushort(x);
    }

    template<>
    __forceinline
    uint16_t ByteSwap(uint16_t x) noexcept {
        return _byteswap_ushort(x);
    }

    template<>
    __forceinline
    int32_t ByteSwap(int32_t x) noexcept {
        return _byteswap_ulong(x);
    }

    template<>
    __forceinline
    uint32_t ByteSwap(uint32_t x) noexcept {
        return _byteswap_ulong(x);
    }

    template<>
    __forceinline
    int64_t ByteSwap(int64_t x) noexcept {
        return _byteswap_uint64(x);
    }

    template<>
    __forceinline
    uint64_t ByteSwap(uint64_t x) noexcept {
        return _byteswap_uint64(x);
    }

    //
    //  Begin RotateShiftLeft
    //
    template<typename __IntegerType>
    __IntegerType RotateShiftLeft(__IntegerType x, int shift) noexcept;

    template<>
    __forceinline
    int8_t RotateShiftLeft<int8_t>(int8_t x, int shift) noexcept {
        return _rotl8(x, shift);
    }

    template<>
    __forceinline
    uint8_t RotateShiftLeft<uint8_t>(uint8_t x, int shift) noexcept {
        return _rotl8(x, shift);
    }

    template<>
    __forceinline
    int16_t RotateShiftLeft<int16_t>(int16_t x, int shift) noexcept {
        return _rotl16(x, shift);
    }

    template<>
    __forceinline
    uint16_t RotateShiftLeft<uint16_t>(uint16_t x, int shift) noexcept {
        return _rotl16(x, shift);
    }

    template<>
    __forceinline
    int32_t RotateShiftLeft<int32_t>(int32_t x, int shift) noexcept {
        return _rotl(x, shift);
    }

    template<>
    __forceinline
    uint32_t RotateShiftLeft<uint32_t>(uint32_t x, int shift) noexcept {
        return _rotl(x, shift);
    }

    template<>
    __forceinline
    int64_t RotateShiftLeft<int64_t>(int64_t x, int shift) noexcept {
        return _rotl64(x, shift);
    }

    template<>
    __forceinline
    uint64_t RotateShiftLeft<uint64_t>(uint64_t x, int shift) noexcept {
        return _rotl64(x, shift);
    }

    //
    //  Begin RotateShiftRight
    //

    template<typename __IntegerType>
    __IntegerType RotateShiftRight(__IntegerType x, int shift) noexcept;

    template<>
    __forceinline
    int8_t RotateShiftRight<int8_t>(int8_t x, int shift) noexcept {
        return _rotr8(x, shift);
    }

    template<>
    __forceinline
    uint8_t RotateShiftRight<uint8_t>(uint8_t x, int shift) noexcept {
        return _rotr8(x, shift);
    }

    template<>
    __forceinline
    int16_t RotateShiftRight<int16_t>(int16_t x, int shift) noexcept {
        return _rotr16(x, shift);
    }

    template<>
    __forceinline
    uint16_t RotateShiftRight<uint16_t>(uint16_t x, int shift) noexcept {
        return _rotr16(x, shift);
    }

    template<>
    __forceinline
    int32_t RotateShiftRight<int32_t>(int32_t x, int shift) noexcept {
        return _rotr(x, shift);
    }

    template<>
    __forceinline
    uint32_t RotateShiftRight<uint32_t>(uint32_t x, int shift) noexcept {
        return _rotr(x, shift);
    }

    template<>
    __forceinline
    int64_t RotateShiftRight<int64_t>(int64_t x, int shift) noexcept {
        return _rotr64(x, shift);
    }

    template<>
    __forceinline
    uint64_t RotateShiftRight<uint64_t>(uint64_t x, int shift) noexcept {
        return _rotr64(x, shift);
    }
}

#elif defined(__GNUC__)
#include <x86intrin.h>

#ifndef __forceinline
#define __forceinline __attribute__((always_inline)) inline
#endif

#ifdef __unreachable
#error "__unreachable has been defined."
#else
#define __unreachable() __builtin_unreachable()
#endif

namespace accel {

    //
    //  Begin ByteSwap
    //
    template<typename __IntegerType>
    __forceinline
    __IntegerType ByteSwap(__IntegerType x) noexcept {
        static_assert(std::is_integral<__IntegerType>::value, "ByteSwap failure! Not a integer type.");
        static_assert(sizeof(__IntegerType) == 2 ||
                      sizeof(__IntegerType) == 4 ||
                      sizeof(__IntegerType) == 8, "ByteSwap failure! Unsupported integer type.");

        if constexpr (sizeof(__IntegerType) == 2) {
            return __builtin_bswap16(x);
        }

        if constexpr (sizeof(__IntegerType) == 4) {
            return __builtin_bswap32(x);
        }

        if constexpr (sizeof(__IntegerType) == 8) {
            return __builtin_bswap64(x);
        }

        __builtin_unreachable();
    }

    //
    //  Begin RotateShiftLeft
    //
    //  The following code will be optimized by `rol` assembly code
    //
    template<typename __IntegerType>
    __forceinline
    __IntegerType RotateShiftLeft(__IntegerType x, unsigned shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value, "RotateShiftLeft failure! Not a integer type.");
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
    __forceinline
    __IntegerType RotateShiftRight(__IntegerType x, unsigned shift) noexcept {
        static_assert(std::is_integral<__IntegerType>::value, "RotateShiftRight failure! Not a integer type.");
        shift %= sizeof(__IntegerType) * CHAR_BIT;
        if (shift == 0)
            return x;
        else
            return (x >> shift) | (x << (sizeof(__IntegerType) * 8 - shift));
    }

    //
    //  Begin AddCarry
    //
    template<typename __IntegerType>
    __forceinline
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

        __builtin_unreachable();
    }

    //
    //  Begin SubBorrow
    //
    template<typename __IntegerType>
    __forceinline
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

        __builtin_unreachable();
    }

    
}

#else
#error "Unknown compiler"
#endif



