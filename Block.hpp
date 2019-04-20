#pragma once
#include "Config.hpp"
#include <stddef.h>
#include <memory.h>
#include "SecureWiper.hpp"
#include "MemoryAccess.hpp"

namespace accel {

    template<typename __Type, size_t __Length, size_t __AlignSize = sizeof(__Type)>
    struct alignas(__AlignSize) Block {
        using UnitType = __Type;
        using CArrayType = __Type[__Length];
        static constexpr size_t SizeValue = sizeof(CArrayType);
        static constexpr size_t LengthValue = __Length;

        __Type Unit[__Length];

        constexpr size_t Size() const ACCEL_NOEXCEPT {
            return SizeValue;
        }

        constexpr size_t Length() const ACCEL_NOEXCEPT {
            return LengthValue;
        }

        constexpr __Type& operator[](size_t Index) ACCEL_NOEXCEPT {
            return Unit[Index];
        }

        constexpr const __Type& operator[](size_t Index) const ACCEL_NOEXCEPT {
            return Unit[Index];
        }

        CArrayType& AsCArray() ACCEL_NOEXCEPT {
            return Unit;
        }

        const CArrayType& AsCArray() const ACCEL_NOEXCEPT {
            return Unit;
        }

        template<typename __NewCArrayType>
        __NewCArrayType& AsCArrayOf() ACCEL_NOEXCEPT {
            return reinterpret_cast<__NewCArrayType&>(Unit);
        }

        template<typename __NewCArrayType>
        __NewCArrayType& AsCArrayOf() const ACCEL_NOEXCEPT {
            return reinterpret_cast<__NewCArrayType&>(Unit);
        }

        template<Endianness __UnitEndiannessInMemory>
        Block<__Type, __Length, __AlignSize>& LoadFrom(const void* Address) ACCEL_NOEXCEPT {
            if constexpr (__UnitEndiannessInMemory == accel::NativeEndianness) {
                memcpy(Unit, Address, SizeValue);
            } else {    // when endianness is not same, we need byteswap
                for (size_t i = 0; i < LengthValue; ++i)
                    Unit[i] = ByteSwap<__Type>(MemoryReadAs<__Type>(Address, sizeof(__Type), i));
            }
            return *this;
        }

        template<Endianness __UnitEndiannessInMemory>
        const Block<__Type, __Length, __AlignSize>& StoreTo(void* Address) const ACCEL_NOEXCEPT {
            if constexpr (__UnitEndiannessInMemory == accel::NativeEndianness) {
                memcpy(Address, Unit, SizeValue);
            } else {
                for (size_t i = 0; i < LengthValue; ++i)
                    MemoryWriteAs<__Type>(Address, sizeof(__Type), i, ByteSwap<__Type>(Unit[i]));
            }
            return *this;
        }

        void SecureZero() volatile ACCEL_NOEXCEPT {
            SecureWipe(const_cast<CArrayType&>(Unit), SizeValue);
        }
    };

}

