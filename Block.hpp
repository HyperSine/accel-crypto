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

        template<typename __Dummy = typename std::enable_if<__Length == 1>::type>
        operator __Type&() ACCEL_NOEXCEPT {
            return Unit[0];
        }

        template<typename __Dummy = typename std::enable_if<__Length == 1>::type>
        operator const __Type&() const ACCEL_NOEXCEPT {
            return Unit[0];
        }

        template<typename __Dummy = typename std::enable_if<__Length == 1>::type>
        Block<__Type, __Length, __AlignSize>& operator=(const __Type& Other) ACCEL_NOEXCEPT {
            Unit[0] = Other;
            return *this;
        }

        Block<__Type, __Length, __AlignSize>& operator=(const Block<__Type, __Length, __AlignSize>&) ACCEL_NOEXCEPT = default;
        Block<__Type, __Length, __AlignSize>& operator=(Block<__Type, __Length, __AlignSize>&&) ACCEL_NOEXCEPT = default;

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize>& operator=(const Block<__Type, __Length, __OtherAlignSize>& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                Unit[i] = Other.Unit[i];
            }
            return *this;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize>& operator=(Block<__Type, __Length, __OtherAlignSize>&& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                Unit[i] = std::move(Other.Unit[i]);
            }
            return *this;
        }

        constexpr __Type& operator[](size_t Index) ACCEL_NOEXCEPT {
            return Unit[Index];
        }

        constexpr const __Type& operator[](size_t Index) const ACCEL_NOEXCEPT {
            return Unit[Index];
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize>& operator&=(const Block<__Type, __Length, __OtherAlignSize>& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_and_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_and_si256(Unit[i], Other.Unit[i]);
                } else {
                    Unit[i] &= Other.Unit[i];
                }
            }

            return *this;
        }

        Block<__Type, __Length, __AlignSize>& operator&=(const CArrayType& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_and_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_and_si256(Unit[i], Other[i]);
                } else {
                    Unit[i] &= Other[i];
                }
            }

            return *this;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize> operator&(const Block<__Type, __Length, __OtherAlignSize>& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_and_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_and_si256(Unit[i], Other.Unit[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] & Other.Unit[i];
                }
            }

            return RetVal;
        }

        Block<__Type, __Length, __AlignSize> operator&(const CArrayType& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_and_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_and_si256(Unit[i], Other[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] & Other[i];
                }
            }

            return RetVal;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize>& operator|=(const Block<__Type, __Length, __OtherAlignSize>& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_or_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_or_si256(Unit[i], Other.Unit[i]);
                } else {
                    Unit[i] |= Other.Unit[i];
                }
            }

            return *this;
        }

        Block<__Type, __Length, __AlignSize>& operator|=(const CArrayType& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_or_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_or_si256(Unit[i], Other[i]);
                } else {
                    Unit[i] |= Other[i];
                }
            }

            return *this;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize> operator|(const Block<__Type, __Length, __OtherAlignSize>& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_or_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_or_si256(Unit[i], Other.Unit[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] | Other.Unit[i];
                }
            }

            return RetVal;
        }

        Block<__Type, __Length, __AlignSize> operator|(const CArrayType& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_or_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_or_si256(Unit[i], Other[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] | Other[i];
                }
            }

            return RetVal;
        }

        Block<__Type, __Length, __AlignSize>& operator~() ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_xor_si128(Unit[i], _mm_set1_epi32(-1));
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_xor_si256(Unit[i], _mm256_set1_epi32(-1));
                } else {
                    Unit[i] ^= ~Unit[i];
                }
            }

            return *this;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize>& operator^=(const Block<__Type, __Length, __OtherAlignSize>& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_xor_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_xor_si256(Unit[i], Other.Unit[i]);
                } else {
                    Unit[i] ^= Other.Unit[i];
                }
            }

            return *this;
        }

        Block<__Type, __Length, __AlignSize>& operator^=(const CArrayType& Other) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    Unit[i] = _mm_xor_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    Unit[i] = _mm256_xor_si256(Unit[i], Other[i]);
                } else {
                    Unit[i] ^= Other[i];
                }
            }

            return *this;
        }

        template<size_t __OtherAlignSize>
        Block<__Type, __Length, __AlignSize> operator^(const Block<__Type, __Length, __OtherAlignSize>& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_xor_si128(Unit[i], Other.Unit[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_xor_si256(Unit[i], Other.Unit[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] ^ Other.Unit[i];
                }
            }

            return RetVal;
        }

        Block<__Type, __Length, __AlignSize> operator^(const CArrayType& Other) const ACCEL_NOEXCEPT {
            Block<__Type, __Length, __AlignSize> RetVal;

            for (size_t i = 0; i < __Length; ++i) {
                if constexpr (std::is_same<__m128i, __Type>::value) {
                    RetVal.Unit[i] = _mm_xor_si128(Unit[i], Other[i]);
                } else if constexpr (std::is_same<__m256i, __Type>::value) {
                    RetVal.Unit[i] = _mm256_xor_si256(Unit[i], Other[i]);
                } else {
                    RetVal.Unit[i] = Unit[i] ^ Other[i];
                }
            }

            return RetVal;
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

