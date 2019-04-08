#pragma once
#include <stddef.h>
#include <type_traits>
#include "Config.hpp"
#include "SecureWiper.hpp"

namespace accel {

    template<typename __Type, size_t... __Dimensions>
    struct ArrayTraitsOf;

    template<typename __Type, size_t __FirstDimension, size_t... __LeftDimensions>
    struct ArrayTraitsOf<__Type, __FirstDimension, __LeftDimensions...> {
        //
        // 1. "std::decay<__Type>::type == __Type" is required
        // 2. __Type can not be an array type
        //
        static_assert(std::is_same<std::decay<__Type>::type, __Type>::value);
        static_assert(std::is_array<__Type>::value == false);

        using ElementType = __Type;
        using ReducedCArrayType = typename ArrayTraitsOf<__Type, __LeftDimensions...>::CArrayType;
        using CArrayType = ReducedCArrayType[__FirstDimension];
    };

    template<typename __Type, size_t __LastDimension>
    struct ArrayTraitsOf<__Type, __LastDimension> {
        //
        // 1. "std::decay<__Type>::type == __Type" is required
        // 2. __Type can not be an array type
        //
        static_assert(std::is_same<std::decay<__Type>::type, __Type>::value);
        static_assert(std::is_array<__Type>::value == false);

        using ElementType = __Type;
        using ReducedCArrayType = ElementType;
        using CArrayType = ReducedCArrayType[__LastDimension];
    };

    template<typename __CArrayType>
    struct ArrayTraitsOf<__CArrayType> {
        //
        // 1. __CArrayType must be an array type
        // 2. __CArrayType can not be a reference type
        // 3. __CArrayType can not have "const" qualifier
        // 4. __CArrayType can not have "volatile" qualifier
        //
        static_assert(std::is_array<__CArrayType>::value);
        static_assert(std::is_reference<__CArrayType>::value == false);
        static_assert(std::is_volatile<__CArrayType>::value == false);
        static_assert(std::is_const<__CArrayType>::value == false);

        using ElementType = typename std::remove_all_extents<__CArrayType>::type;
        using ReducedCArrayType = typename std::remove_extent<__CArrayType>::type;
        using CArrayType = __CArrayType;
    };

    //
    // ArrayTraitsOf must satisfy the following assertions
    //
    static_assert(std::is_same<typename ArrayTraitsOf<int, 4, 3, 2>::ElementType, int>::value);
    static_assert(std::is_same<const typename ArrayTraitsOf<int, 4, 3, 2>::ElementType, const int>::value);
    static_assert(std::is_same<volatile typename ArrayTraitsOf<int, 4, 3, 2>::ElementType, volatile int>::value);
    static_assert(std::is_same<const volatile typename ArrayTraitsOf<int, 4, 3, 2>::ElementType, const volatile int>::value);

    static_assert(std::is_same<typename ArrayTraitsOf<int, 4, 3, 2>::ReducedCArrayType, int[3][2]>::value);
    static_assert(std::is_same<const typename ArrayTraitsOf<int, 4, 3, 2>::ReducedCArrayType, const int[3][2]>::value);
    static_assert(std::is_same<volatile typename ArrayTraitsOf<int, 4, 3, 2>::ReducedCArrayType, volatile int[3][2]>::value);
    static_assert(std::is_same<const volatile typename ArrayTraitsOf<int, 4, 3, 2>::ReducedCArrayType, const volatile int[3][2]>::value);

    static_assert(std::is_same<typename ArrayTraitsOf<int, 4, 3, 2>::CArrayType, int[4][3][2]>::value);
    static_assert(std::is_same<const typename ArrayTraitsOf<int, 4, 3, 2>::CArrayType, const int[4][3][2]>::value);
    static_assert(std::is_same<volatile typename ArrayTraitsOf<int, 4, 3, 2>::CArrayType, volatile int[4][3][2]>::value);
    static_assert(std::is_same<const volatile typename ArrayTraitsOf<int, 4, 3, 2>::CArrayType, const volatile int[4][3][2]>::value);

    static_assert(std::is_same<ArrayTraitsOf<int[4][3][2]>::ElementType, int>::value);
    static_assert(std::is_same<const ArrayTraitsOf<int[4][3][2]>::ElementType, const int>::value);
    static_assert(std::is_same<volatile ArrayTraitsOf<int[4][3][2]>::ElementType, volatile int>::value);
    static_assert(std::is_same<const volatile ArrayTraitsOf<int[4][3][2]>::ElementType, const volatile int>::value);

    static_assert(std::is_same<ArrayTraitsOf<int[4][3][2]>::ReducedCArrayType, int[3][2]>::value);
    static_assert(std::is_same<const ArrayTraitsOf<int[4][3][2]>::ReducedCArrayType, const int[3][2]>::value);
    static_assert(std::is_same<volatile ArrayTraitsOf<int[4][3][2]>::ReducedCArrayType, volatile int[3][2]>::value);
    static_assert(std::is_same<const volatile ArrayTraitsOf<int[4][3][2]>::ReducedCArrayType, const volatile int[3][2]>::value);

    static_assert(std::is_same<ArrayTraitsOf<int[4][3][2]>::CArrayType, int[4][3][2]>::value);
    static_assert(std::is_same<const ArrayTraitsOf<int[4][3][2]>::CArrayType, const int[4][3][2]>::value);
    static_assert(std::is_same<volatile ArrayTraitsOf<int[4][3][2]>::CArrayType, volatile int[4][3][2]>::value);
    static_assert(std::is_same<const volatile ArrayTraitsOf<int[4][3][2]>::CArrayType, const volatile int[4][3][2]>::value);

    //
    // An enhanced version for C-style array
    //
    template<typename __Type, size_t... __Dimensions>
    struct Array {
        using ArrayTraits = ArrayTraitsOf<__Type, __Dimensions...>;
        using ElementType = typename ArrayTraits::ElementType;
        using CArrayType = typename ArrayTraits::CArrayType;

        static_assert(std::is_pod<ElementType>::value, "Array failure! ElementType must be a POD type.");

        CArrayType _Elements;

        static constexpr size_t RankValue = std::rank<CArrayType>::value;
        static constexpr size_t SizeValue = sizeof(CArrayType);
        static constexpr size_t LengthValue = SizeValue / sizeof(ElementType);
        template<size_t __N>
        static constexpr size_t DimensionLengthValue = std::extent<CArrayType, RankValue - 1 - __N>::value;

        typename ArrayTraits::ReducedCArrayType& operator[](size_t Index) ACCEL_NOEXCEPT {
            return _Elements[Index];
        }

        const typename ArrayTraits::ReducedCArrayType& operator[](size_t Index) const ACCEL_NOEXCEPT {
            return _Elements[Index];
        }

//         volatile typename ArrayTraits::ReducedCArrayType& operator[](size_t Index) volatile ACCEL_NOEXCEPT {
//             return _Elements[Index];
//         }
// 
//         const volatile typename ArrayTraits::ReducedCArrayType& operator[](size_t Index) const volatile ACCEL_NOEXCEPT {
//             return _Elements[Index];
//         }

        Array<__Type, __Dimensions...>& LoadFrom(const CArrayType& RefArray) ACCEL_NOEXCEPT {
            memcpy(_Elements, RefArray, sizeof(CArrayType));
            return *this;
        }

        template<typename __AnyType>
        Array<__Type, __Dimensions...>& LoadFrom(const __AnyType* lpArray) ACCEL_NOEXCEPT {
            memcpy(_Elements, lpArray, sizeof(CArrayType));
            return *this;
        }

        template<typename __AnyType>
        Array<__Type, __Dimensions...>& LoadFrom(const __AnyType* lpArray, size_t cbArray) ACCEL_NOEXCEPT {
            memcpy(_Elements, lpArray, cbArray < sizeof(CArrayType) ? cbArray : sizeof(CArrayType));
            return *this;
        }

        CArrayType& StoreTo(CArrayType& RefArray) ACCEL_NOEXCEPT {
            memcpy(RefArray, _Elements, sizeof(CArrayType));
            return RefArray;
        }

        template<typename __AnyType>
        __AnyType* StoreTo(__AnyType* lpArray) ACCEL_NOEXCEPT {
            memcpy(lpArray, _Elements, sizeof(CArrayType));
            return lpArray;
        }

        template<typename __AnyType>
        __AnyType* StoreTo(__AnyType* lpArray, size_t cbArray) ACCEL_NOEXCEPT {
            memcpy(lpArray, _Elements, cbArray < sizeof(CArrayType) ? cbArray : sizeof(CArrayType));
            return lpArray;
        }

        constexpr size_t Rank() const ACCEL_NOEXCEPT {
            return RankValue;
        }

        constexpr size_t Size() const ACCEL_NOEXCEPT {
            return SizeValue;
        }

        constexpr size_t Length() const ACCEL_NOEXCEPT {
            return LengthValue;
        }

        template<size_t __N>
        constexpr size_t DimensionLength() const ACCEL_NOEXCEPT {
            return DimensionLengthValue<__N>;
        }

        typename ArrayTraits::CArrayType& AsCArray() ACCEL_NOEXCEPT {
            return _Elements;
        }

        const typename ArrayTraits::CArrayType& AsCArray() const ACCEL_NOEXCEPT {
            return _Elements;
        }

//         volatile typename ArrayTraits::CArrayType& AsCArray() volatile ACCEL_NOEXCEPT {
//             return _Elements;
//         }
// 
//         const volatile typename ArrayTraits::CArrayType& AsCArray() const volatile ACCEL_NOEXCEPT {
//             return _Elements;
//         }

        //
        // Re-interpret array as another C-style array
        //
        template<typename __NewCArrayType>
        __NewCArrayType& AsCArrayOf() ACCEL_NOEXCEPT {
            return reinterpret_cast<__NewCArrayType&>(_Elements);
        }

        //
        // Re-interpret array with "const" qualifier as another C-style array with "const" qualifier
        //
        template<typename __NewCArrayType>
        __NewCArrayType& AsCArrayOf() const ACCEL_NOEXCEPT {
            return reinterpret_cast<__NewCArrayType&>(_Elements);
        }

//         //
//         // Re-interpret array with "volatile" qualifier as another C-style array with "volatile" qualifier
//         //
//         template<typename __NewCArrayType>
//         __NewCArrayType& AsCArrayOf() volatile ACCEL_NOEXCEPT {
//             return reinterpret_cast<__NewCArrayType&>(_Elements);
//         }
// 
//         //
//         // Re-interpret array with "const volatile" qualifier as another C-style array with "const volatile" qualifier
//         //
//         template<typename __NewCArrayType>
//         __NewCArrayType& AsCArrayOf() const volatile ACCEL_NOEXCEPT {
//             return reinterpret_cast<__NewCArrayType&>(_Elements);
//         }

        //
        // Clear array with guarantee.
        //
        void SecureZero() volatile ACCEL_NOEXCEPT {
            SecureWipe(const_cast<CArrayType&>(_Elements), sizeof(_Elements));
        }
    };


}

