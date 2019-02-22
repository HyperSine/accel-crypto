#pragma once
#include <stddef.h>
#include <stdint.h>
#include <utility>
#include <type_traits>

namespace accel {

    template<typename __Type, size_t __Length>
    class Array {
        static_assert(std::is_pod<__Type>::value, "Array failure! __Type must be a POD type.");
    public:
        using ElementType = __Type;
        using CArrayType = __Type[__Length];
        static_assert(std::is_same<CArrayType&, __Type(&)[__Length]>::value);
        static_assert(std::is_same<const CArrayType&, const __Type(&)[__Length]>::value);
    private:
        ElementType _Elements[__Length];
    public:

        static constexpr size_t LengthValue = __Length;
        static constexpr size_t SizeValue = sizeof(_Elements);

        //
        // Default constructor
        // All elements use default initialization
        //
        constexpr Array() = default;

        //
        // Variadic constructor
        // Allow initializing like c-style array
        //
        template<typename... __Ts>
        constexpr explicit Array(__Ts&&... Args) :
            _Elements{ std::forward<__Ts>(Args)... } {}

        //
        // Copy constructor
        //
        constexpr Array(const Array<__Type, __Length>&) = default;

        //
        // Move constructor
        // The move constructor for ElementType should be exception-safe
        //
        constexpr Array(Array<__Type, __Length>&&) noexcept = default;

        //
        // Copy assignment
        //
        Array<__Type, __Length>& 
        operator=(const Array<__Type, __Length>&) = default;

        //
        // Move assignment
        // The move assignment for ElementType should be exception-safe
        //
        Array<__Type, __Length>& 
        operator=(Array<__Type, __Length>&&) noexcept = default;

        //
        // Retrieve element by Index
        //
        ElementType& operator[](size_t Index) noexcept {
            return _Elements[Index];
        }

        //
        // A const version for retrieving element by Index
        //
        const ElementType& operator[](size_t Index) const noexcept {
            return _Elements[Index];
        }

        //
        // Return the length of array
        //
        constexpr size_t Length() const noexcept {
            return LengthValue;
        }

        //
        // Return the size of array
        //
        constexpr size_t Size() const noexcept {
            return SizeValue;
        }

        //
        // Return C-Style array reference
        //
        CArrayType& CArray() noexcept {
            return _Elements;
        }

        //
        // Return constant C-Style array reference
        //
        const CArrayType& CArray() const noexcept {
            return _Elements;
        }

        //
        // Cast to other array type
        // You must be aware of what you are doing
        //
        template<typename __NewType, size_t __NewLength>
        Array<__NewType, __NewLength>& AsArrayOf() {
            return *reinterpret_cast<Array<__NewType, __NewLength>*>(this);
        }

        //
        // A const version for casting to other array type
        // You must be aware of what you are doing
        //
        template<typename __NewType, size_t __NewLength>
        const Array<__NewType, __NewLength>& AsArrayOf() const {
            return *reinterpret_cast<const Array<__NewType, __NewLength>*>(this);
        }

        //
        // Clear data securely
        //
        void SecureZero() noexcept {
            volatile char* p = reinterpret_cast<char*>(_Elements);
            size_t s = sizeof(_Elements);
            while (s--) *p++ = 0;
        }
    };

}

