#pragma once
#include <stddef.h>
#include <stdint.h>
#include <utility>
#include <type_traits>
#include <memory.h>

namespace accel {

    template<typename __Type, size_t __Length>
    class Array {
        static_assert(std::is_pod<__Type>::value, "__Type must be a POD type.");
    public:
        using ElementType = __Type;
        static constexpr size_t Length = __Length;
    private:
        ElementType _Elements[__Length];
    public:
        static constexpr size_t Size = sizeof(_Elements);

        //
        //  Begin constructor
        //
        Array() = default;

        template<typename... __Ts>
        explicit Array(__Ts&&... Args) :
            _Elements{ std::forward<__Ts>(Args)... } {}

        Array(const Array<__Type, __Length>& other) = default;

        Array(Array<__Type, __Length>&& other) noexcept = default;

        //
        //  Begin operator=
        //
        Array<__Type, __Length>& operator=(const Array<__Type, __Length>& other) = default;

        Array<__Type, __Length>& operator=(Array<__Type, __Length>&& other) noexcept = default;

        //
        //  Begin operator[]
        //
        ElementType& operator[](size_t i) noexcept {
            return _Elements[i];
        }

        const ElementType& operator[](size_t i) const noexcept {
            return _Elements[i];
        }

        //
        //  Begin GetPtr()
        //
        ElementType* GetPtr() noexcept {
            return _Elements;
        }

        const ElementType* GetPtr() const noexcept {
            return _Elements;
        }

        //
        //  Begin ToArrayOf
        //
        template<typename __NewType, size_t __NewLength>
        Array<__NewType, __NewLength> ToArrayOf() const {
            static_assert(Array<__NewType, __NewLength>::Size <= Size, "ToArrayOf failure! Overflow detected.");
            Array<__NewType, __NewLength> result;
            memcpy(result.GetPtr(), _Elements, Size);
            return result;
        }

        //
        //  Begin AsArrayOf
        //
        template<typename __NewType, size_t __NewLength>
        Array<__NewType, __NewLength>& AsArrayOf() {
            return *reinterpret_cast<Array<__NewType, __NewLength>*>(this);
        }

        template<typename __NewType, size_t __NewLength>
        const Array<__NewType, __NewLength>& AsArrayOf() const {
            return *reinterpret_cast<const Array<__NewType, __NewLength>*>(this);
        }

        //
        //  Begin destructor
        //
        ~Array() = default;
    };

    template<typename __Type, size_t __Length>
    class ArraySecureGuard {
    private:
        Array<__Type, __Length>& _ArrayInstance;
    public:
        explicit ArraySecureGuard(Array<__Type, __Length>& ref_array) noexcept :
            _ArrayInstance(ref_array) {}

        ~ArraySecureGuard() noexcept {
            volatile char* p = reinterpret_cast<char*>(&_ArrayInstance);
            size_t s = sizeof(_ArrayInstance);
            while (s--) *p++ = 0;
        }
    };

    template<typename __Type, size_t __Length>
    class SecureArray {
    private:
        ArraySecureGuard<__Type, __Length> _Guard;
        Array<__Type, __Length> _ArrayInstance;
    public:
        using ElementType = typename Array<__Type, __Length>::ElementType;
        static constexpr size_t Length = Array<__Type, __Length>::Length;
        static constexpr size_t Size = Array<__Type, __Length>::Size;

        //
        //  Begin constructor
        //
        SecureArray() noexcept :
            _Guard(_ArrayInstance) {}

        template<typename... __Ts>
        explicit SecureArray(__Ts&&... Args) :
            _Guard(_ArrayInstance),
            _ArrayInstance(std::forward<__Ts>(Args)...) {}

        SecureArray(const SecureArray<__Type, __Length>& other) :
            _Guard(_ArrayInstance),
            _ArrayInstance(static_cast<const Array<__Type, __Length>&>(other._ArrayInstance)) {}

        SecureArray(SecureArray<__Type, __Length>&& other) noexcept :
            _Guard(_ArrayInstance),
            _ArrayInstance(static_cast<Array<__Type, __Length>&&>(other._ArrayInstance)) {}

        //
        //  Begin operator=
        //
        SecureArray<__Type, __Length>&
        operator=(const SecureArray<__Type, __Length>& other) {
            _ArrayInstance = static_cast<const Array<__Type, __Length>&>(other._ArrayInstance);
        }

        SecureArray<__Type, __Length>&
        operator=(SecureArray<__Type, __Length>&& other) noexcept {
            _ArrayInstance = static_cast<Array<__Type, __Length>&&>(other._ArrayInstance);
        }

        //
        //  Begin operator[]
        //
        ElementType& operator[](size_t i) {
            return _ArrayInstance[i];
        }

        const ElementType& operator[](size_t i) const {
            return _ArrayInstance[i];
        }

        //
        //  Begin GetPtr()
        //
        ElementType* GetPtr() noexcept {
            return _ArrayInstance.GetPtr();
        }

        const ElementType* GetPtr() const noexcept {
            return _ArrayInstance.GetPtr();
        }

        //
        //  Begin ToArrayOf
        //
        template<typename __NewType, size_t __NewLength>
        Array<__NewType, __NewLength> ToArrayOf() const {
            return _ArrayInstance.template ToArrayOf<__NewType, __Length>();
        }

        //
        //  Begin AsArrayOf
        //
        template<typename __NewType, size_t __NewLength>
        Array<__NewType, __NewLength>& AsArrayOf() {
            return _ArrayInstance.template AsArrayOf<__NewType, __NewLength>();
        }

        template<typename __NewType, size_t __NewLength>
        const Array<__NewType, __NewLength>& AsArrayOf() const {
            return _ArrayInstance.template AsArrayOf<__NewType, __NewLength>();
        }

        //
        //  Begin destructor
        //
        ~SecureArray() = default;
    };

    template<size_t __Length>
    using ByteArray = Array<uint8_t, __Length>;

    template<size_t __Length>
    using SecureByteArray = SecureArray<uint8_t, __Length>;
}

