#pragma once
#include <stddef.h>
#include <type_traits>

namespace accel {

    template<typename __Type>
    class SecureWiper {
        static_assert(std::is_reference<__Type>::value == false);
    private:
        __Type& _Ref;
    public:

        explicit SecureWiper(__Type& RefObject) noexcept:
            _Ref(RefObject) {}

        ~SecureWiper() noexcept {
            volatile char* vcp = reinterpret_cast<char*>(&_Ref);
            size_t s = sizeof(_Ref);
            while (s--) {
                *vcp = 0;
                ++vcp;
            }
        }
    };

    inline void* SecureWipe(void* p, size_t s) noexcept {
        volatile char* vcp = reinterpret_cast<char*>(p);
        while (s--) {
            *vcp = 0;
            ++vcp;
        }
        return p;
    }
}

