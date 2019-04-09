#pragma once
#include <stddef.h>
// #include <type_traits>
#include "Intrinsic.hpp"

namespace accel {

    inline void* SecureWipe(void* p, size_t s) noexcept {
        //
        // We use RtlSecureZeroMemory implement
        //
        volatile char* vcp = reinterpret_cast<char*>(p);
#if defined(__x86_64__) || defined(_M_AMD64)
        RepeatSaveTo<char>(const_cast<char*>(vcp), 0, s);
#else
        while (s) {
            *vcp = 0;
            ++vcp;
            --s;
        }
#endif
        return p;
    }

//     template<typename __Type>
//     class SecureWiper {
//         static_assert(std::is_reference<__Type>::value == false);
//     private:
//         __Type& _Ref;
//     public:
// 
//         explicit SecureWiper(__Type& RefObject) noexcept :
//             _Ref(RefObject) {}
// 
//         ~SecureWiper() noexcept {
//             volatile char* vcp = reinterpret_cast<char*>(&_Ref);
//             size_t s = sizeof(_Ref);
//             while (s--) {
//                 *vcp = 0;
//                 ++vcp;
//             }
//         }
//     };
}

