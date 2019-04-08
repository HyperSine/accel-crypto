#pragma once
#include <stdint.h>

namespace accel::Crypto::Internal {

    template<size_t __WordBits>
    class RC5_CONSTANT;

    template<>
    class RC5_CONSTANT<16> {
    protected:
        using WordType = uint16_t;
        static constexpr WordType P = 0xB7E1;
        static constexpr WordType Q = 0x9E37;
    };

    template<>
    class RC5_CONSTANT<32> {
    protected:
        using WordType = uint32_t;
        static constexpr WordType P = 0xB7E15163;
        static constexpr WordType Q = 0x9E3779B9;
    };

    template<>
    class RC5_CONSTANT<64> {
    protected:
        using WordType = uint64_t;
        static constexpr WordType P = 0xB7E151628AED2A6B;
        static constexpr WordType Q = 0x9E3779B97F4A7C15;
    };

}

