#pragma once
#include "rijndael.hpp"

namespace accel::Crypto {

    template<size_t __KeyBits>
    using AES_ALG = RIJNDAEL_ALG<__KeyBits, 128>;

    using AES128_ALG = AES_ALG<128>;
    using AES192_ALG = AES_ALG<192>;
    using AES256_ALG = AES_ALG<256>;

}

