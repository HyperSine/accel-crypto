#pragma once
#include "rijndael.hpp"

namespace accel::Crypto {

    template<size_t __KeyBits>
    using AES_ALG = RIJNDAEL_ALG<__KeyBits, 128>;

}

