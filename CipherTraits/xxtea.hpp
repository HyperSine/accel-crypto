#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"

namespace accel::Crypto {

    template<size_t __N>
    class XXTEA_ALG {
        static_assert(__N >= 2);
    public:
        static constexpr size_t BlockSizeValue = __N * sizeof(uint32_t);
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        static constexpr uint32_t Delta = 0x9E3779B9;
        static constexpr size_t Rounds = 6 + 52 / __N;

//         union BlockType {
//             uint8_t bytes[__N * sizeof(uint32_t)];
//             uint32_t dwords[__N];
//         };
        using BlockType = Array<uint32_t, __N>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 4> _Key;

        ACCEL_FORCEINLINE
        uint32_t _MX(uint32_t e, uint32_t y, uint32_t z, uint32_t sum, unsigned p) const ACCEL_NOEXCEPT {
            return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (_Key[(p % 4) ^ e] ^ z));
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t y, z;
            uint32_t sum = 0;
            unsigned p, e;
            z = RefBlock[__N - 1];

            for (size_t n = 0; n < Rounds; ++n) {
                sum += Delta;
                e = (sum >> 2) % 4;
                for (p = 0; p < __N - 1; ++p) {
                    y = RefBlock[p + 1];
                    z = RefBlock[p] += _MX(e, y, z, sum, p);
                }
                y = RefBlock[0];
                z = RefBlock[__N - 1] += _MX(e, y, z, sum, p);
            }
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t y, z;
            uint32_t sum = Delta;
            unsigned p, e;
            y = RefBlock[0];
            sum *= Rounds;

            for (size_t n = 0; n < Rounds; ++n) {
                e = (sum >> 2) % 4;
                for (p = __N - 1; p > 0; --p) {
                    z = RefBlock[p - 1];
                    y = RefBlock[p] -= _MX(e, y, z, sum, p);
                }
                z = RefBlock[__N - 1];
                y = RefBlock[0] -= _MX(e, y, z, sum, p);
                sum -= Delta;
            }
        }

    public:

        constexpr size_t BlockSize() const ACCEL_NOEXCEPT {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const ACCEL_NOEXCEPT {
            return KeySizeValue;
        }

        ACCEL_NODISCARD
        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (cbUserKey != KeySizeValue) {
                return false;
            } else {
                _Key.LoadFrom(pbUserKey, KeySizeValue);
                _Key[0] = ByteSwap<uint32_t>(_Key[0]);
                _Key[1] = ByteSwap<uint32_t>(_Key[1]);
                _Key[2] = ByteSwap<uint32_t>(_Key[2]);
                _Key[3] = ByteSwap<uint32_t>(_Key[3]);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);

            for (size_t i = 0; i < __N; ++i)
                Text[i] = ByteSwap<uint32_t>(Text[i]);

            _EncryptProcess(Text);

            for (size_t i = 0; i < __N; ++i)
                Text[i] = ByteSwap<uint32_t>(Text[i]);

            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);

            for (size_t i = 0; i < __N; ++i)
                Text[i] = ByteSwap<uint32_t>(Text[i]);

            _DecryptProcess(Text);

            for (size_t i = 0; i < __N; ++i)
                Text[i] = ByteSwap<uint32_t>(Text[i]);

            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~XXTEA_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

