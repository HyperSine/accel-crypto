#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/skipjack_constant.hpp"

namespace accel::Crypto {

    class SKIPJACK_ALG : public Internal::SKIPJACK_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 8;
        static constexpr size_t KeySizeValue = 10;
    private:

        using BlockType = Array<uint16_t, 4>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        uint16_t _GPermutation(uint16_t w, size_t k) const ACCEL_NOEXCEPT {
            uint8_t g1, g2;

            g1 = static_cast<uint8_t>((w >> 8) & 0xFFu);
            g2 = static_cast<uint8_t>(w & 0xFFu);

            g1 ^= FTable[g2 ^ _Key[(4 * k) % 10]];
            g2 ^= FTable[g1 ^ _Key[(4 * k + 1) % 10]];
            g1 ^= FTable[g2 ^ _Key[(4 * k + 2) % 10]];
            g2 ^= FTable[g1 ^ _Key[(4 * k + 3) % 10]];

            return static_cast<uint16_t>((g1 << 8) | g2);
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        uint16_t _InverseGPermutation(uint16_t w, size_t k) const ACCEL_NOEXCEPT {
            uint8_t g1, g2;

            g1 = static_cast<uint8_t>((w >> 8) & 0xFFu);
            g2 = static_cast<uint8_t>(w & 0xFFu);

            g2 ^= FTable[g1 ^ _Key[(4 * k + 3) % 10]];
            g1 ^= FTable[g2 ^ _Key[(4 * k + 2) % 10]];
            g2 ^= FTable[g1 ^ _Key[(4 * k + 1) % 10]];
            g1 ^= FTable[g2 ^ _Key[(4 * k) % 10]];

            return static_cast<uint16_t>((g1 << 8) | g2);
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint16_t w1, w2, w3, w4;
            int16_t k = 0;

            w1 = RefBlock[0];
            w2 = RefBlock[1];
            w3 = RefBlock[2];
            w4 = RefBlock[3];

            // Rule A
            for (; k < 8; ++k) {
                uint16_t prev_w4 = w4;
                w4 = w3;
                w3 = w2;
                w2 = _GPermutation(w1, k);
                w1 = _GPermutation(w1, k) ^ prev_w4 ^ static_cast<uint16_t>(k + 1);
            }

            // Rule B 
            for (; k < 16; ++k) {
                uint16_t prev_w3 = w3;
                w3 = w1 ^ w2 ^ static_cast<uint16_t>(k + 1);
                w2 = _GPermutation(w1, k);
                w1 = w4;
                w4 = prev_w3;
            }

            // Rule A
            for (; k < 24; ++k) {
                uint16_t prev_w4 = w4;
                w4 = w3;
                w3 = w2;
                w2 = _GPermutation(w1, k);
                w1 = _GPermutation(w1, k) ^ prev_w4 ^ static_cast<uint16_t>(k + 1);
            }

            // Rule B 
            for (; k < 32; ++k) {
                uint16_t prev_w3 = w3;
                w3 = w1 ^ w2 ^ static_cast<uint16_t>(k + 1);
                w2 = _GPermutation(w1, k);
                w1 = w4;
                w4 = prev_w3;
            }

            RefBlock[0] = w1;
            RefBlock[1] = w2;
            RefBlock[2] = w3;
            RefBlock[3] = w4;
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint16_t w1, w2, w3, w4;
            int16_t k = 31;

            w1 = RefBlock[0];
            w2 = RefBlock[1];
            w3 = RefBlock[2];
            w4 = RefBlock[3];

            // Inverse RuleB
            for (; k >= 24; --k) {
                uint16_t prev_w1 = w1;
                w1 = _InverseGPermutation(w2, k);
                w2 = _InverseGPermutation(w2, k) ^ w3 ^ static_cast<uint16_t>(k + 1);
                w3 = w4;
                w4 = prev_w1;
            }

            // Inverse RuleA
            for (; k >= 16; --k) {
                uint16_t prev_w4 = w4;
                w4 = w1 ^ w2 ^ static_cast<uint16_t>(k + 1);
                w1 = _InverseGPermutation(w2, k);
                w2 = w3;
                w3 = prev_w4;
            }

            // Inverse RuleB
            for (; k >= 8; --k) {
                uint16_t prev_w1 = w1;
                w1 = _InverseGPermutation(w2, k);
                w2 = _InverseGPermutation(w2, k) ^ w3 ^ static_cast<uint16_t>(k + 1);
                w3 = w4;
                w4 = prev_w1;
            }

            // Inverse RuleA
            for (; k >= 0; --k) {
                uint16_t prev_w4 = w4;
                w4 = w1 ^ w2 ^ static_cast<uint16_t>(k + 1);
                w1 = _InverseGPermutation(w2, k);
                w2 = w3;
                w3 = prev_w4;
            }

            RefBlock[0] = w1;
            RefBlock[1] = w2;
            RefBlock[2] = w3;
            RefBlock[3] = w4;
        }

        Array<uint8_t, 10> _Key;

    public:

        constexpr size_t BlockSize() const ACCEL_NOEXCEPT {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const ACCEL_NOEXCEPT {
            return KeySizeValue;
        }

        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (cbUserKey != KeySizeValue) {
                return false;
            } else {
                _Key.LoadFrom(pbUserKey);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[0]);
            Text[1] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[1]);
            Text[2] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[2]);
            Text[3] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[3]);

            _EncryptProcess(Text);

            reinterpret_cast<uint16_t*>(pbPlaintext)[0] = ByteSwap<uint16_t>(Text[0]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[1] = ByteSwap<uint16_t>(Text[1]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[2] = ByteSwap<uint16_t>(Text[2]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[3] = ByteSwap<uint16_t>(Text[3]);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[0]);
            Text[1] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[1]);
            Text[2] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[2]);
            Text[3] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[3]);

            _DecryptProcess(Text);

            reinterpret_cast<uint16_t*>(pbCiphertext)[0] = ByteSwap<uint16_t>(Text[0]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[1] = ByteSwap<uint16_t>(Text[1]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[2] = ByteSwap<uint16_t>(Text[2]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[3] = ByteSwap<uint16_t>(Text[3]);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

