#pragma once
#include "../Common/Array.hpp"
#include <memory.h>

namespace accel::Crypto {

    template<size_t __N>
    class XXTEA_ALG {
        static_assert(__N >= 2);
    public:
        static constexpr size_t BlockSizeValue = __N * sizeof(uint32_t);
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        static constexpr uint32_t _Delta = 0x9E3779B9;
        static constexpr size_t _Rounds = 6 + 52 / __N;

        union BlockType {
            uint8_t bytes[__N * sizeof(uint32_t)];
            uint32_t dwords[__N];
        };
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureArray<uint32_t, 4> _Key;

        __forceinline
        uint32_t _MX(uint32_t& e, 
                     uint32_t& y, 
                     uint32_t& z, 
                     uint32_t& sum,
                     unsigned& p) const noexcept {
            return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (_Key[(p % 4) ^ e] ^ z));
        }

        void _EncryptProcess(BlockType& RefBlock) const noexcept {
            uint32_t y, z, sum = 0;
            unsigned p, e;
            z = RefBlock.dwords[__N - 1];
            for (size_t n = 0; n < _Rounds; ++n) {
                sum += _Delta;
                e = (sum >> 2) % 4;
                for (p = 0; p < __N - 1; ++p) {
                    y = RefBlock.dwords[p + 1];
                    z = RefBlock.dwords[p] += _MX(e, y, z, sum, p);
                }
                y = RefBlock.dwords[0];
                z = RefBlock.dwords[__N - 1] += _MX(e, y, z, sum, p);
            }
        }

        void _DecryptProcess(BlockType& RefBlock) const noexcept {
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4309)
#endif
            uint32_t y, z, sum = static_cast<uint32_t>(_Rounds * _Delta);
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
            unsigned p, e;
            y = RefBlock.dwords[0];
            for (size_t n = 0; n < _Rounds; ++n) {
                e = (sum >> 2) % 4;
                for (p = __N - 1; p > 0; --p) {
                    z = RefBlock.dwords[p - 1];
                    y = RefBlock.dwords[p] -= _MX(e, y, z, sum, p);
                }
                z = RefBlock.dwords[__N - 1];
                y = RefBlock.dwords[0] -= _MX(e, y, z, sum, p);
                sum -= _Delta;
            }
        }

    public:

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const noexcept {
            return KeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* pUserKey, size_t UserKeySize) noexcept {
            if (UserKeySize != KeySizeValue) {
                return false;
            } else {
                memcpy(_Key.GetPtr(), pUserKey, KeySizeValue);
                _Key[0] = ByteSwap<uint32_t>(_Key[0]);
                _Key[1] = ByteSwap<uint32_t>(_Key[1]);
                _Key[2] = ByteSwap<uint32_t>(_Key[2]);
                _Key[3] = ByteSwap<uint32_t>(_Key[3]);
                return true;
            }
        }

        size_t EncryptBlock(void* pPlaintext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(pPlaintext);

            for (size_t i = 0; i < __N; ++i)
                Text.dwords[i] = ByteSwap<uint32_t>(Text.dwords[i]);

            _EncryptProcess(Text);

            for (size_t i = 0; i < __N; ++i)
                Text.dwords[i] = ByteSwap<uint32_t>(Text.dwords[i]);

            *reinterpret_cast<BlockType*>(pPlaintext) = Text;
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pCiphertext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(pCiphertext);

            for (size_t i = 0; i < __N; ++i)
                Text.dwords[i] = ByteSwap<uint32_t>(Text.dwords[i]);

            _DecryptProcess(Text);

            for (size_t i = 0; i < __N; ++i)
                Text.dwords[i] = ByteSwap<uint32_t>(Text.dwords[i]);

            *reinterpret_cast<BlockType*>(pCiphertext) = Text;
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
        }
    };

}

