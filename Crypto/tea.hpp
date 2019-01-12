#pragma once
#include "../Common/Array.hpp"
#include <memory.h>

namespace accel::Crypto {
    
    class TEA_ALG {
    public:
        static constexpr size_t BlockSizeValue = 64 / 8;
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        static constexpr uint32_t _Delta = 0x9E3779B9;

        union BlockType {
            uint8_t bytes[8];
            uint32_t dwords[2];
        };
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureArray<uint32_t, 4> _Key;

        __forceinline
        void _EncryptProcess(BlockType& RefBlock) const noexcept {
            uint32_t sum = 0;

            for (uint32_t i = 0; i < 32; ++i) {
                sum += _Delta;

                RefBlock.dwords[0] +=
                    ((RefBlock.dwords[1] << 4) + _Key[0]) ^
                    (RefBlock.dwords[1] + sum) ^
                    ((RefBlock.dwords[1] >> 5) + _Key[1]);

                RefBlock.dwords[1] +=
                    ((RefBlock.dwords[0] << 4) + _Key[2]) ^
                    (RefBlock.dwords[0] + sum) ^
                    ((RefBlock.dwords[0] >> 5) + _Key[3]);
            }

            sum = 0;
        }

        __forceinline
        void _DecryptProcess(BlockType& RefBlock) const noexcept {
            uint32_t sum = _Delta << 5;

            for (uint32_t i = 0; i < 32; ++i) {
                RefBlock.dwords[1] -=
                    ((RefBlock.dwords[0] << 4) + _Key[2]) ^
                    (RefBlock.dwords[0] + sum) ^
                    ((RefBlock.dwords[0] >> 5) + _Key[3]);

                RefBlock.dwords[0] -=
                    ((RefBlock.dwords[1] << 4) + _Key[0]) ^
                    (RefBlock.dwords[1] + sum) ^
                    ((RefBlock.dwords[1] >> 5) + _Key[1]);

                sum -= _Delta;
            }

            sum = 0;
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

            Text.dwords[0] = ByteSwap<uint32_t>(Text.dwords[0]);
            Text.dwords[1] = ByteSwap<uint32_t>(Text.dwords[1]);

            _EncryptProcess(Text);

            Text.dwords[0] = ByteSwap<uint32_t>(Text.dwords[0]);
            Text.dwords[1] = ByteSwap<uint32_t>(Text.dwords[1]);

            *reinterpret_cast<BlockType*>(pPlaintext) = Text;
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pCiphertext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(pCiphertext);

            Text.dwords[0] = ByteSwap<uint32_t>(Text.dwords[0]);
            Text.dwords[1] = ByteSwap<uint32_t>(Text.dwords[1]);

            _DecryptProcess(Text);

            Text.dwords[0] = ByteSwap<uint32_t>(Text.dwords[0]);
            Text.dwords[1] = ByteSwap<uint32_t>(Text.dwords[1]);

            *reinterpret_cast<BlockType*>(pCiphertext) = Text;
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
        }
    };

}

