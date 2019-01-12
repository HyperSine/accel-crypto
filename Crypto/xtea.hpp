#pragma once
#include "../Common/Array.hpp"
#include <memory.h>

namespace accel::Crypto {

    class XTEA_ALG {
    public:
        static constexpr size_t BlockSizeValue = 8;
        static constexpr size_t KeySizeValue = 16;
    private:

        static constexpr uint32_t _Delta = 0x9E3779B9;

        union BlockType {
            uint8_t bytes[8];
            uint32_t dwords[2];
        };
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureArray<uint32_t, 4> _Key;
        uint32_t _Rounds;

        __forceinline
        void _EncryptProcess(BlockType& RefBlock) const noexcept {
            uint32_t sum = 0;

            for (uint32_t i = 0; i < _Rounds; ++i) {
                RefBlock.dwords[0] +=
                    (((RefBlock.dwords[1] << 4) ^ (RefBlock.dwords[1] >> 5)) + RefBlock.dwords[1]) ^ 
                    (sum + _Key[sum % _Key.Length()]);

                sum += _Delta;

                RefBlock.dwords[1] +=
                    (((RefBlock.dwords[0] << 4) ^ (RefBlock.dwords[0] >> 5)) + RefBlock.dwords[0]) ^
                    (sum + _Key[(sum >> 11) % _Key.Length()]);
            }

            sum = 0;
        }

        __forceinline
        void _DecryptProcess(BlockType& RefBlock) const noexcept {
            uint32_t sum = _Delta * _Rounds;

            for (uint32_t i = 0; i < _Rounds; ++i) {
                RefBlock.dwords[1] -=
                    (((RefBlock.dwords[0] << 4) ^ (RefBlock.dwords[0] >> 5)) + RefBlock.dwords[0]) ^
                    (sum + _Key[(sum >> 11) % _Key.Length()]);

                sum -= _Delta;

                RefBlock.dwords[0] +=
                    (((RefBlock.dwords[1] << 4) ^ (RefBlock.dwords[1] >> 5)) + RefBlock.dwords[1]) ^
                    (sum + _Key[sum % _Key.Length()]);
            }

            sum = 0;
        }

    public:

        XTEA_ALG() : _Rounds(32) {}

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const noexcept {
            return KeySizeValue;
        }

        void SetRounds(uint32_t NumberOfRounds) noexcept {
            _Rounds = NumberOfRounds;
        }

        uint32_t GetRounds() const noexcept {
            return _Rounds;
        }

        [[nodiscard]]
        bool SetKey(const void* pUserKey, size_t UserKeySize) noexcept {
            if (UserKeySize != KeySizeValue) {
                return false;
            } else {
                memcpy(_Key.GetPtr(), pUserKey, KeySizeValue);
                return true;
            }
        }

        size_t EncryptBlock(void* pPlaintext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(pPlaintext);
            _EncryptProcess(Text);
            *reinterpret_cast<BlockType*>(pPlaintext) = Text;
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pCiphertext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(pCiphertext);
            _DecryptProcess(Text);
            *reinterpret_cast<BlockType*>(pCiphertext) = Text;
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
        }
    };

}

