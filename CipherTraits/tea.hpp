#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"

namespace accel::CipherTraits {
    
    class TEA_ALG {
    public:
        static constexpr size_t BlockSizeValue = 64 / 8;
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        static constexpr uint32_t Delta = 0x9E3779B9;

        using BlockType = Array<uint32_t, 2>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 4> _Key;

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t sum = 0;

            for (uint32_t i = 0; i < 32; ++i) {
                sum += Delta;

                RefBlock[0] +=
                    ((RefBlock[1] << 4) + _Key[0]) ^
                    (RefBlock[1] + sum) ^
                    ((RefBlock[1] >> 5) + _Key[1]);

                RefBlock[1] +=
                    ((RefBlock[0] << 4) + _Key[2]) ^
                    (RefBlock[0] + sum) ^
                    ((RefBlock[0] >> 5) + _Key[3]);
            }

            sum = 0;
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t sum = Delta << 5;

            for (uint32_t i = 0; i < 32; ++i) {
                RefBlock[1] -=
                    ((RefBlock[0] << 4) + _Key[2]) ^
                    (RefBlock[0] + sum) ^
                    ((RefBlock[0] >> 5) + _Key[3]);

                RefBlock[0] -=
                    ((RefBlock[1] << 4) + _Key[0]) ^
                    (RefBlock[1] + sum) ^
                    ((RefBlock[1] >> 5) + _Key[1]);

                sum -= Delta;
            }

            sum = 0;
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

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);

            _EncryptProcess(Text);

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);

            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;
            
            Text.LoadFrom(pbCiphertext);

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);

            _DecryptProcess(Text);

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);

            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~TEA_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

