#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/gost_constant.hpp"
#include <utility>

namespace accel::CipherTraits {

    class GOST2814789_ALG : public Internal::GOST2814789_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 64 / 8;
        static constexpr size_t KeySizeValue = 256 / 8;
    private:

        using BlockType = Array<uint32_t, 2>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint32_t _SubAndRotateShiftLeft11(uint32_t x) ACCEL_NOEXCEPT {
            return
                SBoxAfterR[0][x & 0x000000FFu] ^
                SBoxAfterR[1][(x >> 8u) & 0x000000FFu] ^
                SBoxAfterR[2][(x >> 16u) & 0x000000FFu] ^
                SBoxAfterR[3][(x >> 24u) & 0x000000FFu];
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 3; ++i) {
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[0]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[1]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[2]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[3]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[4]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[5]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[6]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[7]);
            }
            
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[7]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[6]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[5]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[4]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[3]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[2]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[1]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[0]);

            std::swap(RefBlock[0], RefBlock[1]);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[0]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[1]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[2]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[3]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[4]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[5]);
            RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[6]);
            RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[7]);

            for (size_t i = 0; i < 3; ++i) {
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[7]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[6]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[5]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[4]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[3]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[2]);
                RefBlock[1] ^= _SubAndRotateShiftLeft11(RefBlock[0] + _Key[1]);
                RefBlock[0] ^= _SubAndRotateShiftLeft11(RefBlock[1] + _Key[0]);
            }

            std::swap(RefBlock[0], RefBlock[1]);
        }

        Array<uint32_t, 8> _Key;

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
                _Key.LoadFrom(pbUserKey);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);
            _EncryptProcess(Text);
            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);
            _DecryptProcess(Text);
            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~GOST2814789_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

