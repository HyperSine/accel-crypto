#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/blowfish_constant.hpp"
#include <memory.h>

namespace accel::Crypto {

    template<bool __LittleEndian = false>
    class BLOWFISH_ALG : public Internal::BLOWFISH_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 8;
        static constexpr size_t MinKeySizeValue = 1;
        static constexpr size_t MaxKeySizeValue = 56;
    private:

        using BlockType = Array<uint32_t, 2>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 18> _SubKey;
        Array<uint32_t, 4, 256> _SubBox;

        template<char __LR_Tag>
        ACCEL_FORCEINLINE
        uint32_t _F_transform(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t result;

            if constexpr (__LR_Tag == 'L') {
                result = _SubBox[0][RefBlock.template AsCArrayOf<uint8_t[8]>()[3]];
                result += _SubBox[1][RefBlock.template AsCArrayOf<uint8_t[8]>()[2]];
                result ^= _SubBox[2][RefBlock.template AsCArrayOf<uint8_t[8]>()[1]];
                result += _SubBox[3][RefBlock.template AsCArrayOf<uint8_t[8]>()[0]];
            } else if constexpr (__LR_Tag == 'R') {
                result = _SubBox[0][RefBlock.template AsCArrayOf<uint8_t[8]>()[4 + 3]];
                result += _SubBox[1][RefBlock.template AsCArrayOf<uint8_t[8]>()[4 + 2]];
                result ^= _SubBox[2][RefBlock.template AsCArrayOf<uint8_t[8]>()[4 + 1]];
                result += _SubBox[3][RefBlock.template AsCArrayOf<uint8_t[8]>()[4 + 0]];
            } else {
                static_assert(__LR_Tag == 'L' || __LR_Tag == 'R');
                ACCEL_UNREACHABLE();
            }

            return result;
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _EncryptLoop(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[__Index % 2 == 0 ? 0 : 1] ^= _SubKey[__Index];
            RefBlock[__Index % 2 == 0 ? 1 : 0] ^= _F_transform<__Index % 2 == 0 ? 'L' : 'R'>(RefBlock);
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _EncryptLoops(BlockType& RefBlock, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_EncryptLoop<__Indexes>(RefBlock), ...);
        }

        template<bool __LEndian>
        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            if constexpr (__LEndian == false) {
                RefBlock[0] = ByteSwap<uint32_t>(RefBlock[0]);
                RefBlock[1] = ByteSwap<uint32_t>(RefBlock[1]);
            }

            _EncryptLoops(RefBlock, std::make_index_sequence<16>{});

            RefBlock[0] ^= _SubKey[16];
            RefBlock[1] ^= _SubKey[17];

            std::swap(RefBlock[0], RefBlock[1]);

            if constexpr (__LEndian == false) {
                RefBlock[0] = ByteSwap<uint32_t>(RefBlock[0]);
                RefBlock[1] = ByteSwap<uint32_t>(RefBlock[1]);
            }
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _DecryptLoop(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[__Index % 2 == 0 ? 1 : 0] ^= _F_transform<__Index % 2 == 0 ? 'L' : 'R'>(RefBlock);
            RefBlock[__Index % 2 == 0 ? 0 : 1] ^= _SubKey[__Index];
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _DecryptLoops(BlockType& RefBlock, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_DecryptLoop<__Indexes>(RefBlock), ...);
        }

        template<bool __LEndian>
        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            if constexpr (__LEndian == false) {
                RefBlock[0] = ByteSwap<uint32_t>(RefBlock[0]);
                RefBlock[1] = ByteSwap<uint32_t>(RefBlock[1]);
            }

            std::swap(RefBlock[0], RefBlock[1]);

            RefBlock[0] ^= _SubKey[16];
            RefBlock[1] ^= _SubKey[17];

            _DecryptLoops(RefBlock, std::index_sequence<15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0>{});

            if constexpr (__LEndian == false) {
                RefBlock[0] = ByteSwap<uint32_t>(RefBlock[0]);
                RefBlock[1] = ByteSwap<uint32_t>(RefBlock[1]);
            }
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const uint8_t* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            _SubKey.LoadFrom(OriginalPBox);
            _SubBox.LoadFrom(OriginalSBox);

            for (int i = 0; i < _SubKey.Length(); ++i) {
                uint32_t temp = pbUserKey[(i * 4) % cbUserKey];

                temp <<= 8;
                temp |= pbUserKey[(i * 4 + 1) % cbUserKey];

                temp <<= 8;
                temp |= pbUserKey[(i * 4 + 2) % cbUserKey];

                temp <<= 8;
                temp |= pbUserKey[(i * 4 + 3) % cbUserKey];

                _SubKey[i] ^= temp;
            }

            BlockType temp = {};
            for (int i = 0; i < 9; ++i) {
                _EncryptProcess<true>(temp);
                _SubKey.template AsCArrayOf<uint64_t[9]>()[i] = temp.template AsCArrayOf<uint64_t[1]>()[0];
            }

            for (int i = 0; i < 512; ++i) {
                _EncryptProcess<true>(temp);
                _SubBox.template AsCArrayOf<uint64_t[512]>()[i] = temp.template AsCArrayOf<uint64_t[1]>()[0];
            }
        }

    public:

        constexpr size_t BlockSize() const ACCEL_NOEXCEPT {
            return BlockSizeValue;
        }

        constexpr size_t MinKeySize() const ACCEL_NOEXCEPT {
            return MinKeySizeValue;
        }

        constexpr size_t MaxKeySize() const ACCEL_NOEXCEPT {
            return MaxKeySizeValue;
        }

        ACCEL_NODISCARD
        bool SetKey(const void* pUserKey, size_t UserKeySize) ACCEL_NOEXCEPT {
            if (UserKeySize < MinKeySizeValue || UserKeySize > MaxKeySizeValue) {
                return false;
            } else {
                _KeyExpansion(reinterpret_cast<const uint8_t*>(pUserKey), UserKeySize);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);
            _EncryptProcess<__LittleEndian>(Text);
            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);
            _DecryptProcess<__LittleEndian>(Text);
            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _SubKey.SecureZero();
            _SubBox.SecureZero();
        }

        ~BLOWFISH_ALG() ACCEL_NOEXCEPT {
            _SubKey.SecureZero();
            _SubBox.SecureZero();
        }
    };

}

