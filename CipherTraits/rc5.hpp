#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/rc5_constant.hpp"

namespace accel::CipherTraits {

    template<size_t __WordBits, size_t __Rounds, size_t __BytesOfKey>
    class RC5_ALG : public Internal::RC5_CONSTANT<__WordBits> {
        static_assert(__WordBits == 16 || __WordBits == 32 || __WordBits == 64, "RC5_ALG failure! Invalid __WordBits.");
        static_assert(__BytesOfKey < 256, "RC5_ALG failure! Invalid __BytesOfKey.");
    public:
        static constexpr size_t BlockSizeValue = 2 * __WordBits / 8;
        static constexpr size_t KeySizeValue = __BytesOfKey;
    private:

        using WordType = typename Internal::RC5_CONSTANT<__WordBits>::WordType;
        using BlockType = Array<WordType, 2>;
        static_assert(sizeof(WordType) == __WordBits / 8);
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<WordType, 2 * (__Rounds + 1)> _Key;

        ACCEL_FORCEINLINE
        void _KeyExpansion(const uint8_t* pbUserKey) ACCEL_NOEXCEPT {
            constexpr size_t t = 2 * (__Rounds + 1);
            constexpr size_t c = __BytesOfKey ? (__BytesOfKey + (sizeof(WordType) - 1)) / sizeof(WordType) : 1;
            constexpr size_t fin = 3 * (t > c ? t : c);

            Array<WordType, 256 / sizeof(WordType)> L = {};

            L.LoadFrom(pbUserKey, KeySizeValue);

            _Key[0] = Internal::RC5_CONSTANT<__WordBits>::P;
            for (size_t i = 1; i < t; ++i)
                _Key[i] = _Key[i - 1] + Internal::RC5_CONSTANT<__WordBits>::Q;

            size_t ii = 0, jj = 0;
            WordType A = 0, B = 0;
            for (size_t i = 0; i < fin; ++i) {
                _Key[ii] = RotateShiftLeft<WordType>(_Key[ii] + A + B, 3);
                A = _Key[ii];

                L[jj] = RotateShiftLeft<WordType>(L[jj] + A + B, (A + B) % 64);
                B = L[jj];

                ii = (ii + 1) % _Key.Length();
                jj = (jj + 1) % c;
            }

            L.SecureZero();
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[0] += _Key[0];
            RefBlock[1] += _Key[1];
            for (size_t i = 1; i <= __Rounds; ++i) {
                RefBlock[0] = 
                    RotateShiftLeft<WordType>(RefBlock[0] ^ RefBlock[1], RefBlock[1] % __WordBits) + 
                    _Key[i * 2];
                RefBlock[1] = 
                    RotateShiftLeft<WordType>(RefBlock[1] ^ RefBlock[0], RefBlock[0] % __WordBits) +
                    _Key[i * 2 + 1];
            }
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            for (size_t i = __Rounds; i > 0; --i) {
                RefBlock[1] -= _Key[i * 2 + 1];
                RefBlock[1] = 
                    RotateShiftRight<WordType>(RefBlock[1], RefBlock[0] % __WordBits) ^
                    RefBlock[0];
                RefBlock[0] -= _Key[i * 2];
                RefBlock[0] = 
                    RotateShiftRight<WordType>(RefBlock[0], RefBlock[1] % __WordBits) ^
                    RefBlock[1];
            }
            RefBlock[1] -= _Key[1];
            RefBlock[0] -= _Key[0];
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
            if (cbUserKey == KeySizeValue) {
                _KeyExpansion(reinterpret_cast<const uint8_t*>(pbUserKey));
                return true;
            } else {
                return false;
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

        ~RC5_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

