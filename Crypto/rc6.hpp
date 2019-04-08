#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/rc6_constant.hpp"

namespace accel::Crypto {

    template<size_t __WordBits, size_t __Rounds, size_t __BytesOfKey>
    class RC6_ALG : public Internal::RC6_CONSTANT<__WordBits> {
        static_assert(__WordBits == 16 || __WordBits == 32 || __WordBits == 64, "RC6_ALG failure! Invalid __WordBits.");
        static_assert(__BytesOfKey < 256, "RC6_ALG failure! Invalid __BytesOfKey.");
        static_assert(1u << Internal::RC6_CONSTANT<__WordBits>::lgw == __WordBits);
    public:
        static constexpr size_t BlockSizeValue = 4 * __WordBits / 8;
        static constexpr size_t KeySizeValue = __BytesOfKey;
    private:

        using WordType = typename Internal::RC6_CONSTANT<__WordBits>::WordType;
        using BlockType = Array<WordType, 4>;

        static_assert(sizeof(WordType) == __WordBits / 8);
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<WordType, 2 * (__Rounds + 2)> _Key;

        ACCEL_FORCEINLINE
        void _KeyExpansion(const uint8_t* pbUserKey) ACCEL_NOEXCEPT {
            constexpr size_t t = 2 * (__Rounds + 2);
            constexpr size_t c = __BytesOfKey ? (__BytesOfKey + (sizeof(WordType) - 1)) / sizeof(WordType) : 1;
            constexpr size_t fin = 3 * (t > c ? t : c);

            Array<WordType, 256 / sizeof(WordType)> L = {};

            L.LoadFrom(pbUserKey, KeySizeValue);

            _Key[0] = Internal::RC6_CONSTANT<__WordBits>::P;
            for (size_t i = 1; i < t; ++i)
                _Key[i] = _Key[i - 1] + Internal::RC6_CONSTANT<__WordBits>::Q;

            size_t ii = 0, jj = 0;
            WordType A = 0, B = 0;
            for (size_t i = 0; i < fin; ++i) {
                _Key[ii] = RotateShiftLeft<WordType>(_Key[ii] + A + B, 3);
                A = _Key[ii];

                L[jj] = RotateShiftLeft<WordType>(L[jj] + A + B, (A + B) % 64);
                B = L[jj];

                ii = (ii + 1) % t;
                jj = (jj + 1) % c;
            }

            L.SecureZero();
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            auto& A = RefBlock[0];
            auto& B = RefBlock[1];
            auto& C = RefBlock[2];
            auto& D = RefBlock[3];

            B += _Key[0];
            D += _Key[1];
            for (size_t i = 1; i <= __Rounds; ++i) {
                WordType t =
                    RotateShiftLeft<WordType>(B * (2 * B + 1), Internal::RC6_CONSTANT<__WordBits>::lgw);
                WordType u =
                    RotateShiftLeft<WordType>(D * (2 * D + 1), Internal::RC6_CONSTANT<__WordBits>::lgw);
                A = RotateShiftLeft<WordType>(A ^ t, u) + _Key[2 * i];
                C = RotateShiftLeft<WordType>(C ^ u, t) + _Key[2 * i + 1];

                WordType temp = A;
                A = B;
                B = C;
                C = D;
                D = temp;
            }

            A += _Key[2 * __Rounds + 2];
            C += _Key[2 * __Rounds + 3];
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            auto& A = RefBlock[0];
            auto& B = RefBlock[1];
            auto& C = RefBlock[2];
            auto& D = RefBlock[3];

            C -= _Key[2 * __Rounds + 3];
            A -= _Key[2 * __Rounds + 2];
            for (size_t i = __Rounds; i > 0; --i) {
                WordType temp = D;
                D = C;
                C = B;
                B = A;
                A = temp;

                WordType u =
                        RotateShiftLeft<WordType>(D * (2 * D + 1), Internal::RC6_CONSTANT<__WordBits>::lgw);
                WordType t =
                        RotateShiftLeft<WordType>(B * (2 * B + 1), Internal::RC6_CONSTANT<__WordBits>::lgw);
                C = RotateShiftRight<WordType>(C - _Key[2 * i + 1], t) ^ u;
                A = RotateShiftRight<WordType>(A - _Key[2 * i], u) ^ t;
            }
            D -= _Key[1];
            B -= _Key[0];
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

        ~RC6_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

