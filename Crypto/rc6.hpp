#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <memory.h>

namespace accel::Crypto {

    namespace Internal {

        template<size_t __WordBits>
        class RC6_CONSTANT;

        template<>
        class RC6_CONSTANT<16> {
        protected:
            using WordType = uint16_t;
            static constexpr WordType _P = 0xB7E1;
            static constexpr WordType _Q = 0x9E37;
            static constexpr unsigned _lgw = 4;
        };

        template<>
        class RC6_CONSTANT<32> {
        protected:
            using WordType = uint32_t;
            static constexpr WordType _P = 0xB7E15163;
            static constexpr WordType _Q = 0x9E3779B9;
            static constexpr unsigned _lgw = 5;
        };

        template<>
        class RC6_CONSTANT<64> {
        protected:
            using WordType = uint64_t;
            static constexpr WordType _P = 0xB7E151628AED2A6B;
            static constexpr WordType _Q = 0x9E3779B97F4A7C15;
            static constexpr unsigned _lgw = 6;
        };
    }

    template<size_t __WordBits, size_t __Rounds, size_t __BytesOfKey>
    class RC6_ALG : public Internal::RC6_CONSTANT<__WordBits> {
        static_assert(__WordBits == 16 ||
                      __WordBits == 32 ||
                      __WordBits == 64, "RC6_ALG failure! Invalid __WordBits.");
        static_assert(__BytesOfKey < 256, "RC6_ALG failure! Invalid __BytesOfKey.");
    public:
        static constexpr size_t BlockSizeValue = 4 * __WordBits / 8;
        static constexpr size_t KeySizeValue = __BytesOfKey;
    private:

        using WordType = typename Internal::RC6_CONSTANT<__WordBits>::WordType;
        static_assert(sizeof(WordType) == __WordBits / 8);

        static constexpr WordType _P = Internal::RC6_CONSTANT<__WordBits>::_P;
        static constexpr WordType _Q = Internal::RC6_CONSTANT<__WordBits>::_Q;

        static constexpr unsigned _lgw = Internal::RC6_CONSTANT<__WordBits>::_lgw;
        static_assert(1u << _lgw == __WordBits);

        union BlockType {
            WordType Values[4];

            WordType& operator[](size_t i) noexcept {
                return Values[i];
            }

            const WordType& operator[](size_t i) const noexcept {
                return Values[i];
            }
        };
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureArray<WordType, 2 * (__Rounds + 2)> _Key;

        __forceinline
        void _KeyExpansion(const uint8_t* PtrToUserKey) noexcept {
            SecureArray<WordType, 256 / sizeof(WordType)> L;
            constexpr size_t t = 2 * (__Rounds + 2);
            constexpr size_t c = __BytesOfKey ? (__BytesOfKey + (sizeof(WordType) - 1)) / sizeof(WordType) : 1;
            constexpr size_t fin = 3 * (t > c ? t : c);

            memset(L.GetPtr(), 0, L.Size());
            memcpy(L.GetPtr(), PtrToUserKey, KeySizeValue);

            _Key[0] = _P;
            for (size_t i = 1; i < t; ++i)
                _Key[i] = _Key[i - 1] + _Q;

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
        }

        void _EncryptProcess(BlockType& RefBlock) const noexcept {
            auto& A = RefBlock[0];
            auto& B = RefBlock[1];
            auto& C = RefBlock[2];
            auto& D = RefBlock[3];

            B += _Key[0];
            D += _Key[1];
            for (size_t i = 1; i <= __Rounds; ++i) {
                WordType t =
                    RotateShiftLeft<WordType>(B * (2 * B + 1), _lgw);
                WordType u =
                    RotateShiftLeft<WordType>(D * (2 * D + 1), _lgw);
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

        void _DecryptProcess(BlockType& RefBlock) const noexcept {
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
                        RotateShiftLeft<WordType>(D * (2 * D + 1), _lgw);
                WordType t =
                        RotateShiftLeft<WordType>(B * (2 * B + 1), _lgw);
                C = RotateShiftRight<WordType>(C - _Key[2 * i + 1], t) ^ u;
                A = RotateShiftRight<WordType>(A - _Key[2 * i], u) ^ t;
            }
            D -= _Key[1];
            B -= _Key[0];
        }
    public:

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const noexcept {
            return KeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* PtrToUserKey, size_t UserKeySize) noexcept {
            if (UserKeySize == KeySizeValue) {
                _KeyExpansion(reinterpret_cast<const uint8_t*>(PtrToUserKey));
                return true;
            } else {
                return false;
            }
        }

        size_t EncryptBlock(void* PtrToPlaintext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(PtrToPlaintext);
            _EncryptProcess(Text);
            *reinterpret_cast<BlockType*>(PtrToPlaintext) = Text;
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* PtrToCiphertext) const noexcept {
            BlockType Text = *reinterpret_cast<BlockType*>(PtrToCiphertext);
            _DecryptProcess(Text);
            *reinterpret_cast<BlockType*>(PtrToCiphertext) = Text;
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
        }
    };

}

