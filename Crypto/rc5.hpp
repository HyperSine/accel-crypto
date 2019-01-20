#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"

namespace accel::Crypto {

    namespace Internal {
        template<size_t __WordBits>
        class RC5_CONSTANT;

        template<>
        class RC5_CONSTANT<16> {
        protected:
            using WordType = uint16_t;
            static constexpr WordType _P = 0xB7E1;
            static constexpr WordType _Q = 0x9E37;
        };

        template<>
        class RC5_CONSTANT<32> {
        protected:
            using WordType = uint32_t;
            static constexpr WordType _P = 0xB7E15163;
            static constexpr WordType _Q = 0x9E3779B9;
        };

        template<>
        class RC5_CONSTANT<64> {
        protected:
            using WordType = uint64_t;
            static constexpr WordType _P = 0xB7E151628AED2A6B;
            static constexpr WordType _Q = 0x9E3779B97F4A7C15;
        };
    }

    template<size_t __WordBits, size_t __Rounds>
    class RC5_ALG : public Internal::RC5_CONSTANT<__WordBits> {
        static_assert(__WordBits == 16 ||
                      __WordBits == 32 ||
                      __WordBits == 64, "RC5_ALG failure! Invalid __WordBits.");
    public:
        static constexpr size_t BlockSizeValue = 2 * __WordBits / 8;
        static constexpr size_t MinKeySizeValue = 0;
        static constexpr size_t MaxKeySizeValue = 255;
    private:

        using WordType = typename Internal::RC5_CONSTANT<__WordBits>::WordType;
        static constexpr WordType _P = Internal::RC5_CONSTANT<__WordBits>::_P;
        static constexpr WordType _Q = Internal::RC5_CONSTANT<__WordBits>::_Q;

        union BlockType {
            WordType Values[2];

            WordType& operator[](size_t i) noexcept {
                return Values[i];
            }

            const WordType& operator[](size_t i) const noexcept {
                return Values[i];
            }
        };
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureArray<WordType, 2 * (__Rounds + 1)> _Key;

        void _KeyExpansion(const uint8_t* PtrToUserKey, size_t UserKeySize) noexcept {
            SecureArray<WordType, 256 / sizeof(WordType)> L;
            size_t c;

            c = (UserKeySize + (__WordBits / 8 - 1)) / (__WordBits / 8);
            if (c == 0) c = 1;

            memset(L.GetPtr(), 0, L.Size());
            memcpy(L.GetPtr(), PtrToUserKey, UserKeySize);

            _Key[0] = _P;
            for (size_t i = 1; i < _Key.Length(); ++i)
                _Key[i] = _Key[i - 1] + _Q;

            size_t ii = 0, jj = 0;
            WordType A = 0, B = 0;
            for (size_t i = 0, fin = 3 * (_Key.Length() > c ? _Key.Length() : c); i < fin; ++i) {
                _Key[ii] = RotateShiftLeft<WordType>(_Key[ii] + A + B, 3);
                A = _Key[ii];

                L[jj] = RotateShiftLeft<WordType>(L[jj] + A + B, (A + B) % 64);
                B = L[jj];

                ii = (ii + 1) % _Key.Length();
                jj = (jj + 1) % c;
            }
        }

        __forceinline
        void _EncryptProcess(BlockType& RefBlock) const noexcept {
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

        __forceinline
        void _DecryptProcess(BlockType& RefBlock) const noexcept {
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

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t MinKeySize() const noexcept {
            return MinKeySizeValue;
        }

        constexpr size_t MaxKeySize() const noexcept {
            return MaxKeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* PtrToUserKey, size_t UserKeySize) noexcept {
            if (MinKeySizeValue <= UserKeySize && UserKeySize <= MaxKeySizeValue) {
                _KeyExpansion(reinterpret_cast<const uint8_t*>(PtrToUserKey), 
                              UserKeySize);
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

