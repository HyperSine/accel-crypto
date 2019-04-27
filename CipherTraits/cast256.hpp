#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/cast_constant.hpp"

namespace accel::Crypto {

    template<size_t __KeyBits>
    class CAST256_ALG : public Internal::CAST_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 128 / 8;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:

        using BlockType = accel::Array<uint32_t, 4>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 12, 4> _MaskKeys;
        Array<uint32_t, 12, 4> _RotationKeys;

        template<size_t __TypeNum>
        ACCEL_FORCEINLINE
        static uint32_t _Transform(uint32_t MaskKey, uint32_t RotationKey, uint32_t Data) ACCEL_NOEXCEPT {
            union {
                uint8_t I4B[4];
                uint32_t I;
            };

            if constexpr (__TypeNum == 0) {
                I = RotateShiftLeft<uint32_t>(MaskKey + Data, RotationKey);
                return ((SBox[0][I4B[3]] ^ SBox[1][I4B[2]]) - SBox[2][I4B[1]]) + SBox[3][I4B[0]];
            } else if constexpr (__TypeNum == 1) {
                I = RotateShiftLeft<uint32_t>(MaskKey ^ Data, RotationKey);
                return ((SBox[0][I4B[3]] - SBox[1][I4B[2]]) + SBox[2][I4B[1]]) ^ SBox[3][I4B[0]];
            } else if constexpr (__TypeNum == 2) {
                I = RotateShiftLeft<uint32_t>(MaskKey - Data, RotationKey);
                return ((SBox[0][I4B[3]] + SBox[1][I4B[2]]) ^ SBox[2][I4B[1]]) - SBox[3][I4B[0]];
            } else {
                static_assert(__TypeNum < 3);
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        static void _Omega(int i, Array<uint32_t, 8>& Kappa) ACCEL_NOEXCEPT {
            Kappa['G' - 'A'] ^= _Transform<0>(Tm[0][i], Tr[0][i], Kappa['H' - 'A']);
            Kappa['F' - 'A'] ^= _Transform<1>(Tm[1][i], Tr[1][i], Kappa['G' - 'A']);
            Kappa['E' - 'A'] ^= _Transform<2>(Tm[2][i], Tr[2][i], Kappa['F' - 'A']);
            Kappa['D' - 'A'] ^= _Transform<0>(Tm[3][i], Tr[3][i], Kappa['E' - 'A']);
            Kappa['C' - 'A'] ^= _Transform<1>(Tm[4][i], Tr[4][i], Kappa['D' - 'A']);
            Kappa['B' - 'A'] ^= _Transform<2>(Tm[5][i], Tr[5][i], Kappa['C' - 'A']);
            Kappa['A' - 'A'] ^= _Transform<0>(Tm[6][i], Tr[6][i], Kappa['B' - 'A']);
            Kappa['H' - 'A'] ^= _Transform<1>(Tm[7][i], Tr[7][i], Kappa['A' - 'A']);
        }

        template<size_t __Index, uint32_t __Tag>
        ACCEL_FORCEINLINE
        void _QTransform(BlockType& beta) const ACCEL_NOEXCEPT {
            if constexpr (__Tag == 'enc') {
                beta['C' - 'A'] ^= _Transform<0>(_MaskKeys[__Index][0], _RotationKeys[__Index][0], beta['D' - 'A']);
                beta['B' - 'A'] ^= _Transform<1>(_MaskKeys[__Index][1], _RotationKeys[__Index][1], beta['C' - 'A']);
                beta['A' - 'A'] ^= _Transform<2>(_MaskKeys[__Index][2], _RotationKeys[__Index][2], beta['B' - 'A']);
                beta['D' - 'A'] ^= _Transform<0>(_MaskKeys[__Index][3], _RotationKeys[__Index][3], beta['A' - 'A']);
            } else if constexpr (__Tag == 'dec') {
                beta['C' - 'A'] ^= _Transform<0>(_MaskKeys[11 - __Index][0], _RotationKeys[11 - __Index][0], beta['D' - 'A']);
                beta['B' - 'A'] ^= _Transform<1>(_MaskKeys[11 - __Index][1], _RotationKeys[11 - __Index][1], beta['C' - 'A']);
                beta['A' - 'A'] ^= _Transform<2>(_MaskKeys[11 - __Index][2], _RotationKeys[11 - __Index][2], beta['B' - 'A']);
                beta['D' - 'A'] ^= _Transform<0>(_MaskKeys[11 - __Index][3], _RotationKeys[11 - __Index][3], beta['A' - 'A']);
            } else {
                static_assert(__Tag == 'enc' || __Tag == 'dec');
                ACCEL_UNREACHABLE();
            }
        }

        template<size_t __Index, uint32_t __Tag>
        ACCEL_FORCEINLINE
        void _QBarTransform(BlockType& beta) const ACCEL_NOEXCEPT {
            if constexpr (__Tag == 'enc') {
                beta['D' - 'A'] ^= _Transform<0>(_MaskKeys[__Index][3], _RotationKeys[__Index][3], beta['A' - 'A']);
                beta['A' - 'A'] ^= _Transform<2>(_MaskKeys[__Index][2], _RotationKeys[__Index][2], beta['B' - 'A']);
                beta['B' - 'A'] ^= _Transform<1>(_MaskKeys[__Index][1], _RotationKeys[__Index][1], beta['C' - 'A']);
                beta['C' - 'A'] ^= _Transform<0>(_MaskKeys[__Index][0], _RotationKeys[__Index][0], beta['D' - 'A']);
            } else if constexpr (__Tag == 'dec') {
                beta['D' - 'A'] ^= _Transform<0>(_MaskKeys[11 - __Index][3], _RotationKeys[11 - __Index][3], beta['A' - 'A']);
                beta['A' - 'A'] ^= _Transform<2>(_MaskKeys[11 - __Index][2], _RotationKeys[11 - __Index][2], beta['B' - 'A']);
                beta['B' - 'A'] ^= _Transform<1>(_MaskKeys[11 - __Index][1], _RotationKeys[11 - __Index][1], beta['C' - 'A']);
                beta['C' - 'A'] ^= _Transform<0>(_MaskKeys[11 - __Index][0], _RotationKeys[11 - __Index][0], beta['D' - 'A']);
            } else {
                static_assert(__Tag == 'enc' || __Tag == 'dec');
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(Array<uint32_t, 8>& Kappa) ACCEL_NOEXCEPT {
            for (int i = 0; i < 12; ++i) {
                _Omega(2 * i, Kappa);
                _Omega(2 * i + 1, Kappa);

                _MaskKeys[i][0] = Kappa['H' - 'A'];
                _MaskKeys[i][1] = Kappa['F' - 'A'];
                _MaskKeys[i][2] = Kappa['D' - 'A'];
                _MaskKeys[i][3] = Kappa['B' - 'A'];

                _RotationKeys[i][0] = Kappa['A' - 'A'] % 32;
                _RotationKeys[i][1] = Kappa['C' - 'A'] % 32;
                _RotationKeys[i][2] = Kappa['E' - 'A'] % 32;
                _RotationKeys[i][3] = Kappa['G' - 'A'] % 32;
            }
        }

        template<size_t __Index, uint32_t __Tag>
        ACCEL_FORCEINLINE
        void _EncryptDecryptLoop(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            if constexpr (__Index < 6) {
                _QTransform<__Index, __Tag>(RefBlock);
            } else if constexpr (6 <= __Index && __Index < 12) {
                _QBarTransform<__Index, __Tag>(RefBlock);
            } else {
                static_assert(__Index < 12);
            }
        }

        template<uint32_t __Tag, size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _EncryptDecryptLoops(BlockType& RefBlock, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_EncryptDecryptLoop<__Indexes, __Tag>(RefBlock), ...);
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
                Array<uint32_t, 8> Kappa = {};

                Kappa.LoadFrom(pbUserKey, cbUserKey);

                Kappa[0] = ByteSwap<uint32_t>(Kappa[0]);
                Kappa[1] = ByteSwap<uint32_t>(Kappa[1]);
                Kappa[2] = ByteSwap<uint32_t>(Kappa[2]);
                Kappa[3] = ByteSwap<uint32_t>(Kappa[3]);
                Kappa[4] = ByteSwap<uint32_t>(Kappa[4]);
                Kappa[5] = ByteSwap<uint32_t>(Kappa[5]);
                Kappa[6] = ByteSwap<uint32_t>(Kappa[6]);
                Kappa[7] = ByteSwap<uint32_t>(Kappa[7]);

                _KeyExpansion(Kappa);

                Kappa.SecureZero();

                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);
            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);
            Text[2] = ByteSwap<uint32_t>(Text[2]);
            Text[3] = ByteSwap<uint32_t>(Text[3]);

            _EncryptDecryptLoops<'enc'>(Text, std::make_index_sequence<12>{});

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);
            Text[2] = ByteSwap<uint32_t>(Text[2]);
            Text[3] = ByteSwap<uint32_t>(Text[3]);
            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);
            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);
            Text[2] = ByteSwap<uint32_t>(Text[2]);
            Text[3] = ByteSwap<uint32_t>(Text[3]);

            _EncryptDecryptLoops<'dec'>(Text, std::make_index_sequence<12>{});

            Text[0] = ByteSwap<uint32_t>(Text[0]);
            Text[1] = ByteSwap<uint32_t>(Text[1]);
            Text[2] = ByteSwap<uint32_t>(Text[2]);
            Text[3] = ByteSwap<uint32_t>(Text[3]);
            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _MaskKeys.SecureZero();
            _RotationKeys.SecureZero();
        }

        ~CAST256_ALG() ACCEL_NOEXCEPT {
            _MaskKeys.SecureZero();
            _RotationKeys.SecureZero();
        }
    };

    template<size_t __KeyBits>
    using CAST6_ALG = CAST256_ALG<__KeyBits>;
}
