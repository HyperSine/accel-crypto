#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/cast_constant.hpp"

namespace accel::CipherTraits {

    class CAST128_ALG : public Internal::CAST_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 8;
        static constexpr size_t MinKeySizeValue = 40 / 8;
        static constexpr size_t MaxKeySizeValue = 128 / 8;
    private:

        using BlockType = Array<uint32_t, 2>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 16> _MaskKeys;
        Array<uint32_t, 16> _RotationKeys;
        size_t _Rounds;

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
                static_assert(__TypeNum < 3, "_Transform failure! Invalid __TypeNum.");
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(Array<uint8_t, 16>& x, Array<uint8_t, 16>& z) ACCEL_NOEXCEPT {
            const auto& _S1 = Internal::CAST_CONSTANT::SBox[0];
            const auto& _S2 = Internal::CAST_CONSTANT::SBox[1];
            const auto& _S3 = Internal::CAST_CONSTANT::SBox[2];
            const auto& _S4 = Internal::CAST_CONSTANT::SBox[3];
            const auto& _S5 = Internal::CAST_CONSTANT::SBox[4];
            const auto& _S6 = Internal::CAST_CONSTANT::SBox[5];
            const auto& _S7 = Internal::CAST_CONSTANT::SBox[6];
            const auto& _S8 = Internal::CAST_CONSTANT::SBox[7];

            uint8_t& x0 = x[0x3];
            uint8_t& x1 = x[0x2];
            uint8_t& x2 = x[0x1];
            uint8_t& x3 = x[0x0];
            uint8_t& x4 = x[0x7];
            uint8_t& x5 = x[0x6];
            uint8_t& x6 = x[0x5];
            uint8_t& x7 = x[0x4];
            uint8_t& x8 = x[0xB];
            uint8_t& x9 = x[0xA];
            uint8_t& xA = x[0x9];
            uint8_t& xB = x[0x8];
            uint8_t& xC = x[0xF];
            uint8_t& xD = x[0xE];
            uint8_t& xE = x[0xD];
            uint8_t& xF = x[0xC];

            uint8_t& z0 = z[0x3];
            uint8_t& z1 = z[0x2];
            uint8_t& z2 = z[0x1];
            uint8_t& z3 = z[0x0];
            uint8_t& z4 = z[0x7];
            uint8_t& z5 = z[0x6];
            uint8_t& z6 = z[0x5];
            uint8_t& z7 = z[0x4];
            uint8_t& z8 = z[0xB];
            uint8_t& z9 = z[0xA];
            uint8_t& zA = z[0x9];
            uint8_t& zB = z[0x8];
            uint8_t& zC = z[0xF];
            uint8_t& zD = z[0xE];
            uint8_t& zE = z[0xD];
            uint8_t& zF = z[0xC];

            uint32_t& K1 = _MaskKeys[0];
            uint32_t& K2 = _MaskKeys[1];
            uint32_t& K3 = _MaskKeys[2];
            uint32_t& K4 = _MaskKeys[3];
            uint32_t& K5 = _MaskKeys[4];
            uint32_t& K6 = _MaskKeys[5];
            uint32_t& K7 = _MaskKeys[6];
            uint32_t& K8 = _MaskKeys[7];
            uint32_t& K9 = _MaskKeys[8];
            uint32_t& K10 = _MaskKeys[9];
            uint32_t& K11 = _MaskKeys[10];
            uint32_t& K12 = _MaskKeys[11];
            uint32_t& K13 = _MaskKeys[12];
            uint32_t& K14 = _MaskKeys[13];
            uint32_t& K15 = _MaskKeys[14];
            uint32_t& K16 = _MaskKeys[15];
            uint32_t& K17 = _RotationKeys[0];
            uint32_t& K18 = _RotationKeys[1];
            uint32_t& K19 = _RotationKeys[2];
            uint32_t& K20 = _RotationKeys[3];
            uint32_t& K21 = _RotationKeys[4];
            uint32_t& K22 = _RotationKeys[5];
            uint32_t& K23 = _RotationKeys[6];
            uint32_t& K24 = _RotationKeys[7];
            uint32_t& K25 = _RotationKeys[8];
            uint32_t& K26 = _RotationKeys[9];
            uint32_t& K27 = _RotationKeys[10];
            uint32_t& K28 = _RotationKeys[11];
            uint32_t& K29 = _RotationKeys[12];
            uint32_t& K30 = _RotationKeys[13];
            uint32_t& K31 = _RotationKeys[14];
            uint32_t& K32 = _RotationKeys[15];

            uint32_t& x0x1x2x3 = x.template AsCArrayOf<uint32_t[4]>()[0];
            uint32_t& x4x5x6x7 = x.template AsCArrayOf<uint32_t[4]>()[1];
            uint32_t& x8x9xAxB = x.template AsCArrayOf<uint32_t[4]>()[2];
            uint32_t& xCxDxExF = x.template AsCArrayOf<uint32_t[4]>()[3];

            uint32_t& z0z1z2z3 = z.template AsCArrayOf<uint32_t[4]>()[0];
            uint32_t& z4z5z6z7 = z.template AsCArrayOf<uint32_t[4]>()[1];
            uint32_t& z8z9zAzB = z.template AsCArrayOf<uint32_t[4]>()[2];
            uint32_t& zCzDzEzF = z.template AsCArrayOf<uint32_t[4]>()[3];

            z0z1z2z3 = x0x1x2x3 ^ _S5[xD] ^ _S6[xF] ^ _S7[xC] ^ _S8[xE] ^ _S7[x8];
            z4z5z6z7 = x8x9xAxB ^ _S5[z0] ^ _S6[z2] ^ _S7[z1] ^ _S8[z3] ^ _S8[xA];
            z8z9zAzB = xCxDxExF ^ _S5[z7] ^ _S6[z6] ^ _S7[z5] ^ _S8[z4] ^ _S5[x9];
            zCzDzEzF = x4x5x6x7 ^ _S5[zA] ^ _S6[z9] ^ _S7[zB] ^ _S8[z8] ^ _S6[xB];

            K1 = _S5[z8] ^ _S6[z9] ^ _S7[z7] ^ _S8[z6] ^ _S5[z2];
            K2 = _S5[zA] ^ _S6[zB] ^ _S7[z5] ^ _S8[z4] ^ _S6[z6];
            K3 = _S5[zC] ^ _S6[zD] ^ _S7[z3] ^ _S8[z2] ^ _S7[z9];
            K4 = _S5[zE] ^ _S6[zF] ^ _S7[z1] ^ _S8[z0] ^ _S8[zC];
            x0x1x2x3 = z8z9zAzB ^ _S5[z5] ^ _S6[z7] ^ _S7[z4] ^ _S8[z6] ^ _S7[z0];
            x4x5x6x7 = z0z1z2z3 ^ _S5[x0] ^ _S6[x2] ^ _S7[x1] ^ _S8[x3] ^ _S8[z2];
            x8x9xAxB = z4z5z6z7 ^ _S5[x7] ^ _S6[x6] ^ _S7[x5] ^ _S8[x4] ^ _S5[z1];
            xCxDxExF = zCzDzEzF ^ _S5[xA] ^ _S6[x9] ^ _S7[xB] ^ _S8[x8] ^ _S6[z3];
            K5 = _S5[x3] ^ _S6[x2] ^ _S7[xC] ^ _S8[xD] ^ _S5[x8];
            K6 = _S5[x1] ^ _S6[x0] ^ _S7[xE] ^ _S8[xF] ^ _S6[xD];
            K7 = _S5[x7] ^ _S6[x6] ^ _S7[x8] ^ _S8[x9] ^ _S7[x3];
            K8 = _S5[x5] ^ _S6[x4] ^ _S7[xA] ^ _S8[xB] ^ _S8[x7];
            z0z1z2z3 = x0x1x2x3 ^ _S5[xD] ^ _S6[xF] ^ _S7[xC] ^ _S8[xE] ^ _S7[x8];
            z4z5z6z7 = x8x9xAxB ^ _S5[z0] ^ _S6[z2] ^ _S7[z1] ^ _S8[z3] ^ _S8[xA];
            z8z9zAzB = xCxDxExF ^ _S5[z7] ^ _S6[z6] ^ _S7[z5] ^ _S8[z4] ^ _S5[x9];
            zCzDzEzF = x4x5x6x7 ^ _S5[zA] ^ _S6[z9] ^ _S7[zB] ^ _S8[z8] ^ _S6[xB];
            K9 = _S5[z3] ^ _S6[z2] ^ _S7[zC] ^ _S8[zD] ^ _S5[z9];
            K10 = _S5[z1] ^ _S6[z0] ^ _S7[zE] ^ _S8[zF] ^ _S6[zC];
            K11 = _S5[z7] ^ _S6[z6] ^ _S7[z8] ^ _S8[z9] ^ _S7[z2];
            K12 = _S5[z5] ^ _S6[z4] ^ _S7[zA] ^ _S8[zB] ^ _S8[z6];
            x0x1x2x3 = z8z9zAzB ^ _S5[z5] ^ _S6[z7] ^ _S7[z4] ^ _S8[z6] ^ _S7[z0];
            x4x5x6x7 = z0z1z2z3 ^ _S5[x0] ^ _S6[x2] ^ _S7[x1] ^ _S8[x3] ^ _S8[z2];
            x8x9xAxB = z4z5z6z7 ^ _S5[x7] ^ _S6[x6] ^ _S7[x5] ^ _S8[x4] ^ _S5[z1];
            xCxDxExF = zCzDzEzF ^ _S5[xA] ^ _S6[x9] ^ _S7[xB] ^ _S8[x8] ^ _S6[z3];
            K13 = _S5[x8] ^ _S6[x9] ^ _S7[x7] ^ _S8[x6] ^ _S5[x3];
            K14 = _S5[xA] ^ _S6[xB] ^ _S7[x5] ^ _S8[x4] ^ _S6[x7];
            K15 = _S5[xC] ^ _S6[xD] ^ _S7[x3] ^ _S8[x2] ^ _S7[x8];
            K16 = _S5[xE] ^ _S6[xF] ^ _S7[x1] ^ _S8[x0] ^ _S8[xD];

            z0z1z2z3 = x0x1x2x3 ^ _S5[xD] ^ _S6[xF] ^ _S7[xC] ^ _S8[xE] ^ _S7[x8];
            z4z5z6z7 = x8x9xAxB ^ _S5[z0] ^ _S6[z2] ^ _S7[z1] ^ _S8[z3] ^ _S8[xA];
            z8z9zAzB = xCxDxExF ^ _S5[z7] ^ _S6[z6] ^ _S7[z5] ^ _S8[z4] ^ _S5[x9];
            zCzDzEzF = x4x5x6x7 ^ _S5[zA] ^ _S6[z9] ^ _S7[zB] ^ _S8[z8] ^ _S6[xB];
            K17 = _S5[z8] ^ _S6[z9] ^ _S7[z7] ^ _S8[z6] ^ _S5[z2];
            K18 = _S5[zA] ^ _S6[zB] ^ _S7[z5] ^ _S8[z4] ^ _S6[z6];
            K19 = _S5[zC] ^ _S6[zD] ^ _S7[z3] ^ _S8[z2] ^ _S7[z9];
            K20 = _S5[zE] ^ _S6[zF] ^ _S7[z1] ^ _S8[z0] ^ _S8[zC];
            x0x1x2x3 = z8z9zAzB ^ _S5[z5] ^ _S6[z7] ^ _S7[z4] ^ _S8[z6] ^ _S7[z0];
            x4x5x6x7 = z0z1z2z3 ^ _S5[x0] ^ _S6[x2] ^ _S7[x1] ^ _S8[x3] ^ _S8[z2];
            x8x9xAxB = z4z5z6z7 ^ _S5[x7] ^ _S6[x6] ^ _S7[x5] ^ _S8[x4] ^ _S5[z1];
            xCxDxExF = zCzDzEzF ^ _S5[xA] ^ _S6[x9] ^ _S7[xB] ^ _S8[x8] ^ _S6[z3];
            K21 = _S5[x3] ^ _S6[x2] ^ _S7[xC] ^ _S8[xD] ^ _S5[x8];
            K22 = _S5[x1] ^ _S6[x0] ^ _S7[xE] ^ _S8[xF] ^ _S6[xD];
            K23 = _S5[x7] ^ _S6[x6] ^ _S7[x8] ^ _S8[x9] ^ _S7[x3];
            K24 = _S5[x5] ^ _S6[x4] ^ _S7[xA] ^ _S8[xB] ^ _S8[x7];
            z0z1z2z3 = x0x1x2x3 ^ _S5[xD] ^ _S6[xF] ^ _S7[xC] ^ _S8[xE] ^ _S7[x8];
            z4z5z6z7 = x8x9xAxB ^ _S5[z0] ^ _S6[z2] ^ _S7[z1] ^ _S8[z3] ^ _S8[xA];
            z8z9zAzB = xCxDxExF ^ _S5[z7] ^ _S6[z6] ^ _S7[z5] ^ _S8[z4] ^ _S5[x9];
            zCzDzEzF = x4x5x6x7 ^ _S5[zA] ^ _S6[z9] ^ _S7[zB] ^ _S8[z8] ^ _S6[xB];
            K25 = _S5[z3] ^ _S6[z2] ^ _S7[zC] ^ _S8[zD] ^ _S5[z9];
            K26 = _S5[z1] ^ _S6[z0] ^ _S7[zE] ^ _S8[zF] ^ _S6[zC];
            K27 = _S5[z7] ^ _S6[z6] ^ _S7[z8] ^ _S8[z9] ^ _S7[z2];
            K28 = _S5[z5] ^ _S6[z4] ^ _S7[zA] ^ _S8[zB] ^ _S8[z6];
            x0x1x2x3 = z8z9zAzB ^ _S5[z5] ^ _S6[z7] ^ _S7[z4] ^ _S8[z6] ^ _S7[z0];
            x4x5x6x7 = z0z1z2z3 ^ _S5[x0] ^ _S6[x2] ^ _S7[x1] ^ _S8[x3] ^ _S8[z2];
            x8x9xAxB = z4z5z6z7 ^ _S5[x7] ^ _S6[x6] ^ _S7[x5] ^ _S8[x4] ^ _S5[z1];
            xCxDxExF = zCzDzEzF ^ _S5[xA] ^ _S6[x9] ^ _S7[xB] ^ _S8[x8] ^ _S6[z3];
            K29 = _S5[x8] ^ _S6[x9] ^ _S7[x7] ^ _S8[x6] ^ _S5[x3];
            K30 = _S5[xA] ^ _S6[xB] ^ _S7[x5] ^ _S8[x4] ^ _S6[x7];
            K31 = _S5[xC] ^ _S6[xD] ^ _S7[x3] ^ _S8[x2] ^ _S7[x8];
            K32 = _S5[xE] ^ _S6[xF] ^ _S7[x1] ^ _S8[x0] ^ _S8[xD];

            for (size_t i = _Rounds; i < 16; ++i) {
                _MaskKeys[i] = 0;
                _RotationKeys[i] = 0;
            }

            for (size_t i = 0; i < _Rounds; ++i)
                _RotationKeys[i] %= 32;
        }

        template<uint32_t __Tag, size_t __Index>
        ACCEL_FORCEINLINE
        void _EncryptDecryptLoop(uint32_t& L, uint32_t& R) const ACCEL_NOEXCEPT {
            if constexpr (__Tag == 'enc') {
                uint32_t temp = L;
                L = R;
                R = temp ^ _Transform<__Index % 3>(_MaskKeys[__Index], _RotationKeys[__Index], R);
            } else if constexpr (__Tag == 'dec') {
                uint32_t temp = R ^ _Transform<__Index % 3>(_MaskKeys[__Index], _RotationKeys[__Index], L);
                R = L;
                L = temp;
            } else {
                static_assert(__Tag == 'enc' || __Tag == 'dec');
                ACCEL_UNREACHABLE();
            }
        }

        template<uint32_t __Tag, size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _EncryptDecryptLoops(uint32_t& L, uint32_t& R, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_EncryptDecryptLoop<__Tag, __Indexes>(L, R), ...);
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t& L = RefBlock[0];
            uint32_t& R = RefBlock[1];

            L = ByteSwap<uint32_t>(L);
            R = ByteSwap<uint32_t>(R);

            _EncryptDecryptLoops<'enc'>(L, R, std::make_index_sequence<12>{});

            if (_Rounds > 12) {
                uint32_t temp;

                temp = L;
                L = R;
                R = temp ^ _Transform<0>(_MaskKeys[12], _RotationKeys[12], R);

                temp = L;
                L = R;
                R = temp ^ _Transform<1>(_MaskKeys[13], _RotationKeys[13], R);

                temp = L;
                L = R;
                R = temp ^ _Transform<2>(_MaskKeys[14], _RotationKeys[14], R);

                temp = L;
                L = R;
                R = temp ^ _Transform<0>(_MaskKeys[15], _RotationKeys[15], R);
            }

            std::swap(L, R);

            L = ByteSwap<uint32_t>(L);
            R = ByteSwap<uint32_t>(R);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t& L = RefBlock[0];
            uint32_t& R = RefBlock[1];

            L = ByteSwap<uint32_t>(L);
            R = ByteSwap<uint32_t>(R);

            std::swap(L, R);

            if (_Rounds > 12) {
                uint32_t temp;

                temp = R ^ _Transform<0>(_MaskKeys[15], _RotationKeys[15], L);
                R = L;
                L = temp;

                temp = R ^ _Transform<2>(_MaskKeys[14], _RotationKeys[14], L);
                R = L;
                L = temp;

                temp = R ^ _Transform<1>(_MaskKeys[13], _RotationKeys[13], L);
                R = L;
                L = temp;

                temp = R ^ _Transform<0>(_MaskKeys[12], _RotationKeys[12], L);
                R = L;
                L = temp;
            }

            _EncryptDecryptLoops<'dec'>(L, R, std::index_sequence<11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0>{});

            L = ByteSwap<uint32_t>(L);
            R = ByteSwap<uint32_t>(R);
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
        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (cbUserKey < MinKeySizeValue || cbUserKey > MaxKeySizeValue) {
                return false;
            } else {
                Array<uint8_t, 16> x = {}, z = {};

                x.LoadFrom(pbUserKey, cbUserKey);

                x.template AsCArrayOf<uint32_t[4]>()[0] = ByteSwap<uint32_t>(x.template AsCArrayOf<uint32_t[4]>()[0]);
                x.template AsCArrayOf<uint32_t[4]>()[1] = ByteSwap<uint32_t>(x.template AsCArrayOf<uint32_t[4]>()[1]);
                x.template AsCArrayOf<uint32_t[4]>()[2] = ByteSwap<uint32_t>(x.template AsCArrayOf<uint32_t[4]>()[2]);
                x.template AsCArrayOf<uint32_t[4]>()[3] = ByteSwap<uint32_t>(x.template AsCArrayOf<uint32_t[4]>()[3]);

                _Rounds = cbUserKey > 10 ? 16 : 12;

                _KeyExpansion(x, z);

                x.SecureZero();
                z.SecureZero();
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
            _MaskKeys.SecureZero();
            _RotationKeys.SecureZero();
        }

        ~CAST128_ALG() ACCEL_NOEXCEPT {
            _MaskKeys.SecureZero();
            _RotationKeys.SecureZero();
            _Rounds = 0;
        }
    };

    using CAST5_ALG = CAST128_ALG;
}

