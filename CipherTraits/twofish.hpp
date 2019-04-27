#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/twofish_constant.hpp"

namespace accel::CipherTraits {

    template<size_t __KeyBits>
    class TWOFISH_ALG : public Internal::TWOFISH_CONSTANT {
        static_assert(__KeyBits == 128 || __KeyBits == 192 || __KeyBits == 256,
                      "TWOFISH_ALG failure! Invalid __KeyBits.");
    public:
        static constexpr size_t BlockSizeValue = 16;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:

        using BlockType = Array<uint32_t, 4>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<uint32_t, 40> _ExpandedKey;
        Array<uint8_t, __KeyBits / 16> _S;

        template<typename __ByteType>
        ACCEL_FORCEINLINE
        uint32_t _func_h(uint32_t X, const __ByteType& L) const ACCEL_NOEXCEPT {
            auto& x = reinterpret_cast<uint8_t(&)[4]>(X);
            if constexpr (__KeyBits >= 256) {
                x[0] = q1[x[0]] ^ L[12];
                x[1] = q0[x[1]] ^ L[13];
                x[2] = q0[x[2]] ^ L[14];
                x[3] = q1[x[3]] ^ L[15];
            }
            if constexpr (__KeyBits >= 192) {
                x[0] = q1[x[0]] ^ L[8];
                x[1] = q1[x[1]] ^ L[9];
                x[2] = q0[x[2]] ^ L[10];
                x[3] = q0[x[3]] ^ L[11];
            }
            if constexpr (__KeyBits >= 128) {
                x[0] = q1[q0[q0[x[0]] ^ L[4]] ^ L[0]];
                x[1] = q0[q0[q1[x[1]] ^ L[5]] ^ L[1]];
                x[2] = q1[q1[q0[x[2]] ^ L[6]] ^ L[2]];
                x[3] = q0[q1[q1[x[3]] ^ L[7]] ^ L[3]];
            }

            union {
                uint8_t bytes[4];
                uint32_t dword;
            } z;
            z.dword = 0;
            for (int i = 0; i < 4; ++i) {
                z.bytes[i] ^= GF2p8x169MulTable[MDS[i][0]][x[0]];
                z.bytes[i] ^= GF2p8x169MulTable[MDS[i][1]][x[1]];
                z.bytes[i] ^= GF2p8x169MulTable[MDS[i][2]][x[2]];
                z.bytes[i] ^= GF2p8x169MulTable[MDS[i][3]][x[3]];
            }

            return z.dword;
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const uint8_t* pbUserKey) ACCEL_NOEXCEPT {
            Array<uint32_t, __KeyBits / 64> M_e, M_o;

            M_e[0] = reinterpret_cast<const uint32_t*>(pbUserKey)[0];
            M_o[0] = reinterpret_cast<const uint32_t*>(pbUserKey)[1];
            M_e[1] = reinterpret_cast<const uint32_t*>(pbUserKey)[2];
            M_o[1] = reinterpret_cast<const uint32_t*>(pbUserKey)[3];
            if constexpr (__KeyBits >= 192) {
                M_e[2] = reinterpret_cast<const uint32_t*>(pbUserKey)[4];
                M_o[2] = reinterpret_cast<const uint32_t*>(pbUserKey)[5];
            }
            if constexpr (__KeyBits >= 256) {
                M_e[3] = reinterpret_cast<const uint32_t*>(pbUserKey)[6];
                M_o[3] = reinterpret_cast<const uint32_t*>(pbUserKey)[7];
            }

            _S.SecureZero();

            for (size_t i = 0; i < KeySizeValue; ++i) {
                size_t I = __KeyBits / 16 - 4 - (i / 8) * 4;
                _S[I] ^= GF2p8x14DMulTable[RS[0][i % 8]][pbUserKey[i]];
                _S[I + 1] ^= GF2p8x14DMulTable[RS[1][i % 8]][pbUserKey[i]];
                _S[I + 2] ^= GF2p8x14DMulTable[RS[2][i % 8]][pbUserKey[i]];
                _S[I + 3] ^= GF2p8x14DMulTable[RS[3][i % 8]][pbUserKey[i]];
            }

            constexpr uint32_t Rou = 0x01010101;
            for (uint32_t i = 0; i < 20; ++i) {
                uint32_t A = _func_h(2 * i * Rou, M_e.template AsCArrayOf<uint8_t[__KeyBits / 16]>());
                uint32_t B = _func_h((2 * i + 1) * Rou, M_o.template AsCArrayOf<uint8_t[__KeyBits / 16]>());
                B = RotateShiftLeft<uint32_t>(B, 8);
                _ExpandedKey[2 * i] = A + B;
                _ExpandedKey[2 * i + 1] = RotateShiftLeft<uint32_t>(A + 2 * B, 9);
            }

            M_e.SecureZero();
            M_o.SecureZero();
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[0] ^= _ExpandedKey[0];
            RefBlock[1] ^= _ExpandedKey[1];
            RefBlock[2] ^= _ExpandedKey[2];
            RefBlock[3] ^= _ExpandedKey[3];

            for (int i = 0; i < 15; ++i) {
                uint32_t T0 = _func_h(RefBlock[0], _S);
                uint32_t T1 = RotateShiftLeft<uint32_t>(RefBlock[1], 8);
                T1 = _func_h(T1, _S);
                uint32_t F0 = T0 + T1 + _ExpandedKey[2 * i + 8];
                uint32_t F1 = T0 + T1 * 2 + _ExpandedKey[2 * i + 9];

                F0 ^= RefBlock[2];
                F1 ^= RotateShiftLeft<uint32_t>(RefBlock[3], 1);
                RefBlock[2] = RefBlock[0];
                RefBlock[3] = RefBlock[1];
                RefBlock[0] = RotateShiftRight<uint32_t>(F0, 1);
                RefBlock[1] = F1;
            }

            uint32_t T0 = _func_h(RefBlock[0], _S);
            uint32_t T1 = RotateShiftLeft<uint32_t>(RefBlock[1], 8);
            T1 = _func_h(T1, _S);
            uint32_t F0 = T0 + T1 + _ExpandedKey[38];
            uint32_t F1 = T0 + T1 * 2u + _ExpandedKey[39];

            F0 ^= RefBlock[2];
            F1 ^= RotateShiftLeft<uint32_t>(RefBlock[3], 1);
            RefBlock[2] = RotateShiftRight<uint32_t>(F0, 1);
            RefBlock[3] = F1;

            RefBlock[0] ^= _ExpandedKey[4];
            RefBlock[1] ^= _ExpandedKey[5];
            RefBlock[2] ^= _ExpandedKey[6];
            RefBlock[3] ^= _ExpandedKey[7];
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[0] ^= _ExpandedKey[4];
            RefBlock[1] ^= _ExpandedKey[5];
            RefBlock[2] ^= _ExpandedKey[6];
            RefBlock[3] ^= _ExpandedKey[7];

            uint32_t T0 = _func_h(RefBlock[0], _S);
            uint32_t T1 = RotateShiftLeft<uint32_t>(RefBlock[1], 8);
            T1 = _func_h(T1, _S);
            uint32_t F0 = T0 + T1 + _ExpandedKey[38];
            uint32_t F1 = T0 + T1 * 2 + _ExpandedKey[39];

            RefBlock[2] = RotateShiftLeft<uint32_t>(RefBlock[2], 1) ^ F0;
            F1 ^= RefBlock[3];
            RefBlock[3] = RotateShiftRight<uint32_t>(F1, 1);

            for (int i = 14; i >= 0; --i) {
                T0 = _func_h(RefBlock[2], _S);
                T1 = _func_h(RotateShiftLeft<uint32_t>(RefBlock[3], 8), _S);
                F0 = T0 + T1 + _ExpandedKey[2 * i + 8];
                F1 = T0 + T1 * 2 + _ExpandedKey[2 * i + 9];

                F0 ^= RotateShiftLeft<uint32_t>(RefBlock[0], 1);
                F1 ^= RefBlock[1];
                RefBlock[0] = RefBlock[2];
                RefBlock[1] = RefBlock[3];
                RefBlock[3] = RotateShiftRight<uint32_t>(F1, 1);
                RefBlock[2] = F0;
            }

            RefBlock[0] ^= _ExpandedKey[0];
            RefBlock[1] ^= _ExpandedKey[1];
            RefBlock[2] ^= _ExpandedKey[2];
            RefBlock[3] ^= _ExpandedKey[3];
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
                _KeyExpansion(reinterpret_cast<const uint8_t*>(pbUserKey));
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
            _ExpandedKey.SecureZero();
            _S.SecureZero();
        }

        ~TWOFISH_ALG() ACCEL_NOEXCEPT {
            _ExpandedKey.SecureZero();
            _S.SecureZero();
        }
    };

}

