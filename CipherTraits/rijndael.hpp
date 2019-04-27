#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/rijndael_constant.hpp"

namespace accel::CipherTraits {

    template<size_t __KeyBits, size_t __BlockBits>
    class RIJNDAEL_ALG : public Internal::RIJNDAEL_CONSTANT {
        static_assert(__KeyBits == 128 || __KeyBits == 160 || __KeyBits == 192 ||  __KeyBits == 224 || __KeyBits == 256, 
                      "RIJNDAEL_ALG failure! Unsupported __KeyBits.");
        static_assert(__BlockBits == 128 || __BlockBits == 160 || __BlockBits == 192 || __BlockBits == 224 || __BlockBits == 256, 
                      "RIJNDAEL_ALG failure! Unsupported __BlockBits.");
    public:
        static constexpr size_t BlockSizeValue = __BlockBits / 8;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:

        static constexpr size_t _Nb = __BlockBits / 32;
        static constexpr size_t _Nk = __KeyBits / 32;
        static constexpr size_t _Nr = (_Nb > _Nk ? _Nb : _Nk) + 6;

        using BlockType = Array<uint8_t, BlockSizeValue>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        ACCEL_FORCEINLINE
        static void _ByteSub(BlockType& RefBlock) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < BlockSizeValue; ++i)
                RefBlock[i] = SBox[RefBlock[i]];
        }

        ACCEL_FORCEINLINE
        static void _InverseByteSub(BlockType& RefBlock) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < BlockSizeValue; ++i)
                RefBlock[i] = InverseSBox[RefBlock[i]];
        }

        ACCEL_FORCEINLINE
        static void _ShiftRow(BlockType& RefBlock) ACCEL_NOEXCEPT {
            // Nb   C1  C2  C3
            // 4    1   2   3
            // 5    1   2   3
            // 6    1   2   3
            // 7    1   2   4
            // 8    1   3   4
            if constexpr (_Nb == 4) {               // checked
                // 0  4  8  12
                // 1  5  9  13              <<< 1
                // 2  6  10 14              <<< 2
                // 3  7  11 15              <<< 3
                // Shift the second row;
                std::swap(RefBlock[1], RefBlock[5]);    // 5   1  9   13
                std::swap(RefBlock[5], RefBlock[9]);    // 5   9  1   13
                std::swap(RefBlock[9], RefBlock[13]);   // 5   9  13  1
                // Shift the third row;
                std::swap(RefBlock[2], RefBlock[10]);   // 10  6  2   14
                std::swap(RefBlock[6], RefBlock[14]);   // 10  14 2   6
                // Shift the fourth row;
                std::swap(RefBlock[3], RefBlock[15]);   // 15  7  11  3
                std::swap(RefBlock[15], RefBlock[11]);  // 15  7  3   11
                std::swap(RefBlock[11], RefBlock[7]);   // 15  3  7   11
            } else if constexpr (_Nb == 5) {        // checked
                // 0  4  8  12  16
                // 1  5  9  13  17          <<< 1
                // 2  6  10 14  18          <<< 2
                // 3  7  11 15  19          <<< 3
                //Shift the second row;
                std::swap(RefBlock[1], RefBlock[5]);    // 5  1    9   13  17
                std::swap(RefBlock[5], RefBlock[9]);    // 5  9    1   13  17
                std::swap(RefBlock[9], RefBlock[13]);   // 5  9    13  1   17
                std::swap(RefBlock[13], RefBlock[17]);  // 5  9    13  17  1
                //Shift the third row;
                std::swap(RefBlock[2], RefBlock[10]);   // 10  6   2   14  18
                std::swap(RefBlock[6], RefBlock[14]);   // 10  14  2   6   18
                std::swap(RefBlock[10], RefBlock[18]);  // 10  14  18  6   2
                std::swap(RefBlock[14], RefBlock[18]);  // 10  14  18  2   6
                //Shift the fourth row;
                std::swap(RefBlock[3], RefBlock[11]);   // 11  7   3   15  19
                std::swap(RefBlock[7], RefBlock[15]);   // 11  15  3   7   19
                std::swap(RefBlock[3], RefBlock[19]);   // 19  15  3   7   11
                std::swap(RefBlock[3], RefBlock[7]);    // 15  19  3   7   11
            } else if constexpr (_Nb == 6) {        // checked
                // 0  4  8  12  16  20
                // 1  5  9  13  17  21      <<< 1
                // 2  6  10 14  18  22      <<< 2
                // 3  7  11 15  19  23      <<< 3
                // Shift the second row;
                std::swap(RefBlock[1], RefBlock[21]);   // 21  5  9   13  17  1
                std::swap(RefBlock[1], RefBlock[17]);   // 17  5  9   13  21  1
                std::swap(RefBlock[1], RefBlock[13]);   // 13  5  9   17  21  1
                std::swap(RefBlock[1], RefBlock[9]);    // 9   5  13  17  21  1
                std::swap(RefBlock[1], RefBlock[5]);    // 5   9  13  17  21  1
                // Shift the third row;
                std::swap(RefBlock[2], RefBlock[18]);   // 18  6  10  14  2   22
                std::swap(RefBlock[6], RefBlock[22]);   // 18  22 10  14  2   6
                std::swap(RefBlock[2], RefBlock[10]);   // 10  22 18  14  2   6
                std::swap(RefBlock[6], RefBlock[14]);   // 10  14 18  22  2   6
                // Shift the fourth row;
                std::swap(RefBlock[3], RefBlock[15]);   // 15  7  11  3   19  23
                std::swap(RefBlock[7], RefBlock[19]);   // 15  19 11  3   7   23
                std::swap(RefBlock[11], RefBlock[23]);  // 15  19 23  3   7   11
            } else if constexpr (_Nb == 7) {        // checked
                // 0  4  8  12  16  20  24
                // 1  5  9  13  17  21  25      <<< 1
                // 2  6  10 14  18  22  26      <<< 2
                // 3  7  11 15  19  23  27      <<< 4
                // Shift the second row;
                std::swap(RefBlock[1], RefBlock[25]);   // 25  5  9   13  17  21  1
                std::swap(RefBlock[1], RefBlock[21]);   // 21  5  9   13  17  25  1
                std::swap(RefBlock[1], RefBlock[17]);   // 17  5  9   13  21  25  1
                std::swap(RefBlock[1], RefBlock[13]);   // 13  5  9   17  21  25  1
                std::swap(RefBlock[1], RefBlock[9]);    // 9   5  13  17  21  25  1
                std::swap(RefBlock[1], RefBlock[5]);    // 5   9  13  17  21  25  1
                // Shift the third row;
                std::swap(RefBlock[2], RefBlock[22]);   // 22  6  10  14  18  2   26
                std::swap(RefBlock[6], RefBlock[26]);   // 22  26 10  14  18  2   6
                std::swap(RefBlock[2], RefBlock[14]);   // 14  26 10  22  18  2   6
                std::swap(RefBlock[6], RefBlock[18]);   // 14  18 10  22  26  2   6
                std::swap(RefBlock[2], RefBlock[10]);   // 10  18 14  22  26  2   6
                std::swap(RefBlock[6], RefBlock[10]);   // 10  14 18  22  26  2   6
                // Shift the fourth row;
                std::swap(RefBlock[3], RefBlock[15]);   // 15  7  11  3   19  23  27
                std::swap(RefBlock[7], RefBlock[19]);   // 15  19 11  3   7   23  27
                std::swap(RefBlock[11], RefBlock[23]);  // 15  19 23  3   7   11  27
                std::swap(RefBlock[3], RefBlock[27]);   // 27  19 23  3   7   11  15
                std::swap(RefBlock[3], RefBlock[7]);    // 19  27 23  3   7   11  15
                std::swap(RefBlock[7], RefBlock[11]);   // 19  23 27  3   7   11  15
            } else if constexpr (_Nb == 8) {        // checked
                // 0  4  8  12  16  20  24  28
                // 1  5  9  13  17  21  25  29      <<< 1
                // 2  6  10 14  18  22  26  30      <<< 3
                // 3  7  11 15  19  23  27  31      <<< 4
                // Shift the second row;
                std::swap(RefBlock[1], RefBlock[29]);   // 29  5  9   13  17  21  25  1
                std::swap(RefBlock[1], RefBlock[25]);   // 25  5  9   13  17  21  29  1
                std::swap(RefBlock[1], RefBlock[21]);   // 21  5  9   13  17  25  29  1
                std::swap(RefBlock[1], RefBlock[17]);   // 17  5  9   13  21  25  29  1
                std::swap(RefBlock[1], RefBlock[13]);   // 13  5  9   17  21  25  29  1
                std::swap(RefBlock[1], RefBlock[9]);    // 9   5  13  17  21  25  29  1
                std::swap(RefBlock[1], RefBlock[5]);    // 5   9  13  17  21  25  29  1
                // Shift the third row;
                std::swap(RefBlock[2], RefBlock[22]);   // 22  6   10  14  18  2  26  30
                std::swap(RefBlock[6], RefBlock[26]);   // 22  26  10  14  18  2  6   30
                std::swap(RefBlock[10], RefBlock[30]);  // 22  26  30  14  18  2  6   10
                std::swap(RefBlock[2], RefBlock[10]);   // 30  26  22  14  18  2  6   10
                std::swap(RefBlock[6], RefBlock[14]);   // 30  14  22  26  18  2  6   10
                std::swap(RefBlock[2], RefBlock[18]);   // 18  14  22  26  30  2  6   10
                std::swap(RefBlock[2], RefBlock[6]);    // 14  18  22  26  30  2  6   10
                // Shift the fourth row;
                std::swap(RefBlock[3], RefBlock[19]);   // 19  7   11  15  3  23  27  31
                std::swap(RefBlock[7], RefBlock[23]);   // 19  23  11  15  3  7   27  31
                std::swap(RefBlock[11], RefBlock[27]);  // 19  23  27  15  3  7   11  31
                std::swap(RefBlock[15], RefBlock[31]);  // 19  23  27  31  3  7   11  15
            } else {
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        static void _InverseShiftRow(BlockType& RefBlock) ACCEL_NOEXCEPT {
            if constexpr (_Nb == 4) {               // checked
                // Inverse shift the second row;
                std::swap(RefBlock[9], RefBlock[13]);
                std::swap(RefBlock[5], RefBlock[9]);
                std::swap(RefBlock[1], RefBlock[5]);
                // Inverse shift the third row;
                std::swap(RefBlock[6], RefBlock[14]);
                std::swap(RefBlock[2], RefBlock[10]);
                // Inverse shift the fourth row;
                std::swap(RefBlock[11], RefBlock[7]);
                std::swap(RefBlock[15], RefBlock[11]);
                std::swap(RefBlock[3], RefBlock[15]);
            } else if constexpr (_Nb == 5) {        // checked
                // Inverse shift the second row;
                std::swap(RefBlock[13], RefBlock[17]);
                std::swap(RefBlock[9], RefBlock[13]);
                std::swap(RefBlock[5], RefBlock[9]);
                std::swap(RefBlock[1], RefBlock[5]);
                //Inverse shift the third row;
                std::swap(RefBlock[14], RefBlock[18]);
                std::swap(RefBlock[10], RefBlock[18]);
                std::swap(RefBlock[6], RefBlock[14]);
                std::swap(RefBlock[2], RefBlock[10]);
                //Inverse shift the fourth row;
                std::swap(RefBlock[3], RefBlock[7]);
                std::swap(RefBlock[3], RefBlock[19]);
                std::swap(RefBlock[7], RefBlock[15]);
                std::swap(RefBlock[3], RefBlock[11]);
            } else if constexpr (_Nb == 6) {        // checked
                // Inverse shift the second row;
                std::swap(RefBlock[1], RefBlock[5]);
                std::swap(RefBlock[1], RefBlock[9]);
                std::swap(RefBlock[1], RefBlock[13]);
                std::swap(RefBlock[1], RefBlock[17]);
                std::swap(RefBlock[1], RefBlock[21]);
                // Inverse shift the third row;
                std::swap(RefBlock[6], RefBlock[14]);
                std::swap(RefBlock[2], RefBlock[10]);
                std::swap(RefBlock[6], RefBlock[22]);
                std::swap(RefBlock[2], RefBlock[18]);
                // Inverse shift the fourth row;
                std::swap(RefBlock[11], RefBlock[23]);
                std::swap(RefBlock[7], RefBlock[19]);
                std::swap(RefBlock[3], RefBlock[15]);
            } else if constexpr (_Nb == 7) {        // checked
                // Inverse shift the second row;
                std::swap(RefBlock[1], RefBlock[5]);
                std::swap(RefBlock[1], RefBlock[9]);
                std::swap(RefBlock[1], RefBlock[13]);
                std::swap(RefBlock[1], RefBlock[17]);
                std::swap(RefBlock[1], RefBlock[21]);
                std::swap(RefBlock[1], RefBlock[25]);
                // Inverse shift the third row;
                std::swap(RefBlock[6], RefBlock[10]);
                std::swap(RefBlock[2], RefBlock[10]);
                std::swap(RefBlock[6], RefBlock[18]);
                std::swap(RefBlock[2], RefBlock[14]);
                std::swap(RefBlock[6], RefBlock[26]);
                std::swap(RefBlock[2], RefBlock[22]);
                // Shift the fourth row;
                std::swap(RefBlock[7], RefBlock[11]);
                std::swap(RefBlock[3], RefBlock[7]);
                std::swap(RefBlock[3], RefBlock[27]);
                std::swap(RefBlock[11], RefBlock[23]);
                std::swap(RefBlock[7], RefBlock[19]);
                std::swap(RefBlock[3], RefBlock[15]);
            } else if constexpr (_Nb == 8) {        // checked
                // Shift the second row;
                std::swap(RefBlock[1], RefBlock[5]);
                std::swap(RefBlock[1], RefBlock[9]);
                std::swap(RefBlock[1], RefBlock[13]);
                std::swap(RefBlock[1], RefBlock[17]);
                std::swap(RefBlock[1], RefBlock[21]);
                std::swap(RefBlock[1], RefBlock[25]);
                std::swap(RefBlock[1], RefBlock[29]);
                // Shift the third row;
                std::swap(RefBlock[2], RefBlock[6]);
                std::swap(RefBlock[2], RefBlock[18]);
                std::swap(RefBlock[6], RefBlock[14]);
                std::swap(RefBlock[2], RefBlock[10]);
                std::swap(RefBlock[10], RefBlock[30]);
                std::swap(RefBlock[6], RefBlock[26]);
                std::swap(RefBlock[2], RefBlock[22]);
                // Shift the fourth row;
                std::swap(RefBlock[15], RefBlock[31]);
                std::swap(RefBlock[11], RefBlock[27]);
                std::swap(RefBlock[7], RefBlock[23]);
                std::swap(RefBlock[3], RefBlock[19]);
            } else {
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        static void _MatrixTransform(uint8_t* p4b) ACCEL_NOEXCEPT {
            uint32_t result;
            auto& result_bytes = reinterpret_cast<uint8_t(&)[4]>(result);

            result_bytes[0] =
                GF2p8x02[p4b[0]] ^
                GF2p8x03[p4b[1]] ^
                p4b[2] ^
                p4b[3];
            result_bytes[1] =
                p4b[0] ^
                GF2p8x02[p4b[1]] ^
                GF2p8x03[p4b[2]] ^
                p4b[3];
            result_bytes[2] =
                p4b[0] ^
                p4b[1] ^
                GF2p8x02[p4b[2]] ^
                GF2p8x03[p4b[3]];
            result_bytes[3] =
                GF2p8x03[p4b[0]] ^
                p4b[1] ^
                p4b[2] ^
                GF2p8x02[p4b[3]];

            *reinterpret_cast<uint32_t*>(p4b) = result;
            const_cast<volatile uint32_t&>(result) = 0;
        }

        ACCEL_FORCEINLINE
        static void _InverseMatrixTransform(uint8_t* p4b) ACCEL_NOEXCEPT {
            uint32_t result;
            auto& result_bytes = reinterpret_cast<uint8_t(&)[4]>(result);

            result_bytes[0] =
                GF2p8x0E[p4b[0]] ^
                GF2p8x0B[p4b[1]] ^
                GF2p8x0D[p4b[2]] ^
                GF2p8x09[p4b[3]];
            result_bytes[1] =
                GF2p8x09[p4b[0]] ^
                GF2p8x0E[p4b[1]] ^
                GF2p8x0B[p4b[2]] ^
                GF2p8x0D[p4b[3]];
            result_bytes[2] =
                GF2p8x0D[p4b[0]] ^
                GF2p8x09[p4b[1]] ^
                GF2p8x0E[p4b[2]] ^
                GF2p8x0B[p4b[3]];
            result_bytes[3] =
                GF2p8x0B[p4b[0]] ^
                GF2p8x0D[p4b[1]] ^
                GF2p8x09[p4b[2]] ^
                GF2p8x0E[p4b[3]];

            *reinterpret_cast<uint32_t*>(p4b) = result;
            const_cast<volatile uint32_t&>(result) = 0;
        }

        ACCEL_FORCEINLINE
        static void _MixColumn(BlockType& RefBlock) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < _Nb; ++i)
                _MatrixTransform(&RefBlock[4 * i]);
        }

        ACCEL_FORCEINLINE
        static void _InverseMixColumn(BlockType& RefBlock) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < _Nb; ++i)
                _InverseMatrixTransform(&RefBlock[4 * i]);
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const void* pbUserKey) ACCEL_NOEXCEPT {
            _Key.LoadFrom(pbUserKey, KeySizeValue);

            auto& RefKey = _Key.template AsCArrayOf<uint32_t[_Nb * (_Nr + 1)]>();

            for (size_t i = _Nk; i < _Nb * (_Nr + 1); ++i) {
                uint32_t temp = RefKey[i - 1];
                auto temp_bytes = reinterpret_cast<uint8_t (&)[4]>(temp);

                if (i % _Nk == 0) {
                    temp = RotateShiftRight<uint32_t>(temp, 8);
                    temp_bytes[0] = SBox[temp_bytes[0]];
                    temp_bytes[1] = SBox[temp_bytes[1]];
                    temp_bytes[2] = SBox[temp_bytes[2]];
                    temp_bytes[3] = SBox[temp_bytes[3]];
                    temp ^= Rcon[i / _Nk];
                }

                if (_Nk > 6 && i % _Nk == 4) {
                    temp_bytes[0] = SBox[temp_bytes[0]];
                    temp_bytes[1] = SBox[temp_bytes[1]];
                    temp_bytes[2] = SBox[temp_bytes[2]];
                    temp_bytes[3] = SBox[temp_bytes[3]];
                }

                RefKey[i] = RefKey[i - _Nk] ^ temp;
                const_cast<volatile uint32_t&>(temp) = 0;
            }
        }

        ACCEL_FORCEINLINE
        void _XorWithKey(BlockType& RefBlock, size_t Index) const ACCEL_NOEXCEPT {
            RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[0] ^= _Key[Index][0];
            RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[1] ^= _Key[Index][1];
            RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[2] ^= _Key[Index][2];
            RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[3] ^= _Key[Index][3];
            if constexpr (_Nb >= 5) {
                RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[4] ^= _Key[Index][4];
            }
            if constexpr (_Nb >= 6) {
                RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[5] ^= _Key[Index][5];
            }
            if constexpr (_Nb >= 7) {
                RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[6] ^= _Key[Index][6];
            }
            if constexpr (_Nb >= 8) {
                RefBlock.template AsCArrayOf<uint32_t[_Nb]>()[7] ^= _Key[Index][7];
            }
        }

        Array<uint32_t, _Nr + 1, _Nb> _Key;

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
                _KeyExpansion(pbUserKey);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;
            Text.LoadFrom(pbPlaintext);

            _XorWithKey(Text, 0);
            for (size_t i = 1; i < _Nr; ++i) {
                _ByteSub(Text);
                _ShiftRow(Text);
                _MixColumn(Text);
                _XorWithKey(Text, i);
            }
            _ByteSub(Text);
            _ShiftRow(Text);
            _XorWithKey(Text, _Nr);

            Text.StoreTo(pbPlaintext);
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;
            Text.LoadFrom(pbCiphertext);

            _XorWithKey(Text, _Nr);
            _InverseShiftRow(Text);
            _InverseByteSub(Text);
            for (size_t i = 1; i < _Nr; ++i) {
                _XorWithKey(Text, _Nr - i);
                _InverseMixColumn(Text);
                _InverseShiftRow(Text);
                _InverseByteSub(Text);
            }
            _XorWithKey(Text, 0);

            Text.StoreTo(pbCiphertext);
            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~RIJNDAEL_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

    
}

