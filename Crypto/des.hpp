#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "Internal/des_constant.hpp"

namespace accel::Crypto {

    class DES_ALG : public Internal::DES_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 8;
        static constexpr size_t KeySizeValue = 8;
    private:

        using Word24Type = uint32_t;    // The highest 8-bits must be cleared
        using Word28Type = uint32_t;    // The highest 4-bits must be cleared

        struct KeyPairType {
            Word24Type Left;
            Word24Type Right;
        };

        using BlockType = Array<uint8_t, 8>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<KeyPairType, 16> _Key;

        template<unsigned __N>
        ACCEL_FORCEINLINE
        static uint32_t _Word24ExtractNth6Bits(Word24Type X) ACCEL_NOEXCEPT {
            if constexpr (__N == 0) {
                return X >> 18u;
            } else if constexpr (0 < __N && __N < 4) {
                return (X >> ((3u - __N) * 6u)) & 0x0000003Fu;
            } else {
                static_assert(__N < 4);
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        static Word28Type _Word28RotateShiftLeft(Word28Type X, unsigned shift) ACCEL_NOEXCEPT {
            return ((X << shift) | (X >> (28u - shift))) & 0x0FFFFFFFu;
        }

        template<unsigned __N>
        ACCEL_FORCEINLINE
        static Word28Type _Word28ExtractNth4Bits(Word28Type X) ACCEL_NOEXCEPT {
            if constexpr (__N == 0) {
                return X >> 24u;
            } else if constexpr (0 < __N && __N < 7) {
                return (X >> ((6u - __N) * 4u)) & 0x0000000Fu;
            } else {
                static_assert(__N < 7);
                ACCEL_UNREACHABLE();
            }
        }

        ACCEL_FORCEINLINE
        static void _InitialPermutation(const BlockType& RefBlock, uint32_t& OutLeft, uint32_t& OutRight) ACCEL_NOEXCEPT {
#if defined(ACCEL_CONFIG_OPTION_DES_NO_LOOKUP_TABLE)
            uint32_t temp;

            OutLeft = ByteSwap<uint32_t>(RefBlock.template AsCArrayOf<uint32_t[2]>()[0]);
            OutRight = ByteSwap<uint32_t>(RefBlock.template AsCArrayOf<uint32_t[2]>()[1]);

            temp = ((OutLeft >> 4) ^ OutRight) & 0x0F0F0F0F;
            OutRight ^= temp;
            OutLeft ^= (temp << 4);

            temp = ((OutLeft >> 16) ^ OutRight) & 0x0000FFFF;
            OutRight ^= temp;
            OutLeft ^= (temp << 16);

            temp = ((OutRight >> 2) ^ OutLeft) & 0x33333333;
            OutLeft ^= temp;
            OutRight ^= (temp << 2);

            temp = ((OutRight >> 8) ^ OutLeft) & 0x00FF00FF;
            OutLeft ^= temp;
            OutRight ^= (temp << 8);

            OutRight = RotateShiftLeft<uint32_t>(OutRight, 1);
            temp = (OutLeft ^ OutRight) & 0xAAAAAAAA;
            OutLeft ^= temp;
            OutRight ^= temp;
            OutRight = RotateShiftRight<uint32_t>(OutRight, 1);
#else
            uint32_t temp[2];

            *reinterpret_cast<uint64_t*>(temp) =
                IPTable[0][RefBlock[0]] ^
                IPTable[1][RefBlock[1]] ^
                IPTable[2][RefBlock[2]] ^
                IPTable[3][RefBlock[3]] ^
                IPTable[4][RefBlock[4]] ^
                IPTable[5][RefBlock[5]] ^
                IPTable[6][RefBlock[6]] ^
                IPTable[7][RefBlock[7]];

            OutLeft = ByteSwap<uint32_t>(temp[0]);
            OutRight = ByteSwap<uint32_t>(temp[1]);
#endif
        }

        ACCEL_FORCEINLINE
        static void _InverseInitialPermutation(BlockType& RefBlock, uint32_t& InLeft, uint32_t& InRight) ACCEL_NOEXCEPT {
#if defined(ACCEL_CONFIG_OPTION_DES_NO_LOOKUP_TABLE)
            uint32_t temp;

            InRight = RotateShiftLeft<uint32_t>(InRight, 1);
            temp = (InRight ^ InLeft) & 0xAAAAAAAAu;
            InRight ^= temp;
            InLeft ^= temp;
            InRight = RotateShiftRight<uint32_t>(InRight, 1);

            temp = ((InRight >> 8) ^ InLeft) & 0x00FF00FFu;
            InLeft ^= temp;
            InRight ^= (temp << 8);

            temp = ((InRight >> 2) ^ InLeft) & 0x33333333u;
            InLeft ^= temp;
            InRight ^= (temp << 2);

            temp = ((InLeft >> 16) ^ InRight) & 0x0000FFFFu;
            InRight ^= temp;
            InLeft ^= (temp << 16);

            temp = ((InLeft >> 4) ^ InRight) & 0x0F0F0F0Fu;
            InRight ^= temp;
            InLeft ^= (temp << 4);

            RefBlock.template AsCArrayOf<uint32_t[2]>()[0] = ByteSwap<uint32_t>(InLeft);
            RefBlock.template AsCArrayOf<uint32_t[2]>()[1] = ByteSwap<uint32_t>(InRight);
#else
            InLeft = ByteSwap<uint32_t>(InLeft);
            InRight = ByteSwap<uint32_t>(InRight);

            const auto& InLeftBytes = reinterpret_cast<const uint8_t (&)[4]>(InLeft);
            const auto& InRightBytes = reinterpret_cast<const uint8_t (&)[4]>(InRight);

            RefBlock.template AsCArrayOf<uint64_t[1]>()[0] =
                FPTable[0][InLeftBytes[0]] ^
                FPTable[1][InLeftBytes[1]] ^
                FPTable[2][InLeftBytes[2]] ^
                FPTable[3][InLeftBytes[3]] ^
                FPTable[4][InRightBytes[0]] ^
                FPTable[5][InRightBytes[1]] ^
                FPTable[6][InRightBytes[2]] ^
                FPTable[7][InRightBytes[3]];
#endif
        }

        ACCEL_FORCEINLINE
        uint32_t _CipherFunction(uint32_t R, size_t i) const ACCEL_NOEXCEPT {
            Word24Type L24, R24;

            // do E Bit-Selection
            {
                //  ---------E Bit-Selection Table---------------
                //  32  1   2   3   4   5
                //  4   5   6   7   8   9
                //  8   9   10  11  12  13
                //  12  13  14  15  16  17
                //  16  17  18  19  20  21
                //  20  21  22  23  24  25
                //  24  25  26  27  28  29
                //  28  29  30  31  32  1
                //  --------------------------------------------


                //  ------------------------------------------------------L24
                //                  24  25
                //  26  27  28  29  30  31
                //  32  1   2   3   4   5   //  mask = 0x00FC0000u
                //  6   7   8   9   10  11
                //  12  13  14  15  16  17
                //  18  19  20  21  22  23
                R = RotateShiftRight<uint32_t>(R, 9);
                L24 =  R & 0x00FC0000u;
                //  ------------------------------------------------------L24
                //                  22  23
                //  24  25  26  27  28  29
                //  30  31  32  1   2   3
                //  4   5   6   7   8   9   //  mask = 0x0003F000u
                //  10  11  12  13  14  15
                //  16  17  18  19  20  21
                R = RotateShiftRight<uint32_t>(R, 2);
                L24 ^= R & 0x0003F000u;
                //  ------------------------------------------------------L24
                //                  20  21
                //  22  23  24  25  26  27
                //  28  29  30  31  32  1
                //  2   3   4   5   6   7
                //  8   9   10  11  12  13  //  mask = 0x00000FC0u
                //  14  15  16  17  18  19
                R = RotateShiftRight<uint32_t>(R, 2);
                L24 ^= R & 0x00000FC0u;
                //  ------------------------------------------------------L24
                //                  18  19
                //  20  21  22  23  24  25
                //  26  27  28  29  30  31
                //  32  1   2   3   4   5
                //  6   7   8   9   10  11
                //  12  13  14  15  16  17  //  mask = 0x0000003Fu
                R = RotateShiftRight<uint32_t>(R, 2);
                L24 ^= R & 0x0000003Fu;
                //  ------------------------------------------------------R24
                //                  8   9
                //  10  11  12  13  14  15
                //  16  17  18  19  20  21  //  mask = 0x00FC0000u
                //  22  23  24  25  26  27
                //  28  29  30  31  32  1
                //  2   3   4   5   6   7
                R = RotateShiftRight<uint32_t>(R, 10);
                R24 = R & 0x00FC0000u;
                //  ------------------------------------------------------R24
                //                  6   7
                //  8   9   10  11  12  13
                //  14  15  16  17  18  19
                //  20  21  22  23  24  25  //  mask = 0x0003F000u
                //  26  27  28  29  30  31
                //  32  1   2   3   4   5
                R = RotateShiftRight<uint32_t>(R, 2);
                R24 ^= R & 0x0003F000u;
                //  ------------------------------------------------------R24
                //                  4   5
                //  6   7   8   9   10  11
                //  12  13  14  15  16  17
                //  18  19  20  21  22  23
                //  24  25  26  27  28  29  // mask = 0x00000FC0u
                //  30  31  32  1   2   3
                R = RotateShiftRight<uint32_t>(R, 2);
                R24 ^= R & 0x00000FC0u;
                //  ------------------------------------------------------R24
                //                  2   3
                //  4   5   6   7   8   9
                //  10  11  12  13  14  15
                //  16  17  18  19  20  21
                //  22  23  24  25  26  27
                //  28  29  30  31  32  1   //  mask = 0x0000003Fu
                R = RotateShiftRight<uint32_t>(R, 2);
                R24 ^= R & 0x0000003Fu;
            }

            L24 ^= _Key[i].Left;
            R24 ^= _Key[i].Right;

            // S and P transform
            R =
                S1AfterPTransform[_Word24ExtractNth6Bits<0>(L24)] ^
                S2AfterPTransform[_Word24ExtractNth6Bits<1>(L24)] ^
                S3AfterPTransform[_Word24ExtractNth6Bits<2>(L24)] ^
                S4AfterPTransform[_Word24ExtractNth6Bits<3>(L24)] ^
                S5AfterPTransform[_Word24ExtractNth6Bits<0>(R24)] ^
                S6AfterPTransform[_Word24ExtractNth6Bits<1>(R24)] ^
                S7AfterPTransform[_Word24ExtractNth6Bits<2>(R24)] ^
                S8AfterPTransform[_Word24ExtractNth6Bits<3>(R24)];

            return R;
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const uint8_t* pbUserKey) ACCEL_NOEXCEPT {
            Word28Type C, D;

            C =
                PCTable1[0][0][pbUserKey[0] >> 1u] ^
                PCTable1[0][1][pbUserKey[1] >> 1u] ^
                PCTable1[0][2][pbUserKey[2] >> 1u] ^
                PCTable1[0][3][pbUserKey[3] >> 1u] ^
                PCTable1[0][4][pbUserKey[4] >> 1u] ^
                PCTable1[0][5][pbUserKey[5] >> 1u] ^
                PCTable1[0][6][pbUserKey[6] >> 1u] ^
                PCTable1[0][7][pbUserKey[7] >> 1u];
            D =
                PCTable1[1][0][pbUserKey[0] >> 1u] ^
                PCTable1[1][1][pbUserKey[1] >> 1u] ^
                PCTable1[1][2][pbUserKey[2] >> 1u] ^
                PCTable1[1][3][pbUserKey[3] >> 1u] ^
                PCTable1[1][4][pbUserKey[4] >> 1u] ^
                PCTable1[1][5][pbUserKey[5] >> 1u] ^
                PCTable1[1][6][pbUserKey[6] >> 1u] ^
                PCTable1[1][7][pbUserKey[7] >> 1u];

            for (unsigned i = 0; i < 16; ++i) {
                C = _Word28RotateShiftLeft(C, ShiftList[i]);
                D = _Word28RotateShiftLeft(D, ShiftList[i]);
                _Key[i].Left =
                    PCTable2[0][0][_Word28ExtractNth4Bits<0>(C)] ^
                    PCTable2[0][1][_Word28ExtractNth4Bits<1>(C)] ^
                    PCTable2[0][2][_Word28ExtractNth4Bits<2>(C)] ^
                    PCTable2[0][3][_Word28ExtractNth4Bits<3>(C)] ^
                    PCTable2[0][4][_Word28ExtractNth4Bits<4>(C)] ^
                    PCTable2[0][5][_Word28ExtractNth4Bits<5>(C)] ^
                    PCTable2[0][6][_Word28ExtractNth4Bits<6>(C)];
                _Key[i].Right =
                    PCTable2[1][0][_Word28ExtractNth4Bits<0>(D)] ^
                    PCTable2[1][1][_Word28ExtractNth4Bits<1>(D)] ^
                    PCTable2[1][2][_Word28ExtractNth4Bits<2>(D)] ^
                    PCTable2[1][3][_Word28ExtractNth4Bits<3>(D)] ^
                    PCTable2[1][4][_Word28ExtractNth4Bits<4>(D)] ^
                    PCTable2[1][5][_Word28ExtractNth4Bits<5>(D)] ^
                    PCTable2[1][6][_Word28ExtractNth4Bits<6>(D)];
            }

            static_cast<volatile Word28Type&>(C) = 0;
            static_cast<volatile Word28Type&>(D) = 0;
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t L, R;

            _InitialPermutation(RefBlock, L, R);

            for (int i = 0; i < 16; i += 2) {
                L ^= _CipherFunction(R, i);
                R ^= _CipherFunction(L, i + 1);
            }

            _InverseInitialPermutation(RefBlock, R, L);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            uint32_t L, R;

            _InitialPermutation(RefBlock, R, L);

            for (int i = 14; i >= 0; i -= 2) {
                R ^= _CipherFunction(L, i + 1);
                L ^= _CipherFunction(R, i);
            }

            _InverseInitialPermutation(RefBlock, L, R);
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
                auto pb = reinterpret_cast<const uint8_t*>(pbUserKey);

                for (size_t i = 0; i < KeySizeValue; ++i)
                    if (PopulationCount<uint8_t>(pb[i]) % 2 == 0)
                        return false;

                _KeyExpansion(pb);

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

        ~DES_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

