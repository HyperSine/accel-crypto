#pragma once
#include <stdint.h>
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    class MD5_ALG {
    private:
        SecureArray<uint32_t, 4> _State;

        uint32_t _F(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return (X & Y) | (~X & Z);
        }

        uint32_t _G(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return (X & Z) | (Y & ~Z);
        }

        uint32_t _H(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return X ^ Y ^ Z;
        }

        uint32_t _I(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return Y ^ (X | ~Z);
        }

        void _FF(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s, uint32_t T) noexcept {
            A += _F(B, C, D) + K + T;
            A = Intrinsic::RotateShiftLeft(A, s);
            A += B;
        }

        void _GG(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s, uint32_t T) noexcept {
            A += _G(B, C, D) + K + T;
            A = Intrinsic::RotateShiftLeft(A, s);
            A += B;
        }

        void _HH(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s, uint32_t T) noexcept {
            A += _H(B, C, D) + K + T;
            A = Intrinsic::RotateShiftLeft(A, s);
            A += B;
        }

        void _II(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s, uint32_t T) noexcept {
            A += _I(B, C, D) + K + T;
            A = Intrinsic::RotateShiftLeft(A, s);
            A += B;
        }
    public:
        static constexpr size_t BlockSize = 64;
        static constexpr size_t DigestSize = 16;

        MD5_ALG() noexcept :
            _State{ 0x67452301u,
                    0xEFCDAB89u,
                    0x98BADCFEu,
                    0x10325476u } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t AA = 0, BB = 0, CC = 0, DD = 0;
            auto MessageBlock = reinterpret_cast<const uint32_t(*)[16]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                AA = _State[0];
                BB = _State[1];
                CC = _State[2];
                DD = _State[3];

                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][0], 7, 0xD76AA478);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][1], 12, 0xE8C7B756);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][2], 17, 0x242070DB);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][3], 22, 0xC1BDCEEE);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][4], 7, 0xF57C0FAF);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][5], 12, 0x4787C62A);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][6], 17, 0xA8304613);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][7], 22, 0xFD469501);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][8], 7, 0x698098D8);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][9], 12, 0x8B44F7AF);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][10], 17, 0xFFFF5BB1);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][11], 22, 0x895CD7BE);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][12], 7, 0x6B901122);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][13], 12, 0xFD987193);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][14], 17, 0xA679438E);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][15], 22, 0x49B40821);

                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][1], 5, 0xF61E2562);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][6], 9, 0xC040B340);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][11], 14, 0x265E5A51);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][0], 20, 0xE9B6C7AA);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][5], 5, 0xD62F105D);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][10], 9, 0x02441453);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][15], 14, 0xD8A1E681);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][4], 20, 0xE7D3FBC8);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][9], 5, 0x21E1CDE6);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][14], 9, 0xC33707D6);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][3], 14, 0xF4D50D87);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][8], 20, 0x455A14ED);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][13], 5, 0xA9E3E905);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][2], 9, 0xFCEFA3F8);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][7], 14, 0x676F02D9);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][12], 20, 0x8D2A4C8A);

                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][5], 4, 0xFFFA3942);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][8], 11, 0x8771F681);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][11], 16, 0x6D9D6122);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][14], 23, 0xFDE5380C);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][1], 4, 0xA4BEEA44);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][4], 11, 0x4BDECFA9);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][7], 16, 0xF6BB4B60);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][10], 23, 0xBEBFBC70);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][13], 4, 0x289B7EC6);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][0], 11, 0xEAA127FA);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][3], 16, 0xD4EF3085);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][6], 23, 0x04881D05);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][9], 4, 0xD9D4D039);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][12], 11, 0xE6DB99E5);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][15], 16, 0x1FA27CF8);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][2], 23, 0xC4AC5665);

                _II(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][0], 6, 0xF4292244);
                _II(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][7], 10, 0x432AFF97);
                _II(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][14], 15, 0xAB9423A7);
                _II(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][5], 21, 0xFC93A039);
                _II(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][12], 6, 0x655B59C3);
                _II(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][3], 10, 0x8F0CCC92);
                _II(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][10], 15, 0xFFEFF47D);
                _II(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][1], 21, 0x85845DD1);
                _II(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][8], 6, 0x6FA87E4F);
                _II(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][15], 10, 0xFE2CE6E0);
                _II(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][6], 15, 0xA3014314);
                _II(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][13], 21, 0x4E0811A1);
                _II(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][4], 6, 0xF7537E82);
                _II(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][11], 10, 0xBD3AF235);
                _II(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][2], 15, 0x2AD7D2BB);
                _II(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][9], 21, 0xEB86D391);

                _State[0] += AA;
                _State[1] += BB;
                _State[2] += CC;
                _State[3] += DD;
            }
        }

        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) {
            assert(TailDataSize <= 2 * BlockSize - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSize - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(FormattedTailData + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) : (BlockSize - sizeof(uint64_t)))) =
                    ProcessedBytes * 8;

            Cycle(FormattedTailData, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTailData;
                size_t s = sizeof(FormattedTailData);
                while (s--) *p++ = 0;
            }
        }

        ByteArray<DigestSize> Digest() const noexcept {
            return _State.AsArrayOf<uint8_t, DigestSize>();
        }
    };

}

