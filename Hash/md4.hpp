#pragma once
#include "../Config.hpp"
#include "../SecureWiper.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    class MD4_ALG {
    private:
        SecureWiper<Array<uint32_t, 4>> _StateWiper;
        Array<uint32_t, 4> _State;

        ACCEL_FORCEINLINE
        uint32_t _F(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return (X & Y) | (~X & Z);
        }

        ACCEL_FORCEINLINE
        uint32_t _G(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return (X & Y) | (X & Z) | (Y & Z);
        }

        ACCEL_FORCEINLINE
        uint32_t _H(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            return X ^ Y ^ Z;
        }

        ACCEL_FORCEINLINE
        void _FF(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s) noexcept {
            A += _F(B, C, D) + K;
            A = RotateShiftLeft(A, s);
        }

        ACCEL_FORCEINLINE
        void _GG(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s) noexcept {
            A += _G(B, C, D) + K + 0x5A827999u;
            A = RotateShiftLeft(A, s);
        }

        ACCEL_FORCEINLINE
        void _HH(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, uint32_t s) noexcept {
            A += _H(B, C, D) + K + 0x6ED9EBA1u;
            A = RotateShiftLeft(A, s);
        }

    public:
        static constexpr size_t BlockSizeValue = 64;
        static constexpr size_t DigestSizeValue = 16;

        MD4_ALG() noexcept :
            _StateWiper(_State),
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

                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][0], 3);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][1], 7);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][2], 11);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][3], 19);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][4], 3);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][5], 7);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][6], 11);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][7], 19);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][8], 3);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][9], 7);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][10], 11);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][11], 19);
                _FF(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][12], 3);
                _FF(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][13], 7);
                _FF(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][14], 11);
                _FF(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][15], 19);

                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][0], 3);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][4], 5);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][8], 9);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][12], 13);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][1], 3);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][5], 5);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][9], 9);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][13], 13);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][2], 3);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][6], 5);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][10], 9);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][14], 13);
                _GG(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][3], 3);
                _GG(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][7], 5);
                _GG(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][11], 9);
                _GG(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][15], 13);

                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][0], 3);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][8], 9);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][4], 11);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][12], 15);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][2], 3);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][10], 9);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][6], 11);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][14], 15);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][1], 3);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][9], 9);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][5], 11);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][13], 15);
                _HH(_State[0], _State[1], _State[2], _State[3], MessageBlock[i][3], 3);
                _HH(_State[3], _State[0], _State[1], _State[2], MessageBlock[i][11], 9);
                _HH(_State[2], _State[3], _State[0], _State[1], MessageBlock[i][7], 11);
                _HH(_State[1], _State[2], _State[3], _State[0], MessageBlock[i][15], 15);

                _State[0] += AA;
                _State[1] += BB;
                _State[2] += CC;
                _State[3] += DD;
            }
        }

        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSizeValue - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSizeValue] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSizeValue - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(FormattedTailData + (Rounds > 1 ? (2 * BlockSizeValue - sizeof(uint64_t)) : (BlockSizeValue - sizeof(uint64_t)))) =
                    ProcessedBytes * 8;

            Cycle(FormattedTailData, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTailData;
                size_t s = sizeof(FormattedTailData);
                while (s--) *p++ = 0;
            }
        }

        Array<uint8_t, DigestSizeValue> Digest() const noexcept {
            return _State.AsArrayOf<uint8_t, DigestSizeValue>();
        }
    };

}

