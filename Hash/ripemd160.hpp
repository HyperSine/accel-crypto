#pragma once
#include <stdint.h>
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    class RIPEMD160_ALG {
    private:
        SecureArray<uint32_t, 5> _State;

        static uint32_t _F(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return x ^ y ^ z;
        }

        static uint32_t _G(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return (x & y) | (~x & z);
        }

        static uint32_t _H(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return (x | ~y) ^ z;
        }

        static uint32_t _I(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return (x & z) | (y & ~z);
        }

        static uint32_t _J(uint32_t x, uint32_t y, uint32_t z) noexcept {
            return x ^ (y | ~z);
        }

        static void _OperateX(uint32_t(& Func)(uint32_t, uint32_t, uint32_t),
                              uint32_t& T,
                              uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t& E,
                              uint32_t X, uint32_t K, uint32_t s) noexcept {
            T = Intrinsic::RotateShiftLeft(A + Func(B, C, D) + X + K, s) + E;
            A = E;
            E = D;
            D = Intrinsic::RotateShiftLeft(C, 10);
            C = B;
            B = T;
        }
    public:
        static constexpr size_t BlockSize = 64;
        static constexpr size_t DigestSize = 20;

        RIPEMD160_ALG() noexcept :
            _State{ 0x67452301u,
                    0xefcdab89u,
                    0x98badcfeu,
                    0x10325476u,
                    0xc3d2e1f0u } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t A, B, C, D, E;
            uint32_t AA, BB, CC, DD, EE;
            uint32_t T;
            auto MessageBlock = reinterpret_cast<const uint32_t(*)[16]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                A = AA = _State[0];
                B = BB = _State[1];
                C = CC = _State[2];
                D = DD = _State[3];
                E = EE = _State[4];

                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][0], 0, 11);;
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][5], 0x50A28BE6, 8);;
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][1], 0, 14);;
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][14], 0x50A28BE6, 9);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][2], 0, 15);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][7], 0x50A28BE6, 9);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][3], 0, 12);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][0], 0x50A28BE6, 11);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][4], 0, 5);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][9], 0x50A28BE6, 13);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][5], 0, 8);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][2], 0x50A28BE6, 15);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][6], 0, 7);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][11], 0x50A28BE6, 15);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][7], 0, 9);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][4], 0x50A28BE6, 5);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][8], 0, 11);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][13], 0x50A28BE6, 7);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][9], 0, 13);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][6], 0x50A28BE6, 7);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][10], 0, 14);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][15], 0x50A28BE6, 8);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][11], 0, 15);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][8], 0x50A28BE6, 11);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][12], 0, 6);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][1], 0x50A28BE6, 14);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][13], 0, 7);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][10], 0x50A28BE6, 14);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][14], 0, 9);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][3], 0x50A28BE6, 12);
                _OperateX(_F, T, A, B, C, D, E, MessageBlock[i][15], 0, 8);
                _OperateX(_J, T, AA, BB, CC, DD, EE, MessageBlock[i][12], 0x50A28BE6, 6);

                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][7], 0x5A827999, 7);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][6], 0x5C4DD124, 9);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][4], 0x5A827999, 6);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][11], 0x5C4DD124, 13);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][13], 0x5A827999, 8);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][3], 0x5C4DD124, 15);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][1], 0x5A827999, 13);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][7], 0x5C4DD124, 7);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][10], 0x5A827999, 11);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][0], 0x5C4DD124, 12);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][6], 0x5A827999, 9);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][13], 0x5C4DD124, 8);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][15], 0x5A827999, 7);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][5], 0x5C4DD124, 9);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][3], 0x5A827999, 15);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][10], 0x5C4DD124, 11);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][12], 0x5A827999, 7);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][14], 0x5C4DD124, 7);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][0], 0x5A827999, 12);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][15], 0x5C4DD124, 7);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][9], 0x5A827999, 15);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][8], 0x5C4DD124, 12);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][5], 0x5A827999, 9);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][12], 0x5C4DD124, 7);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][2], 0x5A827999, 11);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][4], 0x5C4DD124, 6);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][14], 0x5A827999, 7);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][9], 0x5C4DD124, 15);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][11], 0x5A827999, 13);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][1], 0x5C4DD124, 13);
                _OperateX(_G, T, A, B, C, D, E, MessageBlock[i][8], 0x5A827999, 12);
                _OperateX(_I, T, AA, BB, CC, DD, EE, MessageBlock[i][2], 0x5C4DD124, 11);

                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][3], 0x6ED9EBA1, 11);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][15], 0x6D703EF3, 9);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][10], 0x6ED9EBA1, 13);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][5], 0x6D703EF3, 7);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][14], 0x6ED9EBA1, 6);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][1], 0x6D703EF3, 15);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][4], 0x6ED9EBA1, 7);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][3], 0x6D703EF3, 11);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][9], 0x6ED9EBA1, 14);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][7], 0x6D703EF3, 8);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][15], 0x6ED9EBA1, 9);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][14], 0x6D703EF3, 6);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][8], 0x6ED9EBA1, 13);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][6], 0x6D703EF3, 6);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][1], 0x6ED9EBA1, 15);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][9], 0x6D703EF3, 14);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][2], 0x6ED9EBA1, 14);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][11], 0x6D703EF3, 12);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][7], 0x6ED9EBA1, 8);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][8], 0x6D703EF3, 13);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][0], 0x6ED9EBA1, 13);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][12], 0x6D703EF3, 5);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][6], 0x6ED9EBA1, 6);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][2], 0x6D703EF3, 14);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][13], 0x6ED9EBA1, 5);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][10], 0x6D703EF3, 13);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][11], 0x6ED9EBA1, 12);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][0], 0x6D703EF3, 13);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][5], 0x6ED9EBA1, 7);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][4], 0x6D703EF3, 7);
                _OperateX(_H, T, A, B, C, D, E, MessageBlock[i][12], 0x6ED9EBA1, 5);
                _OperateX(_H, T, AA, BB, CC, DD, EE, MessageBlock[i][13], 0x6D703EF3, 5);

                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][1], 0x8F1BBCDC, 11);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][8], 0x7A6D76E9, 15);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][9], 0x8F1BBCDC, 12);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][6], 0x7A6D76E9, 5);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][11], 0x8F1BBCDC, 14);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][4], 0x7A6D76E9, 8);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][10], 0x8F1BBCDC, 15);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][1], 0x7A6D76E9, 11);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][0], 0x8F1BBCDC, 14);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][3], 0x7A6D76E9, 14);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][8], 0x8F1BBCDC, 15);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][11], 0x7A6D76E9, 14);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][12], 0x8F1BBCDC, 9);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][15], 0x7A6D76E9, 6);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][4], 0x8F1BBCDC, 8);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][0], 0x7A6D76E9, 14);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][13], 0x8F1BBCDC, 9);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][5], 0x7A6D76E9, 6);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][3], 0x8F1BBCDC, 14);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][12], 0x7A6D76E9, 9);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][7], 0x8F1BBCDC, 5);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][2], 0x7A6D76E9, 12);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][15], 0x8F1BBCDC, 6);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][13], 0x7A6D76E9, 9);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][14], 0x8F1BBCDC, 8);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][9], 0x7A6D76E9, 12);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][5], 0x8F1BBCDC, 6);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][7], 0x7A6D76E9, 5);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][6], 0x8F1BBCDC, 5);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][10], 0x7A6D76E9, 15);
                _OperateX(_I, T, A, B, C, D, E, MessageBlock[i][2], 0x8F1BBCDC, 12);
                _OperateX(_G, T, AA, BB, CC, DD, EE, MessageBlock[i][14], 0x7A6D76E9, 8);

                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][4], 0xA953FD4E, 9);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][12], 0, 8);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][0], 0xA953FD4E, 15);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][15], 0, 5);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][5], 0xA953FD4E, 5);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][10], 0, 12);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][9], 0xA953FD4E, 11);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][4], 0, 9);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][7], 0xA953FD4E, 6);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][1], 0, 12);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][12], 0xA953FD4E, 8);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][5], 0, 5);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][2], 0xA953FD4E, 13);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][8], 0, 14);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][10], 0xA953FD4E, 12);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][7], 0, 6);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][14], 0xA953FD4E, 5);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][6], 0, 8);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][1], 0xA953FD4E, 12);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][2], 0, 13);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][3], 0xA953FD4E, 13);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][13], 0, 6);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][8], 0xA953FD4E, 14);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][14], 0, 5);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][11], 0xA953FD4E, 11);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][0], 0, 15);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][6], 0xA953FD4E, 8);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][3], 0, 13);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][15], 0xA953FD4E, 5);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][9], 0, 11);
                _OperateX(_J, T, A, B, C, D, E, MessageBlock[i][13], 0xA953FD4E, 6);
                _OperateX(_F, T, AA, BB, CC, DD, EE, MessageBlock[i][11], 0, 11);

                T = _State[1] + C + DD;
                _State[1] = _State[2] + D + EE;
                _State[2] = _State[3] + E + AA;
                _State[3] = _State[4] + A + BB;
                _State[4] = _State[0] + B + CC;
                _State[0] = T;
            }
        }

        //
        //  Once Finish(...) is called, this object should be treated as const
        //
        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSize - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSize - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(FormattedTailData + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) : (BlockSize - sizeof(uint64_t)))) = ProcessedBytes * 8;

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

