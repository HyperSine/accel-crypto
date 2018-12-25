#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <assert.h>

namespace accel::Hash {

    class SM3_ALG {
    private:
        SecureArray<uint32_t, 8> _State;

        template<size_t __j>
        static constexpr uint32_t _T() {
            if constexpr (0 <= __j && __j < 16) {
                return 0x79cc4519u;
            }
            if constexpr (16 <= __j && __j < 64) {
                return 0x7a879d8au;
            }
        }

        template<size_t __j>
        __forceinline
        static uint32_t _FF(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            if constexpr (0 <= __j && __j < 16) {
                return X ^ Y ^ Z;
            }

            if constexpr (16 <= __j && __j < 64) {
                return (X & Y) | (X & Z) | (Y & Z);
            }
        }

        template<size_t __j>
        __forceinline
        static uint32_t _GG(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            if constexpr (0 <= __j && __j < 16) {
                return X ^ Y ^ Z;
            }

            if constexpr (16 <= __j && __j < 64) {
                return (X & Y) | (~X & Z);
            }
        }

        __forceinline
        static uint32_t _P0(uint32_t X) noexcept {
            return X ^ Intrinsic::RotateShiftLeft(X, 9) ^ Intrinsic::RotateShiftLeft(X, 17);
        }

        __forceinline
        static uint32_t _P1(uint32_t X) noexcept {
            return X ^ Intrinsic::RotateShiftLeft(X, 15) ^ Intrinsic::RotateShiftLeft(X, 23);
        }

        __forceinline
        static void _MessageExtend(uint32_t (&W)[68], uint32_t (&WW)[64], const uint32_t (&B)[16]) noexcept {
            int j = 0;

            for (; j < 16; ++j)
                W[j] = Intrinsic::ByteSwap(B[j]);

            for (; j < 68; ++j) {
                W[j] =
                    _P1(W[j - 16] ^
                        W[j - 9] ^
                        Intrinsic::RotateShiftLeft(W[j - 3], 15)) ^
                    Intrinsic::RotateShiftLeft(W[j - 13], 7) ^
                    W[j - 6];
            }

            for (j = 0; j < 64; ++j)
                WW[j] = W[j] ^ W[j + 4];
        }

        template<size_t __Index>
        __forceinline
        static void _Loop(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                          uint32_t& E, uint32_t& F, uint32_t& G, uint32_t& H,
                          uint32_t& SS1, uint32_t& SS2, uint32_t& TT1, uint32_t& TT2,
                          uint32_t (&W)[68], uint32_t (&WW)[64]) {
            SS1 =
                Intrinsic::RotateShiftLeft(
                    Intrinsic::RotateShiftLeft(A, 12) +
                    E +
                    Intrinsic::RotateShiftLeft(_T<__Index>(), static_cast<int>(__Index)),
                7);
            SS2 = SS1 ^ Intrinsic::RotateShiftLeft(A, 12);
            TT1 = _FF<__Index>(A, B, C) + D + SS2 + WW[__Index];
            TT2 = _GG<__Index>(E, F, G) + H + SS1 + W[__Index];
            D = C;
            C = Intrinsic::RotateShiftLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = Intrinsic::RotateShiftLeft(F, 19);
            F = E;
            E = _P0(TT2);
        }

        template<size_t... __Indexes>
        __forceinline
        static void _Loops(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                           uint32_t& E, uint32_t& F, uint32_t& G, uint32_t& H,
                           uint32_t& SS1, uint32_t& SS2, uint32_t& TT1, uint32_t& TT2,
                           uint32_t (&W)[68], uint32_t (&WW)[64], std::index_sequence<__Indexes...>) {
            (_Loop<__Indexes>(A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, W, WW), ...);
        }

        __forceinline
        void _Compress(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                       uint32_t& E, uint32_t& F, uint32_t& G, uint32_t& H,
                       uint32_t& SS1, uint32_t& SS2, uint32_t& TT1, uint32_t& TT2,
                       uint32_t (&W)[68], uint32_t (&WW)[64]) noexcept {
            A = _State[0];
            B = _State[1];
            C = _State[2];
            D = _State[3];
            E = _State[4];
            F = _State[5];
            G = _State[6];
            H = _State[7];

            _Loops(A, B, C, D, E, F, G, H,
                   SS1, SS2, TT1, TT2,
                   W, WW, std::make_index_sequence<64>{});

            _State[0] ^= A;
            _State[1] ^= B;
            _State[2] ^= C;
            _State[3] ^= D;
            _State[4] ^= E;
            _State[5] ^= F;
            _State[6] ^= G;
            _State[7] ^= H;
        }

    public:
        static constexpr size_t BlockSize = 64;
        static constexpr size_t DigestSize = 32;

        SM3_ALG() noexcept :
            _State{ 0x7380166fu,
                    0x4914b2b9u,
                    0x172442d7u,
                    0xda8a0600u,
                    0xa96f30bcu,
                    0x163138aau,
                    0xe38dee4du,
                    0xb0fb0e4eu } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t A, B, C, D, E, F, G, H;
            uint32_t SS1, SS2, TT1, TT2;
            uint32_t W[68];
            uint32_t WW[64];
            auto MessageBlock = reinterpret_cast<const uint32_t(*)[16]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                _MessageExtend(W, WW, MessageBlock[i]);
                _Compress(A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, W, WW);
            }
        }

        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSize - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSize - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(FormattedTailData + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) : (BlockSize - sizeof(uint64_t)))) =
                    Intrinsic::ByteSwap<uint64_t>(ProcessedBytes * 8);

            Cycle(FormattedTailData, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTailData;
                size_t s = sizeof(FormattedTailData);
                while (s--) *p++ = 0;
            }

            _State[0] = Intrinsic::ByteSwap(_State[0]);
            _State[1] = Intrinsic::ByteSwap(_State[1]);
            _State[2] = Intrinsic::ByteSwap(_State[2]);
            _State[3] = Intrinsic::ByteSwap(_State[3]);
            _State[4] = Intrinsic::ByteSwap(_State[4]);
            _State[5] = Intrinsic::ByteSwap(_State[5]);
            _State[6] = Intrinsic::ByteSwap(_State[6]);
            _State[7] = Intrinsic::ByteSwap(_State[7]);
        }

        ByteArray<DigestSize> Digest() const noexcept {
            return _State.AsArrayOf<uint8_t, DigestSize>();
        }
    };

}

