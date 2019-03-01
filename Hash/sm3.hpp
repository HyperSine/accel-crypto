#pragma once
#include "../Config.hpp"
#include "../SecureWiper.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <assert.h>

namespace accel::Hash {

    class SM3_ALG {
    private:

        SecureWiper<Array<uint32_t, 8>> _StateWiper;
        Array<uint32_t, 8> _State;

        // rename _T to _T_Constant, 
        // to avoid conflict with _T macro in windows
        template<size_t __j>
        static constexpr uint32_t _T_Constant() {
            if constexpr (0 <= __j && __j < 16) {
                return 0x79cc4519u;
            }
            if constexpr (16 <= __j && __j < 64) {
                return 0x7a879d8au;
            }
        }

        template<size_t __j>
        ACCEL_FORCEINLINE
        static uint32_t _FF(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            if constexpr (0 <= __j && __j < 16) {
                return X ^ Y ^ Z;
            }

            if constexpr (16 <= __j && __j < 64) {
                return (X & Y) | (X & Z) | (Y & Z);
            }
        }

        template<size_t __j>
        ACCEL_FORCEINLINE
        static uint32_t _GG(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            if constexpr (0 <= __j && __j < 16) {
                return X ^ Y ^ Z;
            }

            if constexpr (16 <= __j && __j < 64) {
                return (X & Y) | (~X & Z);
            }
        }

        ACCEL_FORCEINLINE
        static uint32_t _P0(uint32_t X) noexcept {
            return X ^ RotateShiftLeft(X, 9) ^ RotateShiftLeft(X, 17);
        }

        ACCEL_FORCEINLINE
        static uint32_t _P1(uint32_t X) noexcept {
            return X ^ RotateShiftLeft(X, 15) ^ RotateShiftLeft(X, 23);
        }

        ACCEL_FORCEINLINE
        static void _MessageExtend(uint32_t (&W)[68], uint32_t (&WW)[64], const uint32_t (&B)[16]) noexcept {
            int j = 0;

            for (; j < 16; ++j)
                W[j] = ByteSwap(B[j]);

            for (; j < 68; ++j) {
                W[j] =
                    _P1(W[j - 16] ^
                        W[j - 9] ^
                        RotateShiftLeft(W[j - 3], 15)) ^
                    RotateShiftLeft(W[j - 13], 7) ^
                    W[j - 6];
            }

            for (j = 0; j < 64; ++j)
                WW[j] = W[j] ^ W[j + 4];
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        static void _Loop(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                          uint32_t& E, uint32_t& F, uint32_t& G, uint32_t& H,
                          uint32_t& SS1, uint32_t& SS2, uint32_t& TT1, uint32_t& TT2,
                          uint32_t (&W)[68], uint32_t (&WW)[64]) {
            SS1 =
                RotateShiftLeft(
                    RotateShiftLeft(A, 12) +
                    E +
                    RotateShiftLeft(_T_Constant<__Index>(), static_cast<int>(__Index)),
                7);
            SS2 = SS1 ^ RotateShiftLeft(A, 12);
            TT1 = _FF<__Index>(A, B, C) + D + SS2 + WW[__Index];
            TT2 = _GG<__Index>(E, F, G) + H + SS1 + W[__Index];
            D = C;
            C = RotateShiftLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RotateShiftLeft(F, 19);
            F = E;
            E = _P0(TT2);
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        static void _Loops(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                           uint32_t& E, uint32_t& F, uint32_t& G, uint32_t& H,
                           uint32_t& SS1, uint32_t& SS2, uint32_t& TT1, uint32_t& TT2,
                           uint32_t (&W)[68], uint32_t (&WW)[64], std::index_sequence<__Indexes...>) {
            (_Loop<__Indexes>(A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, W, WW), ...);
        }

        ACCEL_FORCEINLINE
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
        static constexpr size_t BlockSizeValue = 64;
        static constexpr size_t DigestSizeValue = 32;

        SM3_ALG() noexcept :
            _StateWiper(_State),
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
            assert(TailDataSize <= 2 * BlockSizeValue - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSizeValue] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSizeValue - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(FormattedTailData + (Rounds > 1 ? (2 * BlockSizeValue - sizeof(uint64_t)) : (BlockSizeValue - sizeof(uint64_t)))) =
                    ByteSwap<uint64_t>(ProcessedBytes * 8);

            Cycle(FormattedTailData, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTailData;
                size_t s = sizeof(FormattedTailData);
                while (s--) *p++ = 0;
            }

            _State[0] = ByteSwap(_State[0]);
            _State[1] = ByteSwap(_State[1]);
            _State[2] = ByteSwap(_State[2]);
            _State[3] = ByteSwap(_State[3]);
            _State[4] = ByteSwap(_State[4]);
            _State[5] = ByteSwap(_State[5]);
            _State[6] = ByteSwap(_State[6]);
            _State[7] = ByteSwap(_State[7]);
        }

        Array<uint8_t, DigestSizeValue> Digest() const noexcept {
            return _State.AsArrayOf<uint8_t, DigestSizeValue>();
        }
    };

}

