#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    class RIPEMD128_ALG {
    private:
        SecureArray<uint32_t, 4> _State;

        template<size_t __Index>
        __forceinline
        static constexpr uint32_t _f(uint32_t x, uint32_t y, uint32_t z) noexcept {
            static_assert(__Index < 64, "RIPEMD128_ALG::_f(x, y, z) failure!");
            if constexpr (0 <= __Index && __Index < 16) {
                return x ^ y ^ z;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return (x & y) | (~x & z);
            } else if constexpr (32 <= __Index && __Index < 48) {
                return (x | ~y) ^ z;
            } else {
                return (x & z) | (y & ~z);
            }
        }

        template<size_t __Index>
        static constexpr uint32_t _K() noexcept {
            static_assert(__Index < 64, "RIPEMD128_ALG::_K() failure!");
            if constexpr (0 <= __Index && __Index < 16) {
                return 0;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return 0x5A827999u;
            } else if constexpr (32 <= __Index && __Index < 48) {
                return 0x6ED9EBA1u;
            } else {
                return 0x8F1BBCDCu;
            }
        }

        template<size_t __Index>
        static constexpr uint32_t _KK() noexcept {
            static_assert(__Index < 64, "RIPEMD128_ALG::_KK() failure!");
            if constexpr (0 <= __Index && __Index < 16) {
                return 0x50A28BE6u;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return 0x5C4DD124u;
            } else if constexpr (32 <= __Index && __Index < 48) {
                return 0x6D703EF3u;
            } else {
                return 0;
            }
        }

        static constexpr size_t _r[64] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
        };

        static constexpr size_t _rr[64] = {
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
        };

        static constexpr int _s[64] = {
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
        };

        static constexpr int _ss[64] = {
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
        };

        template<size_t __Index>
        __forceinline
        static void _Loop(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                          uint32_t& AA, uint32_t& BB, uint32_t& CC, uint32_t& DD,
                          uint32_t& T,
                          const uint32_t (&X)[16]) noexcept {
            T = RotateShiftLeft<uint32_t>(A + _f<__Index>(B, C, D) + X[_r[__Index]] + _K<__Index>(), _s[__Index]);
            A = D;
            D = C;
            C = B;
            B = T;
            T = RotateShiftLeft<uint32_t>(AA + _f<63 - __Index>(BB, CC, DD) + X[_rr[__Index]] + _KK<__Index>(), _ss[__Index]);
            AA = DD;
            DD = CC;
            CC = BB;
            BB = T;
        }

        template<size_t... __Indexes>
        __forceinline
        static void _Loops(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                           uint32_t& AA, uint32_t& BB, uint32_t& CC, uint32_t& DD,
                           uint32_t& T,
                           const uint32_t(&X)[16], std::index_sequence<__Indexes...>) noexcept {
            (_Loop<__Indexes>(A, B, C, D, AA, BB, CC, DD, T, X), ...);
        }

    public:
        static constexpr size_t BlockSize = 64;
        static constexpr size_t DigestSize = 16;

        RIPEMD128_ALG() noexcept :
            _State{ 0x67452301u,
                    0xEFCDAB89u,
                    0x98BADCFEu,
                    0x10325476u } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t A, B, C, D;
            uint32_t AA, BB, CC, DD;
            uint32_t T;
            auto MessageBlocks = reinterpret_cast<const uint32_t(*)[16]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                A = AA = _State[0];
                B = BB = _State[1];
                C = CC = _State[2];
                D = DD = _State[3];

                _Loops(A, B, C, D, AA, BB, CC, DD, T, MessageBlocks[i], std::make_index_sequence<64>{});

                T = _State[1] + C + DD;
                _State[1] = _State[2] + D + AA;
                _State[2] = _State[3] + A + BB;
                _State[3] = _State[0] + B + CC;
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

