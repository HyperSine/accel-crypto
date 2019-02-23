#pragma once
#include "../Config.hpp"
#include "../SecureWiper.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    namespace Internal {

        template<size_t __Bits>
        class RIPEMD_CONSTANT;

        template<>
        class RIPEMD_CONSTANT<128> {
        protected:
            static constexpr Array<uint32_t, 4> _InitValue{ 
                0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u 
            };
        };

        template<>
        class RIPEMD_CONSTANT<160> {
        protected:
            static constexpr Array<uint32_t, 5> _InitValue{ 
                0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                0xc3d2e1f0u 
            };
        };

        template<>
        class RIPEMD_CONSTANT<256> {
        protected:
            static constexpr Array<uint32_t, 8> _InitValue{ 
                0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                0x76543210u, 0xFEDCBA98u, 0x89ABCDEFu, 0x01234567u 
            };
        };

        template<>
        class RIPEMD_CONSTANT<320> {
        protected:
            static constexpr Array<uint32_t, 10> _InitValue{ 
                0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                0xC3D2E1F0u, 0x76543210u, 0xFEDCBA98u, 0x89ABCDEFu,
                0x01234567u, 0x3C2D1E0Fu 
            };
        };

    }

    template<size_t __Bits>
    class RIPEMD_ALG : public Internal::RIPEMD_CONSTANT<__Bits> {
        static_assert(__Bits == 128 ||
                      __Bits == 160 ||
                      __Bits == 256 ||
                      __Bits == 320, "RIPEMD_ALG failure! Unsupported bits.");
    private:
        SecureWiper<Array<uint32_t, __Bits / 32>> _StateWiper;
        Array<uint32_t, __Bits / 32> _State;

        template<size_t __Index>
        ACCEL_FORCEINLINE
        static uint32_t _f(uint32_t x, uint32_t y, uint32_t z) noexcept {
            if constexpr (0 <= __Index && __Index < 16) {
                return x ^ y ^ z;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return (x & y) | (~x & z);
            } else if constexpr (32 <= __Index && __Index < 48) {
                return (x | ~y) ^ z;
            } else if constexpr (48 <= __Index && __Index < 64) {
                return (x & z) | (y & ~z);
            } else if constexpr ((__Bits == 160 || __Bits == 320) &&
                                 64 <= __Index && __Index < 80) {
                return x ^ (y | ~z);    // only available when __Bits is 160 or 320
            } else {
                static_assert(((__Bits == 128 || __Bits == 256) && __Index < 64) ||
                              ((__Bits == 160 || __Bits == 320) && __Index < 80),
                              "_f(x, y, z) failure! Out of range.");
            }
            ACCEL_UNREACHABLE();
        }

        template<size_t __Index>
        static constexpr uint32_t _K() {
            if constexpr (0 <= __Index && __Index < 16) {
                return 0u;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return 0x5A827999u;
            } else if constexpr (32 <= __Index && __Index < 48) {
                return 0x6ED9EBA1u;
            } else if constexpr (48 <= __Index && __Index < 64) {
                return 0x8F1BBCDCu;
            } else if constexpr ((__Bits == 160 || __Bits == 320) &&
                                 64 <= __Index && __Index < 80) {
                return 0xA953FD4Eu;     // only available when __Bits is 160 or 320
            } else {
                static_assert(((__Bits == 128 || __Bits == 256) && __Index < 64) ||
                              ((__Bits == 160 || __Bits == 320) && __Index < 80),
                              "_K() failure! Out of range.");
            }
            ACCEL_UNREACHABLE();
        }

        template<size_t __Index>
        static constexpr uint32_t _KK() {
            if constexpr (0 <= __Index && __Index < 16) {
                return 0x50A28BE6u;
            } else if constexpr (16 <= __Index && __Index < 32) {
                return 0x5C4DD124u;
            } else if constexpr (32 <= __Index && __Index < 48) {
                return 0x6D703EF3u;
            } else if constexpr (48 <= __Index && __Index < 64) {
                if constexpr (__Bits == 128 || __Bits == 256) {
                    return 0u;
                } else {
                    return 0x7A6D76E9u;
                }
            } else if constexpr ((__Bits == 160 || __Bits == 320) &&
                                 64 <= __Index && __Index < 80) {
                return 0u;      // only available when __Bits is 160 or 320
            } else {
                static_assert(((__Bits == 128 || __Bits == 256) && __Index < 64) ||
                              ((__Bits == 160 || __Bits == 320) && __Index < 80),
                              "_KK() failure! Out of range.");
            }
            ACCEL_UNREACHABLE();
        }

        static constexpr size_t _r[80] = {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
                3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
                1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
                4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
        };

        static constexpr size_t _rr[80] = {
                5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
                6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
                15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
                8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
                12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        };

        static constexpr unsigned _s[80] = {
                11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
                7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
                11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
                11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
                9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        };

        static constexpr unsigned _ss[80] = {
                8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
                9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
                9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
                15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
                8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        };

        // for RIPEMD-128, RIPEMD-256 only
        template<size_t __Index>
        ACCEL_FORCEINLINE
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

            // for the case when RIPEMD-256
            if constexpr (__Bits == 256) {
                if constexpr (__Index == 15) {
                    T = A;
                    A = AA;
                    AA = T;
                }
                if constexpr (__Index == 31) {
                    T = B;
                    B = BB;
                    BB = T;
                }
                if constexpr (__Index == 47) {
                    T = C;
                    C = CC;
                    CC = T;
                }
                if constexpr (__Index == 63) {
                    T = D;
                    D = DD;
                    DD = T;
                }
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        static void _Loops(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D,
                           uint32_t& AA, uint32_t& BB, uint32_t& CC, uint32_t& DD,
                           uint32_t& T,
                           const uint32_t(&X)[16], std::index_sequence<__Indexes...>) noexcept {
            (_Loop<__Indexes>(A, B, C, D, AA, BB, CC, DD, T, X), ...);
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        static void _LoopEx(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t& E,
                            uint32_t& AA, uint32_t& BB, uint32_t& CC, uint32_t& DD, uint32_t& EE,
                            uint32_t& T,
                            const uint32_t (&X)[16]) noexcept {
            T = RotateShiftLeft<uint32_t>(A + _f<__Index>(B, C, D) + X[_r[__Index]] + _K<__Index>(), _s[__Index]) + E;
            A = E;
            E = D;
            D = RotateShiftLeft<uint32_t>(C, 10);
            C = B;
            B = T;
            T = RotateShiftLeft<uint32_t>(AA + _f<79 - __Index>(BB, CC, DD) + X[_rr[__Index]] + _KK<__Index>(), _ss[__Index]) + EE;
            AA = EE;
            EE = DD;
            DD = RotateShiftLeft<uint32_t>(CC, 10);
            CC = BB;
            BB = T;

            // for the case when RIPEMD-320
            if constexpr (__Bits == 320) {
                if constexpr (__Index == 15) {
                    T = B;
                    B = BB;
                    BB = T;
                }
                if constexpr (__Index == 31) {
                    T = D;
                    D = DD;
                    DD = T;
                }
                if constexpr (__Index == 47) {
                    T = A;
                    A = AA;
                    AA = T;
                }
                if constexpr (__Index == 63) {
                    T = C;
                    C = CC;
                    CC = T;
                }
                if constexpr (__Index == 79) {
                    T = E;
                    E = EE;
                    EE = T;
                }
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        static void _LoopExs(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t& E,
                             uint32_t& AA, uint32_t& BB, uint32_t& CC, uint32_t& DD, uint32_t& EE,
                             uint32_t& T,
                             const uint32_t(&X)[16], std::index_sequence<__Indexes...>) noexcept {
            (_LoopEx<__Indexes>(A, B, C, D, E, AA, BB, CC, DD, EE, T, X), ...);
        }


    public:
        static constexpr size_t BlockSizeValue = 64;
        static constexpr size_t DigestSizeValue = __Bits / 8;

        RIPEMD_ALG() noexcept :
            _StateWiper(_State),
            _State{ Internal::RIPEMD_CONSTANT<__Bits>::_InitValue } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            if constexpr (__Bits == 128 || __Bits == 256) {
                uint32_t A, B, C, D;
                uint32_t AA, BB, CC, DD;
                uint32_t T;
                auto MessageBlocks = reinterpret_cast<const uint32_t(*)[16]>(pData);

                for (size_t i = 0; i < Rounds; ++i) {
                    if constexpr (__Bits == 128) {
                        A = AA = _State[0];
                        B = BB = _State[1];
                        C = CC = _State[2];
                        D = DD = _State[3];
                    } else {
                        A = _State[0];
                        B = _State[1];
                        C = _State[2];
                        D = _State[3];
                        AA = _State[4];
                        BB = _State[5];
                        CC = _State[6];
                        DD = _State[7];
                    }

                    _Loops(A, B, C, D, AA, BB, CC, DD, T, MessageBlocks[i], std::make_index_sequence<64>{});

                    if constexpr (__Bits == 128) {
                        T = _State[1] + C + DD;
                        _State[1] = _State[2] + D + AA;
                        _State[2] = _State[3] + A + BB;
                        _State[3] = _State[0] + B + CC;
                        _State[0] = T;
                    } else {
                        _State[0] += A;
                        _State[1] += B;
                        _State[2] += C;
                        _State[3] += D;
                        _State[4] += AA;
                        _State[5] += BB;
                        _State[6] += CC;
                        _State[7] += DD;
                    }
                }
            } else {
                uint32_t A, B, C, D, E;
                uint32_t AA, BB, CC, DD, EE;
                uint32_t T;
                auto MessageBlocks = reinterpret_cast<const uint32_t(*)[16]>(pData);

                for (size_t i = 0; i < Rounds; ++i) {
                    if constexpr (__Bits == 160) {
                        A = AA = _State[0];
                        B = BB = _State[1];
                        C = CC = _State[2];
                        D = DD = _State[3];
                        E = EE = _State[4];
                    } else {
                        A = _State[0];
                        B = _State[1];
                        C = _State[2];
                        D = _State[3];
                        E = _State[4];
                        AA = _State[5];
                        BB = _State[6];
                        CC = _State[7];
                        DD = _State[8];
                        EE = _State[9];
                    }

                    _LoopExs(A, B, C, D, E, AA, BB, CC, DD, EE, T, MessageBlocks[i], std::make_index_sequence<80>{});

                    if constexpr (__Bits == 160) {
                        T = _State[1] + C + DD;
                        _State[1] = _State[2] + D + EE;
                        _State[2] = _State[3] + E + AA;
                        _State[3] = _State[4] + A + BB;
                        _State[4] = _State[0] + B + CC;
                        _State[0] = T;
                    } else {
                        _State[0] += A;
                        _State[1] += B;
                        _State[2] += C;
                        _State[3] += D;
                        _State[4] += E;
                        _State[5] += AA;
                        _State[6] += BB;
                        _State[7] += CC;
                        _State[8] += DD;
                        _State[9] += EE;
                    }
                }   // for loop
            }   // if constexpr (__Bits == 128 || __Bits == 256)
        }   // end of Cycle

        //
        //  Once Finish(...) is called, the object should be treated as const
        //
        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSizeValue - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSizeValue] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSizeValue - sizeof(uint64_t) ? 2 : 1;
            {
                auto pBitSizeArea =
                    reinterpret_cast<uint64_t*>(
                        FormattedTailData + (Rounds > 1 ? (2 * BlockSizeValue - sizeof(uint64_t)) :
                                                          (BlockSizeValue - sizeof(uint64_t))
                                            )
                    );
                *pBitSizeArea = ProcessedBytes * 8;
            }

            Cycle(FormattedTailData, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTailData;
                size_t s = sizeof(FormattedTailData);
                while (s--) *p++ = 0;
            }
        }

        Array<uint8_t, DigestSizeValue> Digest() const noexcept {
            return _State.template AsArrayOf<uint8_t, DigestSizeValue>();
        }
    };

}

