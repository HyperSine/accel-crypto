#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include "../Common/ShuffleForward.hpp"
#include <memory.h>
#include <assert.h>

namespace accel::Hash {

    template<size_t __i, size_t __j>
    struct _HAVAL_PHI;

    template<>
    struct _HAVAL_PHI<3, 1> {
        using Value = std::index_sequence<1, 0, 3, 5, 6, 2, 4>;
    };

    template<>
    struct _HAVAL_PHI<3, 2> {
        using Value = std::index_sequence<4, 2, 1, 0, 5, 3, 6>;
    };

    template<>
    struct _HAVAL_PHI<3, 3> {
        using Value = std::index_sequence<6, 1, 2, 3, 4, 5, 0>;
    };

    template<>
    struct _HAVAL_PHI<4, 1> {
        using Value = std::index_sequence<2, 6, 1, 4, 5, 3, 0>;
    };

    template<>
    struct _HAVAL_PHI<4, 2> {
        using Value = std::index_sequence<3, 5, 2, 0, 1, 6, 4>;
    };

    template<>
    struct _HAVAL_PHI<4, 3> {
        using Value = std::index_sequence<1, 4, 3, 6, 0, 2, 5>;
    };

    template<>
    struct _HAVAL_PHI<4, 4> {
        using Value = std::index_sequence<6, 4, 0, 5, 2, 1, 3>;
    };

    template<>
    struct _HAVAL_PHI<5, 1> {
        using Value = std::index_sequence<3, 4, 1, 0, 5, 2, 6>;
    };

    template<>
    struct _HAVAL_PHI<5, 2> {
        using Value = std::index_sequence<6, 2, 1, 0, 3, 4, 5>;
    };

    template<>
    struct _HAVAL_PHI<5, 3> {
        using Value = std::index_sequence<2, 6, 0, 4, 3, 1, 5>;
    };

    template<>
    struct _HAVAL_PHI<5, 4> {
        using Value = std::index_sequence<1, 5, 3, 2, 0, 4, 6>;
    };

    template<>
    struct _HAVAL_PHI<5, 5> {
        using Value = std::index_sequence<2, 5, 0, 6, 4, 3, 1>;
    };

    template<size_t __bits, size_t __PASS>
    class _HAVAL_ALG_IMPL {
        static_assert(__bits == 128 ||
                      __bits == 160 ||
                      __bits == 192 ||
                      __bits == 224 ||
                      __bits == 256, "_IMPL_HAVAL_ALG failure! Invalid __bits");
        static_assert(__PASS == 3 ||
                      __PASS == 4 ||
                      __PASS == 5,
                      "_IMPL_HAVAL_ALG failure! Invalid __PASS");
    private:

        static constexpr unsigned _HAVAL_VERSION = 1;

        static constexpr uint32_t _K[5][32] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,

            0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
            0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
            0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
            0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5,

            0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
            0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27, 0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
            0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
            0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C,

            0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
            0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1, 0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
            0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
            0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4,

            0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
            0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073, 0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
            0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
            0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4
        };

        static constexpr size_t _ord[5][32] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,

            5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
            30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27,

            19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
            31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2,

            24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
            22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13,

            27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
            5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15
        };

        template<size_t __pass>
        __forceinline
        static uint32_t _impl_F(uint32_t X6, uint32_t X5, uint32_t X4, uint32_t X3,
                                uint32_t X2, uint32_t X1, uint32_t X0) noexcept {
            if constexpr (__pass == 1) {
                return X0 ^
                    (X1 & X0) ^
                    (X3 & X6) ^
                    (X2 & X5) ^
                    (X1 & X4);
            } else if constexpr (__pass == 2) {
                return X0 ^
                    (X0 & X2) ^
                    (X4 & X5) ^
                    (X3 & X5) ^
                    (X2 & X6) ^
                    (X1 & X4) ^
                    (X1 & X2) ^
                    (X2 & X4 & X5) ^
                    (X1 & X2 & X3);
            } else if constexpr (__pass == 3) {
                return X0 ^
                    (X0 & X3) ^
                    (X3 & X6) ^
                    (X2 & X5) ^
                    (X1 & X4) ^
                    (X1 & X2 & X3);
            } else if constexpr (__pass == 4) {
                return X0 ^
                    (X0 & X4) ^
                    (X4 & X6) ^
                    (X4 & X5) ^
                    (X3 & X6) ^
                    (X3 & X5) ^
                    (X3 & X4) ^
                    (X2 & X6) ^
                    (X1 & X4) ^
                    (X3 & X4 & X6) ^
                    (X2 & X4 & X5) ^
                    (X1 & X2 & X3);
            } else if constexpr (__pass == 5) {
                return X0 ^
                    (X0 & X5) ^
                    (X0 & X1 & X2 & X3) ^
                    (X3 & X6) ^
                    (X2 & X5) ^
                    (X1 & X4);
            } else {
                static_assert(__pass != 0 && __pass < 6, "_impl_F failure! Out of range.");
            }
            __unreachable();
        }

        template<size_t __pass, size_t... __PermuteSeq>
        __forceinline
        static uint32_t _F(uint32_t& T6, uint32_t& T5, uint32_t& T4, uint32_t& T3,
                           uint32_t& T2, uint32_t& T1, uint32_t& T0,
                           std::index_sequence<__PermuteSeq...>) noexcept {
            static_assert(sizeof...(__PermuteSeq) == 7,
                          "_F failure! Incorrect size of __PermuteSeq");
            return accel::ShuffleForward<__PermuteSeq...>(_impl_F<__pass>, T0, T1, T2, T3, T4, T5, T6);
        }

        template<size_t __pass, size_t __Index>
        __forceinline
        static void _Loop(uint32_t& T7, uint32_t& T6, uint32_t& T5, uint32_t& T4,
                          uint32_t& T3, uint32_t& T2, uint32_t& T1, uint32_t& T0,
                          const uint32_t (&MessageBlock)[32]) noexcept {
            uint32_t P = _F<__pass>(T6, T5, T4, T3, T2, T1, T0,
                                    typename _HAVAL_PHI<__PASS, __pass>::Value{});
            uint32_t R = RotateShiftRight<uint32_t>(P, 7) +
                         RotateShiftRight<uint32_t>(T7, 11) +
                         MessageBlock[_ord[__pass - 1][__Index]] +
                         _K[__pass - 1][__Index];
            T7 = R;
        }

        template<size_t __pass, size_t... __Indexes>
        __forceinline
        static void _Loops(uint32_t (&T)[8],
                           const uint32_t (&MessageBlock)[32],
                           std::index_sequence<__Indexes...>) noexcept {
            (_Loop<__pass, __Indexes>(T[7 - (__Indexes + 0) % 8],
                                      T[7 - (__Indexes + 1) % 8],
                                      T[7 - (__Indexes + 2) % 8],
                                      T[7 - (__Indexes + 3) % 8],
                                      T[7 - (__Indexes + 4) % 8],
                                      T[7 - (__Indexes + 5) % 8],
                                      T[7 - (__Indexes + 6) % 8],
                                      T[7 - (__Indexes + 7) % 8], MessageBlock), ...);
        }

        template<size_t __i>
        __forceinline
        static void _Pass(uint32_t (&T)[8], const uint32_t (&MessageBlock)[32]) noexcept {
            _Loops<__i>(T, MessageBlock, std::make_index_sequence<32>{});
        }

        SecureArray<uint32_t, 8> _State;

    public:
        static constexpr size_t BlockSize = 128;
        static constexpr size_t DigestSize = __bits / 8;

        _HAVAL_ALG_IMPL() noexcept :
            _State{ 0x243F6A88u,
                    0x85A308D3u,
                    0x13198A2Eu,
                    0x03707344u,
                    0xA4093822u,
                    0x299F31D0u,
                    0x082EFA98u,
                    0xEC4E6C89u } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t T[8];
            auto MessageBlocks = reinterpret_cast<const uint32_t (*)[32]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                T[0] = _State[0];
                T[1] = _State[1];
                T[2] = _State[2];
                T[3] = _State[3];
                T[4] = _State[4];
                T[5] = _State[5];
                T[6] = _State[6];
                T[7] = _State[7];

                _Pass<1>(T, MessageBlocks[i]);
                _Pass<2>(T, MessageBlocks[i]);
                _Pass<3>(T, MessageBlocks[i]);
                if constexpr (__PASS == 4 || __PASS == 5)
                    _Pass<4>(T, MessageBlocks[i]);
                if constexpr (__PASS == 5)
                    _Pass<5>(T, MessageBlocks[i]);

                _State[0] += T[0];
                _State[1] += T[1];
                _State[2] += T[2];
                _State[3] += T[3];
                _State[4] += T[4];
                _State[5] += T[5];
                _State[6] += T[6];
                _State[7] += T[7];
            }
        }

        void Finish(const void* pTail, size_t TailSize, uint64_t ProcessedBytes) noexcept {
            static constexpr size_t ReserveSize = 1 + 2 + sizeof(uint64_t);
            assert(TailSize <= 2 * BlockSize - ReserveSize);

            uint8_t FormattedTail[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(FormattedTail, pTail, TailSize);
            FormattedTail[TailSize] = 0x01;
            Rounds = TailSize > BlockSize - ReserveSize ? 2 : 1;
            {
                auto pBitSizeArea =
                        reinterpret_cast<uint64_t*>(
                                FormattedTail + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) :
                                                (BlockSize - sizeof(uint64_t))
                                )
                        );
                auto pDGSTLENG = reinterpret_cast<uint8_t*>(pBitSizeArea) - 2;
                pDGSTLENG[0] = static_cast<uint8_t>(
                    (_HAVAL_VERSION & 0x7) |
                    ((__PASS & 0x7) << 3)  |
                    ((__bits & 0x3) << 6)
                );
                pDGSTLENG[1] = static_cast<uint8_t>(__bits >> 2);
                *pBitSizeArea = ProcessedBytes * 8;
            }

            Cycle(FormattedTail, Rounds);

            {   // clear FormattedTailData
                volatile uint8_t* p = FormattedTail;
                size_t s = sizeof(FormattedTail);
                while (s--) *p++ = 0;
            }
        }

        ByteArray<DigestSize> Digest() const noexcept {
            ByteArray<DigestSize> result;
            if constexpr (__bits == 128) {
                result.template AsArrayOf<uint32_t, 4>()[0] =
                    RotateShiftRight((_State[7] & 0x000000ffu) |
                                     (_State[6] & 0xff000000u) |
                                     (_State[5] & 0x00ff0000u) |
                                     (_State[4] & 0x0000ff00u), 8);
                result.template AsArrayOf<uint32_t, 4>()[1] =
                    RotateShiftRight((_State[7] & 0x0000ff00u) |
                                     (_State[6] & 0x000000ffu) |
                                     (_State[5] & 0xff000000u) |
                                     (_State[4] & 0x00ff0000u), 16);
                result.template AsArrayOf<uint32_t, 4>()[2] =
                    RotateShiftRight((_State[7] & 0x00ff0000u) |
                                     (_State[6] & 0x0000ff00u) |
                                     (_State[5] & 0x000000ffu) |
                                     (_State[4] & 0xff000000u), 24);
                result.template AsArrayOf<uint32_t, 4>()[3] =
                    (_State[7] & 0xff000000u) |
                    (_State[6] & 0x00ff0000u) |
                    (_State[5] & 0x0000ff00u) |
                    (_State[4] & 0x000000ffu);
                result.template AsArrayOf<uint32_t, 4>()[0] += _State[0];
                result.template AsArrayOf<uint32_t, 4>()[1] += _State[1];
                result.template AsArrayOf<uint32_t, 4>()[2] += _State[2];
                result.template AsArrayOf<uint32_t, 4>()[3] += _State[3];
                return result;
            } else if constexpr (__bits == 160) {
                result.template AsArrayOf<uint32_t, 5>()[0] =
                    RotateShiftRight((_State[7] & 0x0000003fu) |
                                     (_State[6] & 0xfe000000u) |
                                     (_State[5] & 0x01f80000u), 19);
                result.template AsArrayOf<uint32_t, 5>()[1] =
                    RotateShiftRight((_State[7] & 0x00000fc0u) |
                                     (_State[6] & 0x0000003fu) |
                                     (_State[5] & 0xfe000000u), 25);
                result.template AsArrayOf<uint32_t, 5>()[2] =
                    (_State[7] & 0x0007f000u) |
                    (_State[6] & 0x00000fc0u) |
                    (_State[5] & 0x0000003fu);
                result.template AsArrayOf<uint32_t, 5>()[3] =
                    ((_State[7] & 0x01f80000u) |
                     (_State[6] & 0x0007f000u) |
                     (_State[5] & 0x00000fc0u)) >> 6;
                result.template AsArrayOf<uint32_t, 5>()[4] =
                    ((_State[7] & 0xfe000000u) |
                     (_State[6] & 0x01f80000u) |
                     (_State[5] & 0x0007f000u)) >> 12;
                result.template AsArrayOf<uint32_t, 5>()[0] += _State[0];
                result.template AsArrayOf<uint32_t, 5>()[1] += _State[1];
                result.template AsArrayOf<uint32_t, 5>()[2] += _State[2];
                result.template AsArrayOf<uint32_t, 5>()[3] += _State[3];
                result.template AsArrayOf<uint32_t, 5>()[4] += _State[4];
                return result;
            } else if constexpr (__bits == 192) {
                result.template AsArrayOf<uint32_t, 6>()[0] =
                    RotateShiftRight((_State[7] & 0x0000001fu) |
                                     (_State[6] & 0xfc000000u), 26);
                result.template AsArrayOf<uint32_t, 6>()[1] =
                    (_State[7] & 0x000003e0u) |
                    (_State[6] & 0x0000001fu);
                result.template AsArrayOf<uint32_t, 6>()[2] =
                    ((_State[7] & 0x0000fc00u) |
                     (_State[6] & 0x000003e0u)) >> 5;
                result.template AsArrayOf<uint32_t, 6>()[3] =
                    ((_State[7] & 0x001f0000u) |
                     (_State[6] & 0x0000fc00u)) >> 10;
                result.template AsArrayOf<uint32_t, 6>()[4] =
                    ((_State[7] & 0x03e00000u) |
                     (_State[6] & 0x001f0000u)) >> 16;
                result.template AsArrayOf<uint32_t, 6>()[5] =
                    ((_State[7] & 0xfc000000u) |
                     (_State[6] & 0x03e00000u)) >> 21;
                result.template AsArrayOf<uint32_t, 6>()[0] += _State[0];
                result.template AsArrayOf<uint32_t, 6>()[1] += _State[1];
                result.template AsArrayOf<uint32_t, 6>()[2] += _State[2];
                result.template AsArrayOf<uint32_t, 6>()[3] += _State[3];
                result.template AsArrayOf<uint32_t, 6>()[4] += _State[4];
                result.template AsArrayOf<uint32_t, 6>()[5] += _State[5];
                return result;
            } else if constexpr (__bits == 224) {
                result.template AsArrayOf<uint32_t, 7>()[0] =
                    (_State[7] & 0xf8000000u) >> 27;
                result.template AsArrayOf<uint32_t, 7>()[1] =
                    (_State[7] & 0x07c00000u) >> 22;
                result.template AsArrayOf<uint32_t, 7>()[2] =
                    (_State[7] & 0x003c0000u) >> 18;
                result.template AsArrayOf<uint32_t, 7>()[3] =
                    (_State[7] & 0x0003e000u) >> 13;
                result.template AsArrayOf<uint32_t, 7>()[4] =
                    (_State[7] & 0x00001e00u) >> 9;
                result.template AsArrayOf<uint32_t, 7>()[5] =
                    (_State[7] & 0x000001f0u) >> 4;
                result.template AsArrayOf<uint32_t, 7>()[6] =
                    (_State[7] & 0x0000000fu);
                result.template AsArrayOf<uint32_t, 7>()[0] += _State[0];
                result.template AsArrayOf<uint32_t, 7>()[1] += _State[1];
                result.template AsArrayOf<uint32_t, 7>()[2] += _State[2];
                result.template AsArrayOf<uint32_t, 7>()[3] += _State[3];
                result.template AsArrayOf<uint32_t, 7>()[4] += _State[4];
                result.template AsArrayOf<uint32_t, 7>()[5] += _State[5];
                result.template AsArrayOf<uint32_t, 7>()[6] += _State[6];
                return result;
            } else {
                return _State.AsArrayOf<uint8_t, DigestSize>();
            }
        }
    };

    using HAVAL128_3_ALG = _HAVAL_ALG_IMPL<128, 3>;
    using HAVAL128_4_ALG = _HAVAL_ALG_IMPL<128, 4>;
    using HAVAL128_5_ALG = _HAVAL_ALG_IMPL<128, 5>;
    
    using HAVAL160_3_ALG = _HAVAL_ALG_IMPL<160, 3>;
    using HAVAL160_4_ALG = _HAVAL_ALG_IMPL<160, 4>;
    using HAVAL160_5_ALG = _HAVAL_ALG_IMPL<160, 5>;
    
    using HAVAL192_3_ALG = _HAVAL_ALG_IMPL<192, 3>;
    using HAVAL192_4_ALG = _HAVAL_ALG_IMPL<192, 4>;
    using HAVAL192_5_ALG = _HAVAL_ALG_IMPL<192, 5>;

    using HAVAL224_3_ALG = _HAVAL_ALG_IMPL<224, 3>;
    using HAVAL224_4_ALG = _HAVAL_ALG_IMPL<224, 4>;
    using HAVAL224_5_ALG = _HAVAL_ALG_IMPL<224, 5>;

    using HAVAL256_3_ALG = _HAVAL_ALG_IMPL<256, 3>;
    using HAVAL256_4_ALG = _HAVAL_ALG_IMPL<256, 4>;
    using HAVAL256_5_ALG = _HAVAL_ALG_IMPL<256, 5>;
}

