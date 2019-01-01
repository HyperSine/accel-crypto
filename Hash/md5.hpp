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

        template<size_t __Index>
        __forceinline
        static uint32_t _F(uint32_t X, uint32_t Y, uint32_t Z) noexcept {
            if constexpr (0 <= __Index && __Index < 16) {
                return (X & Y) | (~X & Z);
            } else if constexpr (16 <= __Index && __Index < 32) {
                return (X & Z) | (Y & ~Z);
            } else if constexpr (32 <= __Index && __Index < 48) {
                return X ^ Y ^ Z;
            } else if constexpr (48 <= __Index && __Index < 64) {
                return Y ^ (X | ~Z);
            } else {
                static_assert(__Index < 64, "_F failure! Out of range.");
            }
            __unreachable();
        }

        template<size_t __Index>
        __forceinline
        static void _FF(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t& D, uint32_t K, unsigned s, uint32_t T) noexcept {
            A += _F<__Index>(B, C, D) + K + T;
            A = RotateShiftLeft(A, s);
            A += B;
        }

        static constexpr uint32_t _T_Const[64] = {
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
        };

        static constexpr unsigned _s[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        static constexpr size_t _r[64] = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
            5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
            0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
        };

        template<size_t __Index>
        __forceinline
        static void _Loop(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t &D,
                          const uint32_t (&MessageBlock)[16]) noexcept {
            if constexpr (__Index % 4 == 0) {
                _FF<__Index>(A, B, C, D, MessageBlock[_r[__Index]], _s[__Index], _T_Const[__Index]);
            } else if constexpr (__Index % 4 == 1) {
                _FF<__Index>(D, A, B, C, MessageBlock[_r[__Index]], _s[__Index], _T_Const[__Index]);
            } else if constexpr (__Index % 4 == 2) {
                _FF<__Index>(C, D, A, B, MessageBlock[_r[__Index]], _s[__Index], _T_Const[__Index]);
            } else {
                _FF<__Index>(B, C, D, A, MessageBlock[_r[__Index]], _s[__Index], _T_Const[__Index]);
            }
        }

        template<size_t... __Indexes>
        __forceinline
        static void _Loops(uint32_t& A, uint32_t& B, uint32_t& C, uint32_t &D,
                           const uint32_t (&MessageBlock)[16], std::index_sequence<__Indexes...>) {
            (_Loop<__Indexes>(A, B, C, D, MessageBlock), ...);
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

                _Loops(AA, BB, CC, DD, MessageBlock[i], std::make_index_sequence<64>{});

                _State[0] += AA;
                _State[1] += BB;
                _State[2] += CC;
                _State[3] += DD;
            }
        }

        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSize - sizeof(uint64_t) - 1);

            uint8_t FormattedTailData[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(FormattedTailData, pTailData, TailDataSize);
            FormattedTailData[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSize - sizeof(uint64_t) ? 2 : 1;
            {
                auto pBitSizeArea =
                    reinterpret_cast<uint64_t*>(
                        FormattedTailData + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) :
                                                          (BlockSize - sizeof(uint64_t))
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

        ByteArray<DigestSize> Digest() const noexcept {
            return _State.AsArrayOf<uint8_t, DigestSize>();
        }
    };

}

