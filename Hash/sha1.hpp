#pragma once
#include <stdint.h>
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"
#include <memory.h>
#include <assert.h>
#include "hasher.hpp"

namespace accel::Hash {

    class SHA1_ALG {
    private:
        SecureArray<uint32_t, 5> _State;
    public:
        static constexpr size_t BlockSize = 64;
        static constexpr size_t DigestSize = 20;

        SHA1_ALG() noexcept :
            _State{ 0x67452301u,
                    0xEFCDAB89u,
                    0x98BADCFEu,
                    0x10325476u,
                    0xC3D2E1F0u } {}

        void Cycle(const void* pData, size_t Rounds) noexcept {
            uint32_t Buffer[80] = { 0 };
            uint32_t a, b, c, d, e;
            auto MessageBlock = reinterpret_cast<const uint32_t(*)[BlockSize / sizeof(uint32_t)]>(pData);

            for (size_t i = 0; i < Rounds; ++i) {
                for (int j = 0; j < 16; ++j)
                    Buffer[j] = Intrinsic::ByteSwap(MessageBlock[i][j]);

                for (int j = 16; j < 80; ++j)
                    Buffer[j] = Intrinsic::RotateShiftLeft(Buffer[j - 3] ^
                                                           Buffer[j - 8] ^
                                                           Buffer[j - 14] ^
                                                           Buffer[j - 16], 1);
                
                a = _State[0];
                b = _State[1];
                c = _State[2];
                d = _State[3];
                e = _State[4];

                for (int j = 0; j < 20; ++j) {
                    uint32_t T = Intrinsic::RotateShiftLeft(a, 5);
                    T += ((b & c) ^ (~b & d)) + e + 0x5A827999 + Buffer[j];
                    e = d;
                    d = c;
                    c = Intrinsic::RotateShiftLeft(b, 30);
                    b = a;
                    a = T;
                }
                for (int j = 20; j < 40; ++j) {
                    uint32_t T = Intrinsic::RotateShiftLeft(a, 5);
                    T += (b ^ c ^ d) + e + 0x6ED9EBA1 + Buffer[j];
                    e = d;
                    d = c;
                    c = Intrinsic::RotateShiftLeft(b, 30);
                    b = a;
                    a = T;
                }
                for (int j = 40; j < 60; ++j) {
                    uint32_t T = Intrinsic::RotateShiftLeft(a, 5);
                    T += ((b & c) ^ (b & d) ^ (c & d)) + e + 0x8F1BBCDC + Buffer[j];
                    e = d;
                    d = c;
                    c = Intrinsic::RotateShiftLeft(b, 30);
                    b = a;
                    a = T;
                }
                for (int j = 60; j < 80; ++j) {
                    uint32_t T = Intrinsic::RotateShiftLeft(a, 5);
                    T += (b ^ c ^ d) + e + 0xCA62C1D6 + Buffer[j];
                    e = d;
                    d = c;
                    c = Intrinsic::RotateShiftLeft(b, 30);
                    b = a;
                    a = T;
                }
                _State[0] += a;
                _State[1] += b;
                _State[2] += c;
                _State[3] += d;
                _State[4] += e;
            }
        }

        //
        //  Once Finish(...) is called, this object should be treated as const
        //
        void Finish(const void* pTailData, size_t TailDataSize, uint64_t ProcessedBytes) noexcept {
            assert(TailDataSize <= 2 * BlockSize - sizeof(uint64_t) - 1);

            uint8_t Tail[2 * BlockSize] = {};
            size_t Rounds;

            memcpy(Tail, pTailData, TailDataSize);
            Tail[TailDataSize] = 0x80;
            Rounds = TailDataSize >= BlockSize - sizeof(uint64_t) ? 2 : 1;
            *reinterpret_cast<uint64_t*>(Tail + (Rounds > 1 ? (2 * BlockSize - sizeof(uint64_t)) : (BlockSize - sizeof(uint64_t)))) =
                    Intrinsic::ByteSwap<uint64_t>(ProcessedBytes * 8);

            Cycle(Tail, Rounds);

            _State[0] = Intrinsic::ByteSwap(_State[0]);
            _State[1] = Intrinsic::ByteSwap(_State[1]);
            _State[2] = Intrinsic::ByteSwap(_State[2]);
            _State[3] = Intrinsic::ByteSwap(_State[3]);
            _State[4] = Intrinsic::ByteSwap(_State[4]);
        }

        ByteArray<DigestSize> Digest() const noexcept {
            return _State.AsArray().AsArrayOf<uint8_t, DigestSize>();
        }
    };

}

