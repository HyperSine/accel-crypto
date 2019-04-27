#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <utility>
#include <memory.h>

namespace accel::CipherTraits {

    template<size_t __KeyBits>
    class SERPENT_ALG {
        static_assert(__KeyBits == 128 || __KeyBits == 192 || __KeyBits == 256,
                      "SERPENT_ALG failure! Unsupported __KeyBits value.");
    public:
        static constexpr size_t BlockSizeValue = 128 / 8;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:
        using BlockType = Array<uint32_t, 4>;
        using VectorType = uint32_t[4];

        //
        // _SBoxTransform and _InverseSBoxTransform are based on
        // [Speeding up Serpent](http://www.ii.uib.no/~osvik/pub/aes3.pdf)
        //

        template<size_t __Index>
        ACCEL_FORCEINLINE
        static void _SBoxTransform(VectorType& RefVector) ACCEL_NOEXCEPT {
            uint32_t& r0 = RefVector[0];
            uint32_t& r1 = RefVector[1];
            uint32_t& r2 = RefVector[2];
            uint32_t& r3 = RefVector[3];
            uint32_t r4;

            if constexpr (__Index == 0) {
                r3 ^= r0; r4 = r1;
                r1 &= r3; r4 ^= r2;
                r1 ^= r0; r0 |= r3;
                r0 ^= r4; r4 ^= r3;
                r3 ^= r2; r2 |= r1;
                r2 ^= r4; r4 = ~r4;
                r4 |= r1; r1 ^= r3;
                r1 ^= r4; r3 |= r0;
                r1 ^= r3; r4 ^= r3;

                // input:   r0, r1, r2, r3
                // output:  r1, r4, r2, r0
                r3 = r0;
                r0 = r1;
                r1 = r4;
            }

            if constexpr (__Index == 1) {
                r0 = ~r0; r2 = ~r2;
                r4 = r0; r0 &= r1;
                r2 ^= r0; r0 |= r3;
                r3 ^= r2; r1 ^= r0;
                r0 ^= r4; r4 |= r1;
                r1 ^= r3; r2 |= r0;
                r2 &= r4; r0 ^= r1;
                r1 &= r2;
                r1 ^= r0; r0 &= r2;
                r0 ^= r4;

                // input:   r0, r1, r2, r3
                // output:  r2, r0, r3, r1
#if ACCEL_SSE2_AVAILABLE
                __m128i temp = _mm_loadu_si128(reinterpret_cast<__m128i*>(RefVector));
                temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(1, 3, 0, 2));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(RefVector), temp);
#else
                r4 = r0;
                r0 = r2;
                r2 = r3;
                r3 = r1;
                r1 = r4;
#endif
            }
            
            if constexpr (__Index == 2) {
                r4 = r0; r0 &= r2;
                r0 ^= r3; r2 ^= r1;
                r2 ^= r0; r3 |= r4;
                r3 ^= r1; r4 ^= r2;
                r1 = r3; r3 |= r4;
                r3 ^= r0; r0 &= r1;
                r4 ^= r0; r1 ^= r3;
                r1 ^= r4; r4 = ~r4;

                // input:   r0, r1, r2, r3
                // output:  r2, r3, r1, r4
                r0 = r2;
                r2 = r1;
                r1 = r3;
                r3 = r4;
            }

            if constexpr (__Index == 3) {
                r4 = r0; r0 |= r3;
                r3 ^= r1; r1 &= r4;
                r4 ^= r2; r2 ^= r3;
                r3 &= r0; r4 |= r1;
                r3 ^= r4; r0 ^= r1;
                r4 &= r0; r1 ^= r3;
                r4 ^= r2; r1 |= r0;
                r1 ^= r2; r0 ^= r3;
                r2 = r1; r1 |= r3;
                r1 ^= r0;

                // input:   r0, r1, r2, r3
                // output:  r1, r2, r3, r4
                r0 = r1;
                r1 = r2;
                r2 = r3;
                r3 = r4;
            }

            if constexpr (__Index == 4) {
                r1 ^= r3; r3 = ~r3;   
                r2 ^= r3; r3 ^= r0;
                r4 = r1; r1 &= r3;
                r1 ^= r2; r4 ^= r3;
                r0 ^= r4; r2 &= r4;
                r2 ^= r0; r0 &= r1;
                r3 ^= r0; r4 |= r1;
                r4 ^= r0; r0 |= r3;
                r0 ^= r2; r2 &= r3;
                r0 = ~r0; r4 ^= r2;

                // input:   r0, r1, r2, r3
                // output:  r1, r4, r0, r3
                r2 = r0;
                r0 = r1;
                r1 = r4;
            }

            if constexpr (__Index == 5) {
                r0 ^= r1; r1 ^= r3;
                r3 = ~r3; r4 = r1;
                r1 &= r0; r2 ^= r3;
                r1 ^= r2; r2 |= r4;
                r4 ^= r3; r3 &= r1;
                r3 ^= r0; r4 ^= r1;
                r4 ^= r2; r2 ^= r0;
                r0 &= r3; r2 = ~r2;
                r0 ^= r4; r4 |= r3;
                r2 ^= r4;

                // input:   r0, r1, r2, r3
                // output:  r1, r3, r0, r2
#if ACCEL_SSE2_AVAILABLE
                __m128i temp = _mm_loadu_si128(reinterpret_cast<__m128i*>(RefVector));
                temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(2, 0, 3, 1));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(RefVector), temp);
#else
                r4 = r2;
                r2 = r0;
                r0 = r1;
                r1 = r3;
                r3 = r4;
#endif
            }

            if constexpr (__Index == 6) {
                r2 = ~r2; r4 = r3;
                r3 &= r0; r0 ^= r4;
                r3 ^= r2; r2 |= r4;
                r1 ^= r3; r2 ^= r0;
                r0 |= r1; r2 ^= r1;
                r4 ^= r0; r0 |= r3;
                r0 ^= r2; r4 ^= r3;
                r4 ^= r0; r3 = ~r3;
                r2 &= r4; 
                r2 ^= r3;

                // input:   r0, r1, r2, r3
                // output:  r0, r1, r4, r2
                r3 = r2;
                r2 = r4;
            }

            if constexpr (__Index == 7) {
                r4 = r1; r1 |= r2;
                r1 ^= r3; r4 ^= r2;
                r2 ^= r1; r3 |= r4;
                r3 &= r0; r4 ^= r2;
                r3 ^= r1; r1 |= r4;
                r1 ^= r0; r0 |= r4;
                r0 ^= r2; r1 ^= r4;
                r2 ^= r1; r1 &= r0;
                r1 ^= r4; r2 = ~r2;
                r2 |= r0;
                r4 ^= r2;

                // input:   r0, r1, r2, r3
                // output:  r4, r3, r1, r0
                r2 = r1;
                r1 = r3;
                r3 = r0;
                r0 = r4;
            }

            static_assert(__Index < 8);
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        static void _InverseSBoxTransform(VectorType& RefVector) ACCEL_NOEXCEPT {
            uint32_t& r0 = RefVector[0];
            uint32_t& r1 = RefVector[1];
            uint32_t& r2 = RefVector[2];
            uint32_t& r3 = RefVector[3];
            uint32_t r4;

            if constexpr (__Index == 0) {
                r2 = ~r2; r4 = r1;
                r1 |= r0; r4 = ~r4;
                r1 ^= r2; r2 |= r4;
                r1 ^= r3; r0 ^= r4;
                r2 ^= r0; r0 &= r3;
                r4 ^= r0; r0 |= r1;
                r0 ^= r2; r3 ^= r4;
                r2 ^= r1; r3 ^= r0;
                r3 ^= r1;
                r2 &= r3;
                r4 ^= r2;

                // input:   r0, r1, r2, r3
                // output:  r0, r4, r1, r3
                r2 = r1;
                r1 = r4;
            }

            if constexpr (__Index == 1) {
                r4 = r1; r1 ^= r3;
                r3 &= r1; r4 ^= r2;
                r3 ^= r0; r0 |= r1;
                r2 ^= r3; r0 ^= r4;
                r0 |= r2; r1 ^= r3;
                r0 ^= r1; r1 |= r3;
                r1 ^= r0; r4 = ~r4;   
                r4 ^= r1; r1 |= r0;
                r1 ^= r0;
                r1 |= r4;
                r3 ^= r1;

                // input:   r0, r1, r2, r3
                // output:  r4, r0, r3, r2
                r1 = r0;
                r0 = r4;
                r4 = r2;
                r2 = r3;
                r3 = r4;
            }

            if constexpr (__Index == 2) {
                r2 ^= r3; r3 ^= r0;
                r4 = r3; r3 &= r2;
                r3 ^= r1; r1 |= r2;
                r1 ^= r4; r4 &= r3;
                r2 ^= r3; r4 &= r0;
                r4 ^= r2; r2 &= r1;
                r2 |= r0; r3 = ~r3;   
                r2 ^= r3; r0 ^= r3;
                r0 &= r1; r3 ^= r4;
                r3 ^= r0;

                // input:   r0, r1, r2, r3
                // output:  r1, r4, r2, r3
                r0 = r1;
                r1 = r4;
            }

            if constexpr (__Index == 3) {
                r4 = r2; r2 ^= r1;
                r0 ^= r2; r4 &= r2;
                r4 ^= r0; r0 &= r1;
                r1 ^= r3; r3 |= r4;
                r2 ^= r3; r0 ^= r3;
                r1 ^= r4; r3 &= r2;
                r3 ^= r1; r1 ^= r0;
                r1 |= r2; r0 ^= r3;
                r1 ^= r4;
                r0 ^= r1;

                // input:   r0, r1, r2, r3
                // output:  r2, r1, r3, r0
#if ACCEL_SSE2_AVAILABLE
                __m128i temp = _mm_loadu_si128(reinterpret_cast<__m128i*>(RefVector));
                temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(0, 3, 1, 2));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(RefVector), temp);
#else
                r4 = r0;
                r0 = r2;
                r2 = r3;
                r3 = r4;
#endif
            }

            if constexpr (__Index == 4) {
                r4 = r2; r2 &= r3;
                r2 ^= r1; r1 |= r3;
                r1 &= r0; r4 ^= r2;
                r4 ^= r1; r1 &= r2;
                r0 = ~r0; r3 ^= r4;
                r1 ^= r3; r3 &= r0;
                r3 ^= r2; r0 ^= r1;
                r2 &= r0; r3 ^= r0;
                r2 ^= r4;
                r2 |= r3; r3 ^= r0;
                r2 ^= r1;

                // input:   r0, r1, r2, r3
                // output:  r0, r3, r2, r4
                r1 = r3;
                r3 = r4;
            }

            if constexpr (__Index == 5) {
                r1 = ~r1; r4 = r3;
                r2 ^= r1; r3 |= r0;
                r3 ^= r2; r2 |= r1;
                r2 &= r0; r4 ^= r3;
                r2 ^= r4; r4 |= r0;
                r4 ^= r1; r1 &= r2;
                r1 ^= r3; r4 ^= r2;
                r3 &= r4; r4 ^= r1;
                r3 ^= r0; r3 ^= r4;
                r4 = ~r4;

                // input:   r0, r1, r2, r3
                // output:  r1, r4, r3, r2
                r0 = r1;
                r1 = r4;
                r4 = r2;
                r2 = r3;
                r3 = r4;
            }

            if constexpr (__Index == 6) {
                r0 ^= r2; r4 = r2;
                r2 &= r0; r4 ^= r3;
                r2 = ~r2; r3 ^= r1;
                r2 ^= r3; r4 |= r0;
                r0 ^= r2; r3 ^= r4;
                r4 ^= r1; r1 &= r3;
                r1 ^= r0; r0 ^= r3;
                r0 |= r2; r3 ^= r1;
                r4 ^= r0;

                // input:   r0, r1, r2, r3
                // output:  r1, r2, r4, r3
                r0 = r1;
                r1 = r2;
                r2 = r4;
            }

            if constexpr (__Index == 7) {
                r4 = r2; r2 ^= r0;
                r0 &= r3; r2 = ~r2;
                r4 |= r3; r3 ^= r1;
                r1 |= r0; r0 ^= r2;
                r2 &= r4; r1 ^= r2;
                r2 ^= r0; r0 |= r2;
                r3 &= r4; r0 ^= r3;
                r4 ^= r1; r3 ^= r4;
                r4 |= r0; r3 ^= r2;
                r4 ^= r2;

                // input:   r0, r1, r2, r3
                // output:  r3, r0, r1, r4
                r2 = r1;
                r1 = r0;
                r0 = r3;
                r3 = r4;
            }

            static_assert(__Index < 8);

        }

        ACCEL_FORCEINLINE
        static void _LinearTransform(VectorType& X) ACCEL_NOEXCEPT {
            X[0] = RotateShiftLeft<uint32_t>(X[0], 13);
            X[2] = RotateShiftLeft<uint32_t>(X[2], 3);
            X[1] ^= X[0] ^ X[2];
            X[3] ^= X[2] ^ (X[0] << 3);
            X[1] = RotateShiftLeft<uint32_t>(X[1], 1);
            X[3] = RotateShiftLeft<uint32_t>(X[3], 7);
            X[0] ^= X[1] ^ X[3];
            X[2] ^= X[3] ^ (X[1] << 7);
            X[0] = RotateShiftLeft<uint32_t>(X[0], 5);
            X[2] = RotateShiftLeft<uint32_t>(X[2], 22);
        }

        ACCEL_FORCEINLINE
        static void _InverseLinearTransform(VectorType& X) ACCEL_NOEXCEPT {
            X[2] = RotateShiftRight<uint32_t>(X[2], 22);
            X[0] = RotateShiftRight<uint32_t>(X[0], 5);
            X[2] ^= X[3] ^ (X[1] << 7);
            X[0] ^= X[1] ^ X[3];
            X[3] = RotateShiftRight<uint32_t>(X[3], 7);
            X[1] = RotateShiftRight<uint32_t>(X[1], 1);
            X[3] ^= X[2] ^ (X[0] << 3);
            X[1] ^= X[0] ^ X[2];
            X[2] = RotateShiftRight<uint32_t>(X[2], 3);
            X[0] = RotateShiftRight<uint32_t>(X[0], 13);
        }

        ACCEL_FORCEINLINE
        void _KeyShcedule(const uint32_t* p4bUserKey) ACCEL_NOEXCEPT {
            Array<uint32_t, 16> w;

            memcpy(w.AsCArray(), p4bUserKey, KeySizeValue);
            memset(w.AsCArray() + KeySizeValue / sizeof(uint32_t), 0, 256 / 8 - KeySizeValue);

            if constexpr (__KeyBits != 256) {
                // if __KeyBits is not 256
                // append one `1` bit to MSB end
                w[KeySizeValue / sizeof(uint32_t)] = 0x00000001;
            }

            for (uint32_t i = 0; i < 8; ++i) {
                w[i + 8] = RotateShiftLeft<uint32_t>(w[i] ^ w[i + 3] ^ w[i + 5] ^ w[i + 7] ^ 0x9e3779b9 ^ i, 11);
            }

            memcpy(_Key.AsCArray(), w.AsCArray() + 8, sizeof(uint32_t) * 8);

            {
                auto& ks = _Key.template AsCArrayOf<uint32_t[132]>();
                for (uint32_t i = 8; i < 132; ++i) {
                    ks[i] = RotateShiftLeft<uint32_t>(ks[i - 8] ^ ks[i - 5] ^ ks[i - 3] ^ ks[i - 1] ^ 0x9e3779b9 ^ i, 11);
                }
            }

            {
                auto& ks = _Key.template AsCArrayOf<uint32_t[33][4]>();

                for (size_t i = 0; i < 32; i += 8) {
                    _SBoxTransform<3>(ks[i]);
                    _SBoxTransform<2>(ks[i + 1]);
                    _SBoxTransform<1>(ks[i + 2]);
                    _SBoxTransform<0>(ks[i + 3]);
                    _SBoxTransform<7>(ks[i + 4]);
                    _SBoxTransform<6>(ks[i + 5]);
                    _SBoxTransform<5>(ks[i + 6]);
                    _SBoxTransform<4>(ks[i + 7]);
                }

                _SBoxTransform<3>(ks[32]);
            }

            w.SecureZero();
        }
        
        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _XorWithKey(BlockType& RefBlock) const ACCEL_NOEXCEPT {
#if ACCEL_SSE2_AVAILABLE
            __m128i temp = _mm_loadu_si128(RefBlock.template AsCArrayOf<__m128i[1]>());
            temp = _mm_xor_si128(temp, _Key[__Index]);
            _mm_storeu_si128(RefBlock.template AsCArrayOf<__m128i[1]>(), temp);
#else
            RefBlock[0] ^= _Key[__Index][0];
            RefBlock[1] ^= _Key[__Index][1];
            RefBlock[2] ^= _Key[__Index][2];
            RefBlock[3] ^= _Key[__Index][3];
#endif
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _R(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            if constexpr (__Index < 31) {
                _XorWithKey<__Index>(RefBlock);
                _SBoxTransform<__Index % 8>(RefBlock.AsCArray());
                _LinearTransform(RefBlock.AsCArray());
            } else if constexpr (__Index == 31) {
                _XorWithKey<__Index>(RefBlock);
                _SBoxTransform<__Index % 8>(RefBlock.AsCArray());
                _XorWithKey<__Index + 1>(RefBlock);
            }
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _InverseR(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            if constexpr (__Index < 31) {
                _InverseLinearTransform(RefBlock.AsCArray());
                _InverseSBoxTransform<__Index % 8>(RefBlock.AsCArray());
                _XorWithKey<__Index>(RefBlock);
            } else if constexpr (__Index == 31) {
                _XorWithKey<__Index + 1>(RefBlock);
                _InverseSBoxTransform<__Index % 8>(RefBlock.AsCArray());
                _XorWithKey<__Index>(RefBlock);
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_R<__Indexes>(RefBlock), ...);
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock, std::index_sequence<__Indexes...>) const ACCEL_NOEXCEPT {
            (_InverseR<31 - __Indexes>(RefBlock), ...);
        }

#if ACCEL_SSE2_AVAILABLE
        Array<__m128i, 33> _Key;
#else
        Array<uint32_t, 33, 4> _Key;
#endif

    public:

        constexpr size_t BlockSize() const ACCEL_NOEXCEPT {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const ACCEL_NOEXCEPT {
            return KeySizeValue;
        }

        ACCEL_NODISCARD
        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (cbUserKey != KeySizeValue) {
                return false;
            } else {
                _KeyShcedule(reinterpret_cast<const uint32_t*>(pbUserKey));
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);
            _EncryptProcess(Text, std::make_index_sequence<32>{});
            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);
            _DecryptProcess(Text, std::make_index_sequence<32>{});
            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

