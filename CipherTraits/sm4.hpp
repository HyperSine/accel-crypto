#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <utility>

namespace accel::Crypto {

    class SM4_ALG {
    public:
        static constexpr size_t BlockSizeValue = 16;
        static constexpr size_t KeySizeValue = 16;
    private:
        using VectorType = Array<uint32_t, 4>;
        using BlockType = Array<uint32_t, 4>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

#if ACCEL_AVX2_AVAILABLE
        static inline const int SBox[256] = {
#else
        static inline const uint8_t SBox[256] = {
#endif
            0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
            0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
            0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
            0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
            0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
            0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
            0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
            0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
            0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
            0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
            0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
            0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
            0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
            0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
            0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
            0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
        };

        static inline const uint32_t CK[32] = {
            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
            0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
            0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
            0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
            0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
            0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
            0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
        };

        ACCEL_FORCEINLINE
        static void _ReverseBytesOrder4x4(Array<uint32_t, 4>& x) ACCEL_NOEXCEPT {
#if ACCEL_AVX2_AVAILABLE || ACCEL_SSE3_AVAILABLE
            __m128i vec_x;

            vec_x = _mm_loadu_si128(reinterpret_cast<__m128i*>(x.AsCArray()));
            vec_x = _mm_shuffle_epi8(vec_x, _mm_set_epi8(12, 13, 14, 15,
                                                         8, 9, 10, 11,
                                                         4, 5, 6, 7,
                                                         0, 1, 2, 3));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(x.AsCArray()), vec_x);
#else
            x[0] = ByteSwap<uint32_t>(x[0]);
            x[1] = ByteSwap<uint32_t>(x[1]);
            x[2] = ByteSwap<uint32_t>(x[2]);
            x[3] = ByteSwap<uint32_t>(x[3]);
#endif
        }

        ACCEL_FORCEINLINE
        static uint32_t _Tau(uint32_t x) ACCEL_NOEXCEPT {
#if ACCEL_AVX2_AVAILABLE
            __m128i vec_x;

            vec_x = _mm_set1_epi32(x);
            vec_x = _mm_shuffle_epi8(vec_x, _mm_set_epi8(-1, -1, -1, 3,
                                                         -1, -1, -1, 2,
                                                         -1, -1, -1, 1,
                                                         -1, -1, -1, 0));
            vec_x = _mm_i32gather_epi32(SBox, vec_x, 4);
            vec_x = _mm_shuffle_epi8(vec_x, _mm_set_epi8(-1, -1, -1, -1,
                                                         -1, -1, -1, -1,
                                                         -1, -1, -1, -1,
                                                         12, 8, 4, 0));
            return _mm_extract_epi32(vec_x, 0);
#else
            uint32_t r;
            auto x_bytes = reinterpret_cast<uint8_t (&)[4]>(x);
            auto r_bytes = reinterpret_cast<uint8_t (&)[4]>(r);
            r_bytes[0] = SBox[x_bytes[0]];
            r_bytes[1] = SBox[x_bytes[1]];
            r_bytes[2] = SBox[x_bytes[2]];
            r_bytes[3] = SBox[x_bytes[3]];
            return r;
#endif
        }

        ACCEL_FORCEINLINE
        static uint32_t _L(uint32_t x) ACCEL_NOEXCEPT {
            return x ^
                   RotateShiftLeft<uint32_t>(x, 2) ^
                   RotateShiftLeft<uint32_t>(x, 10) ^
                   RotateShiftLeft<uint32_t>(x, 18) ^
                   RotateShiftLeft<uint32_t>(x, 24);
        }

        ACCEL_FORCEINLINE
        static uint32_t _LL(uint32_t x) ACCEL_NOEXCEPT {
            return x ^
                   RotateShiftLeft<uint32_t>(x, 13) ^
                   RotateShiftLeft<uint32_t>(x, 23);
        }

        ACCEL_FORCEINLINE
        static uint32_t _T_Transform(uint32_t x) ACCEL_NOEXCEPT {
            return _L(_Tau(x));
        }

        ACCEL_FORCEINLINE
        static uint32_t _F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) ACCEL_NOEXCEPT {
            return x0 ^ _T_Transform(x1 ^ x2 ^ x3 ^ rk);
        }

        ACCEL_FORCEINLINE
        static uint32_t _TT_Transform(uint32_t x) ACCEL_NOEXCEPT {
            return _LL(_Tau(x));
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const VectorType& MK) ACCEL_NOEXCEPT {
            VectorType K;
            K[0] = MK[0] ^ 0xA3B1BAC6;
            K[1] = MK[1] ^ 0x56AA3350;
            K[2] = MK[2] ^ 0x677D9197;
            K[3] = MK[3] ^ 0xB27022DC;
            for (size_t i = 0; i < 32; ++i)
                _Key[i] = K[(i + 4) % 4] = K[i % 4] ^ _TT_Transform(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i]);
            K.SecureZero();
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& X) const ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 32; ++i)
                X[(i + 4) % 4] = _F(X[i % 4], X[(i + 1) % 4], X[(i + 2) % 4], X[(i + 3) % 4], _Key[i]);
            std::swap(X[0], X[3]);
            std::swap(X[1], X[2]);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& X) const ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 32; ++i)
                X[(i + 4) % 4] = _F(X[i % 4], X[(i + 1) % 4], X[(i + 2) % 4], X[(i + 3) % 4], _Key[31 - i]);
            std::swap(X[0], X[3]);
            std::swap(X[1], X[2]);
        }

        Array<uint32_t, 32> _Key;

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
                VectorType MK;

                MK.LoadFrom(pbUserKey, KeySizeValue);

                _ReverseBytesOrder4x4(MK);

                _KeyExpansion(MK);
                
                MK.SecureZero();
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbPlaintext);
            _ReverseBytesOrder4x4(Text);
            _EncryptProcess(Text);
            _ReverseBytesOrder4x4(Text);
            Text.StoreTo(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.LoadFrom(pbCiphertext);
            _ReverseBytesOrder4x4(Text);
            _DecryptProcess(Text);
            _ReverseBytesOrder4x4(Text);
            Text.StoreTo(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~SM4_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}
