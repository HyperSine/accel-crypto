#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include "Internal/camellia_constant.hpp"
#include <utility>

namespace accel::Crypto {

    template<size_t __KeyBits>
    class CAMELLIA_ALG : public Internal::CAMELLIA_CONSTANT {
        static_assert(__KeyBits == 128 || __KeyBits == 192 || __KeyBits == 256,
                      "CAMELLIA_ALG failure! Not supported __KeyBits");
    public:
        static constexpr size_t BlockSizeValue = 128 / 8;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:

        struct u128_t {
            uint64_t Left;
            uint64_t Right;

            u128_t& operator^=(const u128_t& Other) ACCEL_NOEXCEPT {
                Left ^= Other.Left;
                Right ^= Other.Right;
                return *this;
            }

            ACCEL_NODISCARD
            u128_t operator^(const u128_t& Other) const ACCEL_NOEXCEPT {
                u128_t RetVal;
                RetVal.Left = Left ^ Other.Left;
                RetVal.Right = Right ^ Other.Right;
                return RetVal;
            }

            template<unsigned __shift>
            u128_t& RotLeft() ACCEL_NOEXCEPT {
                static_assert(__shift <= 128);

                if constexpr (__shift == 0 || __shift == 128) {
                    return *this;
                } else if constexpr (__shift < 64) {
                    uint64_t l, r;
                    l = (Left << __shift) | (Right >> (64u - __shift));
                    r = (Right << __shift) | (Left >> (64u - __shift));
                    Left = l;
                    Right = r;
                    return *this;
                } else if constexpr (__shift == 64) {
                    std::swap(Left, Right);
                    return *this;
                } else {    // 64 < __shift && __shift < 128
                    uint64_t l, r;
                    l = (Right << (__shift - 64u)) | (Left >> (64u - (__shift - 64u)));
                    r = (Left << (__shift - 64u)) | (Right >> (64u - (__shift - 64u)));
                    Left = l;
                    Right = r;
                    return *this;
                }
            }
        };

        using BlockType = Array<uint64_t, 2>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        template<unsigned __N>
        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint8_t _U64ExtractNthByte(uint64_t x) ACCEL_NOEXCEPT {
            return static_cast<uint8_t>((x >> ((7 - __N) * 8u)) & 0xFFu);
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint64_t _Transform_F(uint64_t x, uint64_t k) ACCEL_NOEXCEPT {
            // x = x1||x2||x3||x4||x5||x6||x7||x8   (MostSignificantByte -> LeastSignificantByte)
            // _Transform_F(x) = P(S(x ^ k))
            // S(x) = s1(x1)||s2(x2)||s3(x3)||s4(x4)||s2(x5)||s3(x6)||s4(x7)||s1(x8)

            x ^= k;

            /*
             |                 |   | z8 |
             |                 |   | z7 |
             |                 |   | z6 |
             |                 | * | z5 |
             | 0 1 1 1         |   |    |
             | 1 0 1 1         |   |    |
             | 1 1 0 1         |   |    |
             | 1 1 1 0         |   |    |
             */
            uint32_t H0 =
                SBox1110[_U64ExtractNthByte<7>(x)] ^
                SBox4404[_U64ExtractNthByte<6>(x)] ^
                SBox3033[_U64ExtractNthByte<5>(x)] ^
                SBox0222[_U64ExtractNthByte<4>(x)];
            /*
             |                 |   |    |
             |                 |   |    |
             |                 |   |    |
             |                 | * |    |
             |         1 1 1 0 |   | z4 |
             |         0 1 1 1 |   | z3 |
             |         1 0 1 1 |   | z2 |
             |         1 1 0 1 |   | z1 |
             */
            uint32_t H1 =
                SBox4404[_U64ExtractNthByte<3>(x)] ^
                SBox3033[_U64ExtractNthByte<2>(x)] ^
                SBox0222[_U64ExtractNthByte<1>(x)] ^
                SBox1110[_U64ExtractNthByte<0>(x)];

            /*
                    |                 |   |                 |     | z8 |   |                 |   | z8 |
                    |                 |   |                 |     | z7 |   |                 |   | z7 |
                    |                 |   |                 |     | z6 |   |                 |   | z6 |
             H0 = ( |                 | + |                 | ) * | z5 | = |                 | * | z5 |
                    | 0 1 1 1         |   |         1 1 1 0 |     | z4 |   | 0 1 1 1 1 1 1 0 |   | z4 |
                    | 1 0 1 1         |   |         0 1 1 1 |     | z3 |   | 1 0 1 1 0 1 1 1 |   | z3 |
                    | 1 1 0 1         |   |         1 0 1 1 |     | z2 |   | 1 1 0 1 1 0 1 1 |   | z2 |
                    | 1 1 1 0         |   |         1 1 0 1 |     | z1 |   | 1 1 1 0 1 1 0 1 |   | z1 |
             */
            H0 ^= H1;

            /*
                    | 0 1 1 1 1 1 1 0 |   |         0 1 1 1 |     | z8 |   | 0 1 1 1 1 0 0 1 |   | z8 |
                    | 1 0 1 1 0 1 1 1 |   |         1 0 1 1 |     | z7 |   | 1 0 1 1 1 1 0 0 |   | z7 |
                    | 1 1 0 1 1 0 1 1 |   |         1 1 0 1 |     | z6 |   | 1 1 0 1 0 1 1 0 |   | z6 |
             H1 = ( | 1 1 1 0 1 1 0 1 | + |         1 1 1 0 | ) * | z5 | = | 1 1 1 0 0 0 1 1 | * | z5 |
                    |                 |   |                 |     | z4 |   |                 |   | z4 |
                    |                 |   |                 |     | z3 |   |                 |   | z3 |
                    |                 |   |                 |     | z2 |   |                 |   | z2 |
                    |                 |   |                 |     | z1 |   |                 |   | z1 |
             */
            H1 = H0 ^ RotateShiftRight(H1, 8);

            return static_cast<uint64_t>(H0) << 32u | static_cast<uint64_t>(H1);
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint64_t _Transform_FL(uint64_t x, uint64_t kl) ACCEL_NOEXCEPT {
            uint32_t xL = static_cast<uint32_t>(x >> 32u);
            uint32_t xR = static_cast<uint32_t>(x & 0xFFFFFFFFu);
            uint32_t klL = static_cast<uint32_t>(kl >> 32u);
            uint32_t klR = static_cast<uint32_t>(kl & 0xFFFFFFFFu);
            xR ^= RotateShiftLeft<uint32_t>(xL & klL, 1);
            xL ^= xR | klR;
            return static_cast<uint64_t>(xL) << 32u | static_cast<uint64_t>(xR);
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint64_t _Transform_InverseFL(uint64_t x, uint64_t kl) ACCEL_NOEXCEPT {
            uint32_t xL = static_cast<uint32_t>(x >> 32u);
            uint32_t xR = static_cast<uint32_t>(x & 0xFFFFFFFFu);
            uint32_t klL = static_cast<uint32_t>(kl >> 32u);
            uint32_t klR = static_cast<uint32_t>(kl & 0xFFFFFFFFu);
            xL ^= xR | klR;
            xR ^= RotateShiftLeft<uint32_t>(xL & klL, 1);
            return static_cast<uint64_t>(xL) << 32u | static_cast<uint64_t>(xR);
        }

        ACCEL_FORCEINLINE
        void _KeySchedule(const uint64_t* p8bUserKey) ACCEL_NOEXCEPT {
            Array<u128_t, 2> K;

            if constexpr (__KeyBits == 128) {
                K[0].Left = ByteSwap<uint64_t>(p8bUserKey[0]);
                K[0].Right = ByteSwap<uint64_t>(p8bUserKey[1]);
                K[1].Left = 0;
                K[1].Right = 0;
            }

            if constexpr (__KeyBits == 192) {
                K[0].Left = ByteSwap<uint64_t>(p8bUserKey[0]);
                K[0].Right = ByteSwap<uint64_t>(p8bUserKey[1]);
                K[1].Left = ByteSwap<uint64_t>(p8bUserKey[2]);
                K[1].Right = ~K[1].Left;
            }

            if constexpr (__KeyBits == 256) {
                K[0].Left = ByteSwap<uint64_t>(p8bUserKey[0]);
                K[0].Right = ByteSwap<uint64_t>(p8bUserKey[1]);
                K[1].Left = ByteSwap<uint64_t>(p8bUserKey[2]);
                K[1].Right = ByteSwap<uint64_t>(p8bUserKey[3]);
            }

            if constexpr (__KeyBits == 128) {
                u128_t KA;

                KA = K[0] ^ K[1];
                KA.Right ^= _Transform_F(KA.Left, Sigma[1 - 1]);
                KA.Left ^= _Transform_F(KA.Right, Sigma[2 - 1]);

                KA ^= K[0];
                KA.Right ^= _Transform_F(KA.Left, Sigma[3 - 1]);
                KA.Left ^= _Transform_F(KA.Right, Sigma[4 - 1]);

                //-------------------------------------------------------------------

                K[0].template RotLeft<0>();
                _kw[1 - 1] = K[0].Left;
                _kw[2 - 1] = K[0].Right;

                KA.template RotLeft<0>();
                _k[1 - 1] = KA.Left;
                _k[2 - 1] = KA.Right;
                K[0].template RotLeft<15 - 0>();
                _k[3 - 1] = K[0].Left;
                _k[4 - 1] = K[0].Right;
                KA.template RotLeft<15 - 0>();
                _k[5 - 1] = KA.Left;
                _k[6 - 1] = KA.Right;

                KA.template RotLeft<30 - 15>();
                _kl[1 - 1] = KA.Left;
                _kl[2 - 1] = KA.Right;

                K[0].template RotLeft<45 - 15>();
                _k[7 - 1] = K[0].Left;
                _k[8 - 1] = K[0].Right;
                KA.template RotLeft<45 - 30>();
                K[0].template RotLeft<60 - 45>();
                _k[9 - 1] = KA.Left;
                _k[10 - 1] = K[0].Right;
                KA.template RotLeft<60 - 45>();
                _k[11 - 1] = KA.Left;
                _k[12 - 1] = KA.Right;

                K[0].template RotLeft<77 - 60>();
                _kl[3 - 1] = K[0].Left;
                _kl[4 - 1] = K[0].Right;

                K[0].template RotLeft<94 - 77>();
                _k[13 - 1] = K[0].Left;
                _k[14 - 1] = K[0].Right;
                KA.template RotLeft<94 - 60>();
                _k[15 - 1] = KA.Left;
                _k[16 - 1] = KA.Right;
                K[0].template RotLeft<111 - 94>();
                _k[17 - 1] = K[0].Left;
                _k[18 - 1] = K[0].Right;

                KA.template RotLeft<111 - 94>();
                _kw[3 - 1] = KA.Left;
                _kw[4 - 1] = KA.Right;

                SecureWipe(&KA, sizeof(KA));
            }

            if constexpr (__KeyBits == 192 || __KeyBits == 256) {
                u128_t KA, KB;

                KA = K[0] ^ K[1];
                KA.Right ^= _Transform_F(KA.Left, Sigma[1 - 1]);
                KA.Left ^= _Transform_F(KA.Right, Sigma[2 - 1]);

                KA ^= K[0];
                KA.Right ^= _Transform_F(KA.Left, Sigma[3 - 1]);
                KA.Left ^= _Transform_F(KA.Right, Sigma[4 - 1]);

                KB = KA ^ K[1];
                KB.Right ^= _Transform_F(KB.Left, Sigma[5 - 1]);
                KB.Left ^= _Transform_F(KB.Right, Sigma[6 - 1]);

                //-------------------------------------------------------------------

                K[0].template RotLeft<0>();
                _kw[1 - 1] = K[0].Left;
                _kw[2 - 1] = K[0].Right;

                KB.template RotLeft<0>();
                _k[1 - 1] = KB.Left;
                _k[2 - 1] = KB.Right;
                K[1].template RotLeft<15 - 0>();
                _k[3 - 1] = K[1].Left;
                _k[4 - 1] = K[1].Right;
                KA.template RotLeft<15 - 0>();
                _k[5 - 1] = KA.Left;
                _k[6 - 1] = KA.Right;

                K[1].template RotLeft<30 - 15>();
                _kl[1 - 1] = K[1].Left;
                _kl[2 - 1] = K[1].Right;

                KB.template RotLeft<30 - 0>();
                _k[7 - 1] = KB.Left;
                _k[8 - 1] = KB.Right;
                K[0].template RotLeft<45 - 0>();
                _k[9 - 1] = K[0].Left;
                _k[10 - 1] = K[0].Right;
                KA.template RotLeft<45 - 15>();
                _k[11 - 1] = KA.Left;
                _k[12 - 1] = KA.Right;

                K[0].template RotLeft<60 - 45>();
                _kl[3 - 1] = K[0].Left;
                _kl[4 - 1] = K[0].Right;

                K[1].template RotLeft<60 - 30>();
                _k[13 - 1] = K[1].Left;
                _k[14 - 1] = K[1].Right;
                KB.template RotLeft<60 - 30>();
                _k[15 - 1] = KB.Left;
                _k[16 - 1] = KB.Right;
                K[0].template RotLeft<77 - 60>();
                _k[17 - 1] = K[0].Left;
                _k[18 - 1] = K[0].Right;

                KA.template RotLeft<77 - 45>();
                _kl[5 - 1] = KA.Left;
                _kl[6 - 1] = KA.Right;

                K[1].template RotLeft<94 - 60>();
                _k[19 - 1] = K[1].Left;
                _k[20 - 1] = K[1].Right;
                KA.template RotLeft<94 - 77>();
                _k[21 - 1] = KA.Left;
                _k[22 - 1] = KA.Right;
                K[0].template RotLeft<111 - 77>();
                _k[23 - 1] = K[0].Left;
                _k[24 - 1] = K[0].Right;

                KB.template RotLeft<111 - 60>();
                _kw[3 - 1] = KB.Left;
                _kw[4 - 1] = KB.Right;

                SecureWipe(&KA, sizeof(KA));
                SecureWipe(&KB, sizeof(KB));
            }

            K.SecureZero();
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _6Round(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index + 1]);
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index + 2]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index + 3]);
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index + 4]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index + 5]);
        }

        template<size_t __Index>
        ACCEL_FORCEINLINE
        void _Inverse6Round(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index + 5]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index + 4]);
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index + 3]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index + 2]);
            RefBlock[1] ^= _Transform_F(RefBlock[0], _k[__Index + 1]);
            RefBlock[0] ^= _Transform_F(RefBlock[1], _k[__Index]);
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[0] ^= _kw[1 - 1];
            RefBlock[1] ^= _kw[2 - 1];

            _6Round<0>(RefBlock);
            RefBlock[0] = _Transform_FL(RefBlock[0], _kl[1 - 1]);
            RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[2 - 1]);
            _6Round<6>(RefBlock);
            RefBlock[0] = _Transform_FL(RefBlock[0], _kl[3 - 1]);
            RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[4 - 1]);
            _6Round<12>(RefBlock);

            if (__KeyBits > 128) {
                RefBlock[0] = _Transform_FL(RefBlock[0], _kl[5 - 1]);
                RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[6 - 1]);
                _6Round<18>(RefBlock);
            }

            std::swap(RefBlock[0], RefBlock[1]);

            RefBlock[0] ^= _kw[3 - 1];
            RefBlock[1] ^= _kw[4 - 1];
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            RefBlock[0] ^= _kw[3 - 1];
            RefBlock[1] ^= _kw[4 - 1];

            if (__KeyBits > 128) {
                _Inverse6Round<18>(RefBlock);
                RefBlock[0] = _Transform_FL(RefBlock[0], _kl[6 - 1]);
                RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[5 - 1]);
            }

            _Inverse6Round<12>(RefBlock);
            RefBlock[0] = _Transform_FL(RefBlock[0], _kl[4 - 1]);
            RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[3 - 1]);
            _Inverse6Round<6>(RefBlock);
            RefBlock[0] = _Transform_FL(RefBlock[0], _kl[2 - 1]);
            RefBlock[1] = _Transform_InverseFL(RefBlock[1], _kl[1 - 1]);
            _Inverse6Round<0>(RefBlock);

            std::swap(RefBlock[0], RefBlock[1]);

            RefBlock[0] ^= _kw[1 - 1];
            RefBlock[1] ^= _kw[2 - 1];
        }

        Array<uint64_t, 4> _kw;
        Array<uint64_t, (__KeyBits > 128 ? 24 : 18)> _k;
        Array<uint64_t, (__KeyBits > 128 ? 6 : 4)> _kl;

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
                _KeySchedule(reinterpret_cast<const uint64_t*>(pbUserKey));
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint64_t>(reinterpret_cast<uint64_t*>(pbPlaintext)[0]);
            Text[1] = ByteSwap<uint64_t>(reinterpret_cast<uint64_t*>(pbPlaintext)[1]);
            _EncryptProcess(Text);
            reinterpret_cast<uint64_t*>(pbPlaintext)[0] = ByteSwap<uint64_t>(Text[0]);
            reinterpret_cast<uint64_t*>(pbPlaintext)[1] = ByteSwap<uint64_t>(Text[1]);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint64_t>(reinterpret_cast<uint64_t*>(pbCiphertext)[0]);
            Text[1] = ByteSwap<uint64_t>(reinterpret_cast<uint64_t*>(pbCiphertext)[1]);
            _DecryptProcess(Text);
            reinterpret_cast<uint64_t*>(pbCiphertext)[0] = ByteSwap<uint64_t>(Text[0]);
            reinterpret_cast<uint64_t*>(pbCiphertext)[1] = ByteSwap<uint64_t>(Text[1]);

            return BlockSizeValue;
        }

        void ClearKey() {
            _kw.SecureZero();
            _k.SecureZero();
            _kl.SecureZero();
        }

        ~CAMELLIA_ALG() {
            _kw.SecureZero();
            _k.SecureZero();
            _kl.SecureZero();
        }
    };

}

