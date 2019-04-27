#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Block.hpp"
#include "../MemoryAccess.hpp"
#include "../Intrinsic.hpp"
#include "Internal/aria_constant.hpp"

namespace accel::Crypto {

    template<size_t __KeyBits>
    class ARIA_ALG : public Internal::ARIA_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 16;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:

        static constexpr size_t _Nr = __KeyBits / 32 + 8;

        static constexpr auto& CK1 = __KeyBits == 128 ? InversePi[0] : (__KeyBits == 192 ? InversePi[1] : InversePi[2]);
        static constexpr auto& CK2 = __KeyBits == 128 ? InversePi[1] : (__KeyBits == 192 ? InversePi[2] : InversePi[0]);
        static constexpr auto& CK3 = __KeyBits == 128 ? InversePi[2] : (__KeyBits == 192 ? InversePi[0] : InversePi[1]);

        using BlockType = Block<uint32_t, 4, 16>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        template<unsigned __N>
        ACCEL_FORCEINLINE
        static uint8_t _U32ExtractNthByte(uint32_t X) ACCEL_NOEXCEPT {
            return static_cast<uint8_t>((X >> ((3 - __N) * 8u)) & 0x000000FFu);
        }

        ACCEL_FORCEINLINE
        static BlockType& _TransformOfP(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock[1] = ((RefBlock[1] & 0x00ff00ffu) << 8u) | ((RefBlock[1] & 0xff00ff00u) >> 8u);
            RefBlock[2] = RotateShiftLeft<uint32_t>(RefBlock[2], 16);
            RefBlock[3] = ByteSwap<uint32_t>(RefBlock[3]);
            return RefBlock;
        }

        ACCEL_FORCEINLINE
        static BlockType& _TransformOfPP(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock[0] = RotateShiftLeft<uint32_t>(RefBlock[0], 16);
            RefBlock[1] = ByteSwap<uint32_t>(RefBlock[1]);
            RefBlock[3] = ((RefBlock[3] & 0x00ff00ffu) << 8u) | ((RefBlock[3] & 0xff00ff00u) >> 8u);
            return RefBlock;
        }

        ACCEL_FORCEINLINE
        static BlockType& _TransformOfM1(BlockType& RefBlock) ACCEL_NOEXCEPT {
            // from weidai11/cryptopp - aria.cpp
            RefBlock[1] ^= RefBlock[2];
            RefBlock[2] ^= RefBlock[3];
            RefBlock[0] ^= RefBlock[1];
            RefBlock[3] ^= RefBlock[1];
            RefBlock[2] ^= RefBlock[0];
            RefBlock[1] ^= RefBlock[2];
            return RefBlock;
        }

        ACCEL_FORCEINLINE
        static BlockType& _TransformOfM(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock[0] =
                _U32ExtractNthByte<0>(RefBlock[0]) * 0x00010101u ^
                _U32ExtractNthByte<1>(RefBlock[0]) * 0x01000101u ^
                _U32ExtractNthByte<2>(RefBlock[0]) * 0x01010001u ^
                _U32ExtractNthByte<3>(RefBlock[0]) * 0x01010100u;
            RefBlock[1] =
                _U32ExtractNthByte<0>(RefBlock[1]) * 0x00010101u ^
                _U32ExtractNthByte<1>(RefBlock[1]) * 0x01000101u ^
                _U32ExtractNthByte<2>(RefBlock[1]) * 0x01010001u ^
                _U32ExtractNthByte<3>(RefBlock[1]) * 0x01010100u;
            RefBlock[2] =
                _U32ExtractNthByte<0>(RefBlock[2]) * 0x00010101u ^
                _U32ExtractNthByte<1>(RefBlock[2]) * 0x01000101u ^
                _U32ExtractNthByte<2>(RefBlock[2]) * 0x01010001u ^
                _U32ExtractNthByte<3>(RefBlock[2]) * 0x01010100u;
            RefBlock[3] =
                _U32ExtractNthByte<0>(RefBlock[3]) * 0x00010101u ^
                _U32ExtractNthByte<1>(RefBlock[3]) * 0x01000101u ^
                _U32ExtractNthByte<2>(RefBlock[3]) * 0x01010001u ^
                _U32ExtractNthByte<3>(RefBlock[3]) * 0x01010100u;
            return RefBlock;
        }

        ACCEL_FORCEINLINE
        static BlockType& _SubLayer1WithTransformOfM(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock[0] =
                SBox1[_U32ExtractNthByte<0>(RefBlock[0])] ^
                SBox2[_U32ExtractNthByte<1>(RefBlock[0])] ^
                InverseSBox1[_U32ExtractNthByte<2>(RefBlock[0])] ^
                InverseSBox2[_U32ExtractNthByte<3>(RefBlock[0])];
            RefBlock[1] =
                SBox1[_U32ExtractNthByte<0>(RefBlock[1])] ^
                SBox2[_U32ExtractNthByte<1>(RefBlock[1])] ^
                InverseSBox1[_U32ExtractNthByte<2>(RefBlock[1])] ^
                InverseSBox2[_U32ExtractNthByte<3>(RefBlock[1])];
            RefBlock[2] =
                SBox1[_U32ExtractNthByte<0>(RefBlock[2])] ^
                SBox2[_U32ExtractNthByte<1>(RefBlock[2])] ^
                InverseSBox1[_U32ExtractNthByte<2>(RefBlock[2])] ^
                InverseSBox2[_U32ExtractNthByte<3>(RefBlock[2])];
            RefBlock[3] =
                SBox1[_U32ExtractNthByte<0>(RefBlock[3])] ^
                SBox2[_U32ExtractNthByte<1>(RefBlock[3])] ^
                InverseSBox1[_U32ExtractNthByte<2>(RefBlock[3])] ^
                InverseSBox2[_U32ExtractNthByte<3>(RefBlock[3])];
            return RefBlock;
        }

        ACCEL_FORCEINLINE
        static BlockType& _SubLayer2WithTransformOfM(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock[0] =
                InverseSBox1[_U32ExtractNthByte<0>(RefBlock[0])] ^
                InverseSBox2[_U32ExtractNthByte<1>(RefBlock[0])] ^
                SBox1[_U32ExtractNthByte<2>(RefBlock[0])] ^
                SBox2[_U32ExtractNthByte<3>(RefBlock[0])];
            RefBlock[1] =
                InverseSBox1[_U32ExtractNthByte<0>(RefBlock[1])] ^
                InverseSBox2[_U32ExtractNthByte<1>(RefBlock[1])] ^
                SBox1[_U32ExtractNthByte<2>(RefBlock[1])] ^
                SBox2[_U32ExtractNthByte<3>(RefBlock[1])];
            RefBlock[2] =
                InverseSBox1[_U32ExtractNthByte<0>(RefBlock[2])] ^
                InverseSBox2[_U32ExtractNthByte<1>(RefBlock[2])] ^
                SBox1[_U32ExtractNthByte<2>(RefBlock[2])] ^
                SBox2[_U32ExtractNthByte<3>(RefBlock[2])];
            RefBlock[3] =
                InverseSBox1[_U32ExtractNthByte<0>(RefBlock[3])] ^
                InverseSBox2[_U32ExtractNthByte<1>(RefBlock[3])] ^
                SBox1[_U32ExtractNthByte<2>(RefBlock[3])] ^
                SBox2[_U32ExtractNthByte<3>(RefBlock[3])];
            return RefBlock;
        }

        template<typename __XorableType>
        ACCEL_FORCEINLINE
        static void _Fo(BlockType& RefBlock, const __XorableType& Key) ACCEL_NOEXCEPT {
            RefBlock ^= Key;

            _TransformOfM1(
                _TransformOfP(
                    _TransformOfM1(
                        _SubLayer1WithTransformOfM(RefBlock)
                    )
                )
            );
        }

        template<typename __XorableType>
        ACCEL_FORCEINLINE
        static void _Fe(BlockType& RefBlock, const __XorableType& Key) ACCEL_NOEXCEPT {
            RefBlock ^= Key;

            _TransformOfM1(
                _TransformOfPP(
                    _TransformOfM1(
                        _SubLayer2WithTransformOfM(RefBlock)
                    )
                )
            );
        }

        ACCEL_FORCEINLINE
        static void _DiffusionLayerA(BlockType& RefBlock) ACCEL_NOEXCEPT {
            _TransformOfM1(_TransformOfP(_TransformOfM1(_TransformOfM(RefBlock))));
        }

        ACCEL_FORCEINLINE
        static void _EncryptDecryptProcess(BlockType& RefBlock, const Array<BlockType, _Nr + 1>& Keys) ACCEL_NOEXCEPT {
            for (int i = 0; i < _Nr - 2; i += 2) {
                _Fo(RefBlock, Keys[i]);
                _Fe(RefBlock, Keys[i + 1]);
            }

            _Fo(RefBlock, Keys[_Nr - 2]);

            RefBlock ^= Keys[_Nr - 1];

            // S-Box layer type 2
            {
                RefBlock[0] =
                    (InverseSBox1[_U32ExtractNthByte<0>(RefBlock[0])] & 0xFF000000u) |
                    (InverseSBox2[_U32ExtractNthByte<1>(RefBlock[0])] & 0x00FF0000u) |
                    (SBox1[_U32ExtractNthByte<2>(RefBlock[0])] & 0x0000FF00u) |
                    (SBox2[_U32ExtractNthByte<3>(RefBlock[0])] & 0x000000FFu);
                RefBlock[1] =
                    (InverseSBox1[_U32ExtractNthByte<0>(RefBlock[1])] & 0xFF000000u) |
                    (InverseSBox2[_U32ExtractNthByte<1>(RefBlock[1])] & 0x00FF0000u) |
                    (SBox1[_U32ExtractNthByte<2>(RefBlock[1])] & 0x0000FF00u) |
                    (SBox2[_U32ExtractNthByte<3>(RefBlock[1])] & 0x000000FFu);
                RefBlock[2] =
                    (InverseSBox1[_U32ExtractNthByte<0>(RefBlock[2])] & 0xFF000000u) |
                    (InverseSBox2[_U32ExtractNthByte<1>(RefBlock[2])] & 0x00FF0000u) |
                    (SBox1[_U32ExtractNthByte<2>(RefBlock[2])] & 0x0000FF00u) |
                    (SBox2[_U32ExtractNthByte<3>(RefBlock[2])] & 0x000000FFu);
                RefBlock[3] =
                    (InverseSBox1[_U32ExtractNthByte<0>(RefBlock[3])] & 0xFF000000u) |
                    (InverseSBox2[_U32ExtractNthByte<1>(RefBlock[3])] & 0x00FF0000u) |
                    (SBox1[_U32ExtractNthByte<2>(RefBlock[3])] & 0x0000FF00u) |
                    (SBox2[_U32ExtractNthByte<3>(RefBlock[3])] & 0x000000FFu);
            }

            RefBlock ^= Keys[_Nr];
        }

        template<unsigned __Shift>
        ACCEL_FORCEINLINE
        static BlockType _BlockRotateShiftLeft(const BlockType& Block) ACCEL_NOEXCEPT {
            static_assert(__Shift < 128);

            if constexpr (__Shift == 0) {
                return Block;
            } else if constexpr (0 < __Shift && __Shift < 32) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[0] << __Shift) | static_cast<uint32_t>(Block[1] >> (32u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[1] << __Shift) | static_cast<uint32_t>(Block[2] >> (32u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[2] << __Shift) | static_cast<uint32_t>(Block[3] >> (32u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[3] << __Shift) | static_cast<uint32_t>(Block[0] >> (32u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 32) {
                BlockType RetVal;
                RetVal[0] = Block[1];
                RetVal[1] = Block[2];
                RetVal[2] = Block[3];
                RetVal[3] = Block[0];
                return RetVal;
            } else if constexpr (32 < __Shift && __Shift < 64) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[1] << (__Shift - 32u)) | static_cast<uint32_t>(Block[2] >> (64u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[2] << (__Shift - 32u)) | static_cast<uint32_t>(Block[3] >> (64u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[3] << (__Shift - 32u)) | static_cast<uint32_t>(Block[0] >> (64u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[0] << (__Shift - 32u)) | static_cast<uint32_t>(Block[1] >> (64u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 64) {
                BlockType RetVal;
                RetVal[0] = Block[2];
                RetVal[1] = Block[3];
                RetVal[2] = Block[0];
                RetVal[3] = Block[1];
                return RetVal;
            } else if constexpr (64 < __Shift && __Shift < 96) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[2] << (__Shift - 64u)) | static_cast<uint32_t>(Block[3] >> (96u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[3] << (__Shift - 64u)) | static_cast<uint32_t>(Block[0] >> (96u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[0] << (__Shift - 64u)) | static_cast<uint32_t>(Block[1] >> (96u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[1] << (__Shift - 64u)) | static_cast<uint32_t>(Block[2] >> (96u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 96) {
                BlockType RetVal;
                RetVal[0] = Block[3];
                RetVal[1] = Block[0];
                RetVal[2] = Block[1];
                RetVal[3] = Block[2];
                return RetVal;
            } else {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[3] << (__Shift - 96u)) | static_cast<uint32_t>(Block[0] >> (128u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[0] << (__Shift - 96u)) | static_cast<uint32_t>(Block[1] >> (128u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[1] << (__Shift - 96u)) | static_cast<uint32_t>(Block[2] >> (128u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[2] << (__Shift - 96u)) | static_cast<uint32_t>(Block[3] >> (128u - __Shift));
                return RetVal;
            }
        }

        template<unsigned __Shift>
        ACCEL_FORCEINLINE
        static BlockType _BlockRotateShiftRight(const BlockType& Block) ACCEL_NOEXCEPT {
            static_assert(__Shift < 128);

            if constexpr (__Shift == 0) {
                return Block;
            } else if constexpr (0 < __Shift && __Shift < 32) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[0] >> __Shift) | static_cast<uint32_t>(Block[3] << (32u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[1] >> __Shift) | static_cast<uint32_t>(Block[0] << (32u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[2] >> __Shift) | static_cast<uint32_t>(Block[1] << (32u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[3] >> __Shift) | static_cast<uint32_t>(Block[2] << (32u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 32) {
                BlockType RetVal;
                RetVal[0] = Block[3];
                RetVal[1] = Block[0];
                RetVal[2] = Block[1];
                RetVal[3] = Block[2];
                return RetVal;
            } else if constexpr (32 < __Shift && __Shift < 64) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[3] >> (__Shift - 32u)) | static_cast<uint32_t>(Block[2] << (64u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[0] >> (__Shift - 32u)) | static_cast<uint32_t>(Block[3] << (64u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[1] >> (__Shift - 32u)) | static_cast<uint32_t>(Block[0] << (64u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[2] >> (__Shift - 32u)) | static_cast<uint32_t>(Block[1] << (64u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 64) {
                BlockType RetVal;
                RetVal[0] = Block[2];
                RetVal[1] = Block[3];
                RetVal[2] = Block[0];
                RetVal[3] = Block[1];
                return RetVal;
            } else if constexpr (64 < __Shift && __Shift < 96) {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[2] >> (__Shift - 64u)) | static_cast<uint32_t>(Block[1] << (96u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[3] >> (__Shift - 64u)) | static_cast<uint32_t>(Block[2] << (96u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[0] >> (__Shift - 64u)) | static_cast<uint32_t>(Block[3] << (96u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[1] >> (__Shift - 64u)) | static_cast<uint32_t>(Block[0] << (96u - __Shift));
                return RetVal;
            } else if constexpr (__Shift == 96) {
                BlockType RetVal;
                RetVal[0] = Block[1];
                RetVal[1] = Block[2];
                RetVal[2] = Block[3];
                RetVal[3] = Block[0];
                return RetVal;
            } else {
                BlockType RetVal;
                RetVal[0] = static_cast<uint32_t>(Block[1] >> (__Shift - 96u)) | static_cast<uint32_t>(Block[0] << (128u - __Shift));
                RetVal[1] = static_cast<uint32_t>(Block[2] >> (__Shift - 96u)) | static_cast<uint32_t>(Block[1] << (128u - __Shift));
                RetVal[2] = static_cast<uint32_t>(Block[3] >> (__Shift - 96u)) | static_cast<uint32_t>(Block[2] << (128u - __Shift));
                RetVal[3] = static_cast<uint32_t>(Block[0] >> (__Shift - 96u)) | static_cast<uint32_t>(Block[3] << (128u - __Shift));
                return RetVal;
            }
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const void* pbUserKey) ACCEL_NOEXCEPT {
            Block<uint32_t, 4, 16> K[2];
            Block<uint32_t, 4, 16> W[4];

            if constexpr (__KeyBits == 128) {
                if constexpr (accel::NativeEndianness == Endianness::BigEndian) {
                    K[0][0] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0);
                    K[0][1] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1);
                    K[0][2] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2);
                    K[0][3] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3);
                } else {
                    K[0][0] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0));
                    K[0][1] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1));
                    K[0][2] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2));
                    K[0][3] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3));
                }
                K[1][0] = 0;
                K[1][1] = 0;
                K[1][2] = 0;
                K[1][3] = 0;
            }

            if constexpr (__KeyBits == 192) {
                if constexpr (accel::NativeEndianness == Endianness::BigEndian) {
                    K[0][0] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0);
                    K[0][1] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1);
                    K[0][2] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2);
                    K[0][3] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3);
                    K[1][0] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 4);
                    K[1][1] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 5);
                } else {
                    K[0][0] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0));
                    K[0][1] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1));
                    K[0][2] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2));
                    K[0][3] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3));
                    K[1][0] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 4));
                    K[1][1] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 5));
                }
                K[1][2] = 0;
                K[1][3] = 0;
            }

            if constexpr (__KeyBits == 256) {
                if constexpr (accel::NativeEndianness == Endianness::BigEndian) {
                    K[0][0] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0);
                    K[0][1] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1);
                    K[0][2] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2);
                    K[0][3] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3);
                    K[1][0] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 4);
                    K[1][1] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 5);
                    K[1][2] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 6);
                    K[1][3] = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 7);
                } else {
                    K[0][0] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0));
                    K[0][1] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1));
                    K[0][2] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2));
                    K[0][3] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3));
                    K[1][0] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 4));
                    K[1][1] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 5));
                    K[1][2] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 6));
                    K[1][3] = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 7));
                }
            }

            // Set W0
            W[0] = K[0];

            // Set W1
            W[1] = W[0];
            _Fo(W[1], CK1);
            W[1] ^= K[1];

            // Set W2
            W[2] = W[1];
            _Fe(W[2], CK2);
            W[2] ^= W[0];

            // Set W3
            W[3] = W[2];
            _Fo(W[3], CK3);
            W[3] ^= W[1];

            _Key[0] = W[0] ^ _BlockRotateShiftRight<19>(W[1]);
            _Key[1] = W[1] ^ _BlockRotateShiftRight<19>(W[2]);
            _Key[2] = W[2] ^ _BlockRotateShiftRight<19>(W[3]);
            _Key[3] = W[3] ^ _BlockRotateShiftRight<19>(W[0]);

            _Key[4] = W[0] ^ _BlockRotateShiftRight<31>(W[1]);
            _Key[5] = W[1] ^ _BlockRotateShiftRight<31>(W[2]);
            _Key[6] = W[2] ^ _BlockRotateShiftRight<31>(W[3]);
            _Key[7] = W[3] ^ _BlockRotateShiftRight<31>(W[0]);

            _Key[8] = W[0] ^ _BlockRotateShiftLeft<61>(W[1]);
            _Key[9] = W[1] ^ _BlockRotateShiftLeft<61>(W[2]);
            _Key[10] = W[2] ^ _BlockRotateShiftLeft<61>(W[3]);
            _Key[11] = W[3] ^ _BlockRotateShiftLeft<61>(W[0]);

            _Key[12] = W[0] ^ _BlockRotateShiftLeft<31>(W[1]);

            if (__KeyBits > 128) {
                _Key[13] = W[1] ^ _BlockRotateShiftLeft<31>(W[2]);
                _Key[14] = W[2] ^ _BlockRotateShiftLeft<31>(W[3]);
            }

            if (__KeyBits > 192) {
                _Key[15] = W[3] ^ _BlockRotateShiftLeft<31>(W[0]);
                _Key[16] = W[0] ^ _BlockRotateShiftLeft<19>(W[1]);
            }

            _InvKey[0] = _Key[_Nr];
            for (size_t i = 1; i < _Nr; ++i) {
                _InvKey[i] = _Key[_Nr - i];
                _DiffusionLayerA(_InvKey[i]);
            }
            _InvKey[_Nr] = _Key[0];

            K[0].SecureZero();
            K[1].SecureZero();
            W[0].SecureZero();
            W[1].SecureZero();
            W[2].SecureZero();
            W[3].SecureZero();
        }

        Array<BlockType, _Nr + 1> _Key;
        Array<BlockType, _Nr + 1> _InvKey;

    public:

        constexpr size_t BlockSize() const ACCEL_NOEXCEPT {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const ACCEL_NOEXCEPT {
            return KeySizeValue;
        };

        ACCEL_NODISCARD
        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (cbUserKey != KeySizeValue) {
                return false;
            } else {
                _KeyExpansion(pbUserKey);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::BigEndian>(pbPlaintext);
            _EncryptDecryptProcess(Text, _Key);
            Text.template StoreTo<Endianness::BigEndian>(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::BigEndian>(pbCiphertext);
            _EncryptDecryptProcess(Text, _InvKey);
            Text.template StoreTo<Endianness::BigEndian>(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }

        ~ARIA_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }
    };

}

