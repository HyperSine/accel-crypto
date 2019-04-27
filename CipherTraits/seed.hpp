#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Block.hpp"
#include "../Intrinsic.hpp"
#include "../MemoryAccess.hpp"
#include "Internal/seed_constant.hpp"
#include <utility>

namespace accel::CipherTraits {

    class SEED_ALG : public Internal::SEED_CONSTANT {
    public:
        static constexpr size_t BlockSizeValue = 128 / 8;
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        using BlockType = Block<uint32_t, 4, 16>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        template<unsigned __N>
        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint8_t _U4ExtractNthByte(uint32_t X) ACCEL_NOEXCEPT {
            return static_cast<uint8_t>((X >> (__N * 8u)) & 0xFFu);
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint32_t _FunctionG(uint32_t X) ACCEL_NOEXCEPT {
#if defined(ACCEL_CONFIG_OPTION_SEED_USE_EXTENDED_SBOX)
            return
                SBoxEx[0][static_cast<uint8_t>(X & 0xFFu)] ^
                SBoxEx[1][static_cast<uint8_t>((X >> 8) & 0xFFu)] ^
                SBoxEx[2][static_cast<uint8_t>((X >> 16) & 0xFFu)] ^
                SBoxEx[3][static_cast<uint8_t>((X >> 24) & 0xFFu)];
#else
            return
                ((SBox[0][_U4ExtractNthByte<0>(X)] * 0x01010101u) & 0x3FCFF3FCu) ^
                ((SBox[1][_U4ExtractNthByte<1>(X)] * 0x01010101u) & 0xFC3FCFF3u) ^
                ((SBox[0][_U4ExtractNthByte<2>(X)] * 0x01010101u) & 0xF3FC3FCFu) ^
                ((SBox[1][_U4ExtractNthByte<3>(X)] * 0x01010101u) & 0xCFF3FC3Fu);
#endif
        }

        ACCEL_FORCEINLINE
        void _FunctionF(uint32_t C, uint32_t D, uint32_t& OutC, uint32_t& OutD, int Round) const ACCEL_NOEXCEPT {
            uint32_t t;

            C ^= _Key[Round][0];
            D ^= _Key[Round][1];

            D ^= C;

            t = _FunctionG(D);
            C = _FunctionG(C + t);
            D = _FunctionG(C + t);
            C += D;

            OutC = C;
            OutD = D;
        }

        void _KeySchedule(const void* pbUserKey) ACCEL_NOEXCEPT {
            uint32_t A, B, C, D;

            if constexpr (accel::NativeEndianness == Endianness::BigEndian) {
                A = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0);
                B = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1);
                C = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2);
                D = MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3);
            } else {
                A = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 0));
                B = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 1));
                C = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 2));
                D = ByteSwap<uint32_t>(MemoryReadAs<uint32_t>(pbUserKey, sizeof(uint32_t), 3));
            }

            for (size_t i = 0; i < 16; ++i) {
                _Key[i][0] = _FunctionG(A + C - KC[i]);
                _Key[i][1] = _FunctionG(B - D + KC[i]);
                if (i % 2 == 0) {
                    uint64_t t = (static_cast<uint64_t>(A) << 32u) | static_cast<uint64_t>(B);
                    t = RotateShiftRight<uint64_t>(t, 8);
                    A = static_cast<uint32_t>((t >> 32u) & 0xFFFFFFFFu);
                    B = static_cast<uint32_t>(t & 0xFFFFFFFFu);
                } else {
                    uint64_t t = (static_cast<uint64_t>(C) << 32u) | static_cast<uint64_t>(D);
                    t = RotateShiftLeft<uint64_t>(t, 8);
                    C = static_cast<uint32_t>((t >> 32u) & 0xFFFFFFFFu);
                    D = static_cast<uint32_t>(t & 0xFFFFFFFFu);
                }
            }

            static_cast<volatile uint32_t&>(A) = 0;
            static_cast<volatile uint32_t&>(B) = 0;
            static_cast<volatile uint32_t&>(C) = 0;
            static_cast<volatile uint32_t&>(D) = 0;
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            for (int i = 0; i < 16; i += 2) {
                uint32_t t0, t1;

                _FunctionF(RefBlock[2], RefBlock[3], t0, t1, i);
                RefBlock[0] ^= t0;
                RefBlock[1] ^= t1;

                _FunctionF(RefBlock[0], RefBlock[1], t0, t1, i + 1);
                RefBlock[2] ^= t0;
                RefBlock[3] ^= t1;
            }

            std::swap(RefBlock[0], RefBlock[2]);
            std::swap(RefBlock[1], RefBlock[3]);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) const ACCEL_NOEXCEPT {
            for (int i = 14; i >= 0; i -= 2) {
                uint32_t t0, t1;

                _FunctionF(RefBlock[2], RefBlock[3], t0, t1, i + 1);
                RefBlock[0] ^= t0;
                RefBlock[1] ^= t1;

                _FunctionF(RefBlock[0], RefBlock[1], t0, t1, i);
                RefBlock[2] ^= t0;
                RefBlock[3] ^= t1;
            }

            std::swap(RefBlock[0], RefBlock[2]);
            std::swap(RefBlock[1], RefBlock[3]);
        }

        Array<Block<uint32_t, 2, 8>, 16> _Key;

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
                _KeySchedule(pbUserKey);
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::BigEndian>(pbPlaintext);
            _EncryptProcess(Text);
            Text.template StoreTo<Endianness::BigEndian>(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::BigEndian>(pbCiphertext);
            _DecryptProcess(Text);
            Text.template StoreTo<Endianness::BigEndian>(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~SEED_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

