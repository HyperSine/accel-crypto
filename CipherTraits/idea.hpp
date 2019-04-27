#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"
#include <utility>

namespace accel::CipherTraits {

    class IDEA_ALG {
    public:
        static constexpr size_t BlockSizeValue = 64 / 8;
        static constexpr size_t KeySizeValue = 128 / 8;
    private:

        using BlockType = Array<uint16_t, 4>;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        ACCEL_FORCEINLINE
        static int _GcdEx(int a, int b, int& out_x, int& out_y) ACCEL_NOEXCEPT {
            int prevx = 1, x = 0, prevy = 0, y = 1;
            while (b) {
                int q, t;

                q = a / b;

                t = x;
                x = prevx - q * x;
                prevx = t;

                t = y;
                y = prevy - q * y;
                prevy = t;

                t = a;
                a = b;
                b = t % b;
            }

            out_x = prevx;
            out_y = prevy;
            return a;
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint16_t _InverseMod65537(uint16_t Val) ACCEL_NOEXCEPT {
            if (Val <= 1) {
                // for x = 0, return 1 / 0x10000 (mod 0x10001) = 0x10000 -> 0
                // for x = 1, return 1 / 0x00001 (mod 0x10001) = 0x00001 -> 1
                return Val;
            } else {
                int x, y;
                _GcdEx(0x10001, Val, x, y);
                return y < 0 ? y + 0x10001 : y;
            }
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint16_t _OperationXor(uint16_t a, uint16_t b) ACCEL_NOEXCEPT {
            return a ^ b;
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint16_t _OperationAdd(uint16_t a, uint16_t b) ACCEL_NOEXCEPT {
            return a + b;
        }

        ACCEL_NODISCARD
        ACCEL_FORCEINLINE
        static uint16_t _OperationMul(uint16_t a, uint16_t b) ACCEL_NOEXCEPT {
            uint32_t v = a * b;
            if (v) {
                return static_cast<uint16_t>(v % 0x10001u);
            } else {
                /*  Proved by the following python3 code

for i in range(65536):
    a = (((i if i != 0 else 0x10000) * 0x10000) % 0x10001) & 0xffff
    b = (1 - 0 - i) & 0xffff
    assert(a == b)  # no AssertionError fired

                 */
                return static_cast<uint16_t>(1 - a - b);
            }
        }

        ACCEL_FORCEINLINE
        void _KeySchedule(const uint16_t* p2bUserKey) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 8; ++i) {
                _Key[i] = ByteSwap<uint16_t>(p2bUserKey[i]);
            }

            //
            // Set _Key
            //
            for (size_t i = 8; i < 52; ++i) {
                _Key[i] = static_cast<uint16_t>(
                    (_Key[i % 8 < 7 ? i - 7 : i - 15] << (25u - 16u)) | 
                    (_Key[i % 8 < 6 ? i - 6 : i - 14] >> (16u - (25u - 16u)))
                );
            }

            //
            // Set _InvKey
            //

            _InvKey[0] = _InverseMod65537(_Key[48]);
            _InvKey[1] = -_Key[49];
            _InvKey[2] = -_Key[50];
            _InvKey[3] = _InverseMod65537(_Key[51]);

            for (size_t i = 4; i < 52 - 6; i += 6) {
                _InvKey[i] = _Key[50 - i];
                _InvKey[i + 1] = _Key[51 - i];
                _InvKey[i + 2] = _InverseMod65537(_Key[46 - i]);
                _InvKey[i + 3] = -_Key[48 - i];
                _InvKey[i + 4] = -_Key[47 - i];
                _InvKey[i + 5] = _InverseMod65537(_Key[49 - i]);
            }

            _InvKey[46] = _Key[4];
            _InvKey[47] = _Key[5];
            _InvKey[48] = _InverseMod65537(_Key[0]);
            _InvKey[49] = -_Key[1];
            _InvKey[50] = -_Key[2];
            _InvKey[51] = _InverseMod65537(_Key[3]);
        }

        ACCEL_FORCEINLINE
        static void _EncryptDecryptProcess(BlockType& RefBlock, const Array<uint16_t, 52>& Key) ACCEL_NOEXCEPT {
            uint16_t a, b, c, d, t0, t1, t2;

            a = RefBlock[0];
            b = RefBlock[1];
            c = RefBlock[2];
            d = RefBlock[3];

            for (size_t i = 0; i < 48; i += 6) {
                a = _OperationMul(a, Key[i]);
                b = _OperationAdd(b, Key[i + 1]);
                c = _OperationAdd(c, Key[i + 2]);
                d = _OperationMul(d, Key[i + 3]);

                t0 = _OperationMul(_OperationXor(a, c), Key[i + 4]);
                t1 = _OperationMul(_OperationAdd(_OperationXor(b, d), t0), Key[i + 5]);
                t2 = _OperationAdd(t0, t1);

                a = _OperationXor(a, t1);
                c = _OperationXor(c, t1);
                b = _OperationXor(b, t2);
                d = _OperationXor(d, t2);

                std::swap(b, c);
            }

            RefBlock[0] = _OperationMul(a, Key[48]);
            RefBlock[1] = _OperationAdd(c, Key[49]);
            RefBlock[2] = _OperationAdd(b, Key[50]);
            RefBlock[3] = _OperationMul(d, Key[51]);
        }

        Array<uint16_t, 52> _Key;
        Array<uint16_t, 52> _InvKey;

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
                _KeySchedule(reinterpret_cast<const uint16_t*>(pbUserKey));
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[0]);
            Text[1] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[1]);
            Text[2] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[2]);
            Text[3] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbPlaintext)[3]);

            _EncryptDecryptProcess(Text, _Key);

            reinterpret_cast<uint16_t*>(pbPlaintext)[0] = ByteSwap<uint16_t>(Text[0]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[1] = ByteSwap<uint16_t>(Text[1]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[2] = ByteSwap<uint16_t>(Text[2]);
            reinterpret_cast<uint16_t*>(pbPlaintext)[3] = ByteSwap<uint16_t>(Text[3]);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) const ACCEL_NOEXCEPT {
            BlockType Text;

            Text[0] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[0]);
            Text[1] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[1]);
            Text[2] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[2]);
            Text[3] = ByteSwap<uint16_t>(reinterpret_cast<uint16_t*>(pbCiphertext)[3]);

            _EncryptDecryptProcess(Text, _InvKey);

            reinterpret_cast<uint16_t*>(pbCiphertext)[0] = ByteSwap<uint16_t>(Text[0]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[1] = ByteSwap<uint16_t>(Text[1]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[2] = ByteSwap<uint16_t>(Text[2]);
            reinterpret_cast<uint16_t*>(pbCiphertext)[3] = ByteSwap<uint16_t>(Text[3]);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }

        ~IDEA_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
        }
    };

}

