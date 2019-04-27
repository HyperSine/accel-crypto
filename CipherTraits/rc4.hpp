#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include <utility>

namespace accel::Crypto {

    class RC4_ALG {
    public:
        static constexpr size_t MinKeySizeValue = 1;
        static constexpr size_t MaxKeySizeValue = 256;
    private:

        Array<uint8_t, 256> _InitSBox;
        mutable Array<uint8_t, 256> _SBox;
        mutable uint8_t _X;
        mutable uint8_t _Y;

        ACCEL_FORCEINLINE
        void _SetInitSBox(const uint8_t* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 256; ++i)
                _InitSBox[i] = pbUserKey[i % cbUserKey];
        }

        ACCEL_FORCEINLINE
        void _SetSBox() ACCEL_NOEXCEPT {
            for (size_t i = 0; i < 256; ++i)
                _SBox[i] = static_cast<uint8_t>(i);

            uint8_t j = 0;
            for (size_t i = 0; i < 256; ++i) {
                j += _InitSBox[i] + _SBox[i];
                std::swap(_SBox[i], _SBox[j]);
            }


        }

        ACCEL_FORCEINLINE
        void _EncryptDecryptProcess(uint8_t* pbText, size_t cbText) const ACCEL_NOEXCEPT {
            uint8_t i = _X, j = _Y;
            for (size_t k = 0; k < cbText; ++k) {
                i += 1;
                j += _SBox[i];
                pbText[k] ^= _SBox[(_SBox[i] + _SBox[j]) % _SBox.Length()];
                std::swap(_SBox[i], _SBox[j]);
            }
            _X = i;
            _Y = j;
        }

    public:

        constexpr size_t MinKeySize() const ACCEL_NOEXCEPT {
            return MinKeySizeValue;
        }

        constexpr size_t MaxKeySize() const ACCEL_NOEXCEPT {
            return MaxKeySizeValue;
        }

        ACCEL_NODISCARD
        bool SetKey(const void* pbUserKey, size_t cbUserKey) ACCEL_NOEXCEPT {
            if (MinKeySizeValue <= cbUserKey && cbUserKey <= MaxKeySizeValue) {
                _SetInitSBox(reinterpret_cast<const uint8_t*>(pbUserKey), cbUserKey);
                _SetSBox();
                _X = 0;
                _Y = 0;
                return true;
            } else {
                return false;
            }
        }

        size_t EncryptStream(void* pbPlaintext, size_t cbPlaintext) const ACCEL_NOEXCEPT {
            _EncryptDecryptProcess(reinterpret_cast<uint8_t*>(pbPlaintext), cbPlaintext);
            return cbPlaintext;
        }

        size_t DecryptStream(void* pbCiphertext, size_t cbCiphertext) const ACCEL_NOEXCEPT {
            _EncryptDecryptProcess(reinterpret_cast<uint8_t*>(pbCiphertext), cbCiphertext);
            return cbCiphertext;
        }

        void Reset() ACCEL_NOEXCEPT {
            _SetSBox();
            _X = 0;
            _Y = 0;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _InitSBox.SecureZero();
            _SBox.SecureZero();
            _X = 0;
            _Y = 0;
        }

        ~RC4_ALG() ACCEL_NOEXCEPT {
            _InitSBox.SecureZero();
            _SBox.SecureZero();
            _X = 0;
            _Y = 0;
        }
    };

}

