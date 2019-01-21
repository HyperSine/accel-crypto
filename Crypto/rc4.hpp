#pragma once
#include "../Common/Config.hpp"
#include "../Common/Array.hpp"

namespace accel::Crypto {

    class RC4_ALG {
    public:
        static constexpr size_t MinKeySizeValue = 1;
        static constexpr size_t MaxKeySizeValue = 256;
    private:

        SecureArray<uint8_t, 256> _InitSBox;
        mutable SecureArray<uint8_t, 256> _SBox;

        ACCEL_FORCEINLINE
        void _KeyExpansion() noexcept {
            for (size_t i = 0; i < 256; ++i)
                _SBox[i] = static_cast<uint8_t>(i);

            uint8_t j = 0;
            for (size_t i = 0; i < 256; ++i) {
                j += _InitSBox[i] + _SBox[i];
                std::swap(_SBox[i], _SBox[j]);
            }
        }

        ACCEL_FORCEINLINE
        void _EncDecProcess(uint8_t* PtrToText, size_t TextSize) const noexcept {
            uint8_t i = 0, j = 0;
            for (size_t k = 0; k < TextSize; ++k) {
                i += 1;
                j += _SBox[i];
                uint8_t temp = _SBox[i];
                _SBox[i] = _SBox[j];
                _SBox[j] = temp;
                PtrToText[k] ^= _SBox[(_SBox[i] + _SBox[j]) % 256];
            }
        }

    public:

        constexpr size_t MinKeySize() const noexcept {
            return MinKeySizeValue;
        }

        constexpr size_t MaxKeySize() const noexcept {
            return MaxKeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* PtrToUserKey, size_t UserKeySize) noexcept {
            if (MinKeySizeValue <= UserKeySize && UserKeySize <= MaxKeySizeValue) {
                auto BytesOfUserKey = reinterpret_cast<const uint8_t*>(PtrToUserKey);

                for (size_t i = 0; i < 256; ++i)
                    _InitSBox[i] = BytesOfUserKey[i % UserKeySize];

                _KeyExpansion();

                return true;
            } else {
                return false;
            }
        }

        size_t EncryptStream(void* PtrToPlaintext, size_t TextSize) const noexcept {
            _EncDecProcess(reinterpret_cast<uint8_t*>(PtrToPlaintext), TextSize);
            return TextSize;
        }

        size_t DecryptStream(void* PtrToCiphertext, size_t TextSize) const noexcept {
            _EncDecProcess(reinterpret_cast<uint8_t*>(PtrToCiphertext), TextSize);
            return TextSize;
        }

        void Reset() noexcept {
            _KeyExpansion();
        }

        void ClearKey() noexcept {
            _InitSBox.SecureZero();
            _SBox.SecureZero();
        }

    };

}

