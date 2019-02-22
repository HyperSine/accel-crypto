#pragma once
#include "../Config.hpp"
#include "../SecureWiper.hpp"
#include "../Array.hpp"
#include "../Intrinsic.hpp"

// Detect if AESNI feature is enabled.
// For MSVC detect if SSE2 is enabled only.
#if defined(__GNUC__) && defined(__AES__) || defined(_MSC_VER) && (_M_IX86_FP >= 2 || _M_AMD64)

namespace accel::Crypto {

    template<size_t __key_bits>
    class AES_AESNI_ALG {
        static_assert(__key_bits == 128 ||
                      __key_bits == 192 ||
                      __key_bits == 256, "AES_AESNI_ALG failure! Unsupported __key_bits.");
    public:
        static constexpr size_t BlockSizeValue = 16;
        static constexpr size_t KeySizeValue = __key_bits / 8;
    private:
        static constexpr size_t _Nb = 4;
        static constexpr size_t _Nk = __key_bits / 32;
        static constexpr size_t _Nr = (_Nb > _Nk ? _Nb : _Nk) + 6;

        static constexpr int _Rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        using BlockType = __m128i;
        static_assert(sizeof(BlockType) == BlockSizeValue);

        SecureWiper<Array<__m128i, _Nr + 1>> _KeyWiper;
        SecureWiper<Array<__m128i, _Nr + 1>> _InvKeyWiper;
        Array<__m128i, _Nr + 1> _Key;
        Array<__m128i, _Nr + 1> _InvKey;

        //
        //  Calculate `_InvKey`, which will be used in decryption, based on `_Key`.
        //  This function is for internal use only.
        //
        ACCEL_FORCEINLINE
            void _InverseKeyExpansion() noexcept {
            _InvKey[0] = _Key[_Nr];
            for (size_t i = 1; i < _Nr; ++i)
                _InvKey[i] = _mm_aesimc_si128(_Key[_Nr - i]);
            _InvKey[_Nr] = _Key[0];
        }

        //
        //  Key expansion helper
        //
        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
            void _KeyExpansion128Loop(__m128i& assist_key, __m128i& buffer) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer;
            } else if constexpr (0 < __Index && __Index < 11) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer, __Rcon),
                                               _MM_SHUFFLE(3, 3, 3, 3));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                _Key[__Index] = buffer = _mm_xor_si128(buffer, assist_key);
            } else {
                static_assert(__Index < 11,
                              "_KeyExpansion128Loop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
            void _KeyExpansion128Loops(__m128i& assist_key,
                                       __m128i& buffer,
                                       std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion128Loop<__Indexes, _Rcon[__Indexes]>(assist_key, buffer), ...);
        }

        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
            void _KeyExpansion192Loop(__m128i& assist_key,
                                      __m128i& buffer_l,
                                      __m128i& buffer_h) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _mm_storel_epi64(&_Key[1], buffer_h);
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, __Rcon),
                                               _MM_SHUFFLE(1, 1, 1, 1));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _mm_storeu_si128(
                    reinterpret_cast<__m128i*>(_Key.template AsArrayOf<uint64_t, 2 * (_Nr + 1)>().CArray() + (__Index / 2) * 3),
                    _mm_xor_si128(buffer_l, assist_key));
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h,
                                         _mm_shuffle_epi32(buffer_l,
                                                           _MM_SHUFFLE(3, 3, 3, 3)));
                buffer_l = _mm_xor_si128(buffer_l, assist_key);
                buffer_h = _mm_xor_si128(buffer_h, assist_key);
                _mm_storel_epi64(
                    reinterpret_cast<__m128i*>(_Key.template AsArrayOf<uint64_t, 2 * (_Nr + 1)>().CArray() + (__Index / 2) * 3 + 2),
                    buffer_h);
            } else {
                static_assert(__Index < (_Nr / 3) * 4 + 1,
                              "_KeyExpansion192Loop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
            void _KeyExpansion192Loops(__m128i& assist_key,
                                       __m128i& buffer_l,
                                       __m128i& buffer_h,
                                       std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion192Loop<__Indexes, _Rcon[__Indexes / 2]>(assist_key, buffer_l, buffer_h), ...);
        }

        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
            void _KeyExpansion256Loop(__m128i& assist_key,
                                      __m128i& buffer_l,
                                      __m128i& buffer_h) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _Key[1] = buffer_h;
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, __Rcon),
                                               _MM_SHUFFLE(3, 3, 3, 3));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _Key[__Index] = buffer_l = _mm_xor_si128(buffer_l, assist_key);
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_l, __Rcon),
                                               _MM_SHUFFLE(2, 2, 2, 2));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                _Key[__Index] = buffer_h = _mm_xor_si128(buffer_h, assist_key);
            } else {
                static_assert(__Index < _Nr + 1,
                              "_KeyExpansion256Loop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
            void _KeyExpansion256Loops(__m128i& assist_key,
                                       __m128i& buffer_l,
                                       __m128i& buffer_h,
                                       std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion256Loop<__Indexes, _Rcon[__Indexes / 2]>(assist_key, buffer_l, buffer_h), ...);
        }

        ACCEL_FORCEINLINE
            void _KeyExpansion(const __m128i* PtrToUserKey) noexcept {
            if constexpr (__key_bits == 128) {
                __m128i assist_key;
                __m128i buffer;
                buffer = _mm_loadu_si128(PtrToUserKey);
                _KeyExpansion128Loops(assist_key,
                                      buffer,
                                      std::make_index_sequence<_Nr + 1>{});
            }

            if constexpr (__key_bits == 192) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = _mm_loadu_si128(PtrToUserKey);
                buffer_h = _mm_loadl_epi64(PtrToUserKey + 1);
                _KeyExpansion192Loops(assist_key,
                                      buffer_l,
                                      buffer_h,
                                      std::make_index_sequence<(_Nr / 3) * 4 + 1>{});
            }

            if constexpr (__key_bits == 256) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = _mm_loadu_si128(PtrToUserKey);
                buffer_h = _mm_loadu_si128(PtrToUserKey + 1);
                _KeyExpansion256Loops(assist_key,
                                      buffer_l,
                                      buffer_h,
                                      std::make_index_sequence<_Nr + 1>{});
            }
        }

        ACCEL_FORCEINLINE
            void _EncryptProcess(BlockType& RefBlock) noexcept {
            RefBlock = _mm_xor_si128(RefBlock, _Key[0]);
            for (size_t i = 1; i < _Nr; ++i)
                RefBlock = _mm_aesenc_si128(RefBlock, _Key[i]);
            RefBlock = _mm_aesenclast_si128(RefBlock, _Key[_Nr]);
        }

        ACCEL_FORCEINLINE
            void _DecryptProcess(BlockType& RefBlock) noexcept {
            RefBlock = _mm_xor_si128(RefBlock, _InvKey[0]);
            for (size_t i = 1; i < _Nr; ++i)
                RefBlock = _mm_aesdec_si128(RefBlock, _InvKey[i]);
            RefBlock = _mm_aesdeclast_si128(RefBlock, _InvKey[_Nr]);
        }

    public:

        AES_AESNI_ALG() noexcept :
            _KeyWiper(_Key),
            _InvKeyWiper(_InvKey) {}

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const noexcept {
            return KeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* PtrToUserKey, size_t UserKeySize) noexcept {
            if (UserKeySize != KeySizeValue)
                return false;

            _KeyExpansion(reinterpret_cast<const __m128i*>(PtrToUserKey));
            _InverseKeyExpansion();

            return true;
        }

        size_t EncryptBlock(void* PtrToPlaintext) noexcept {
            BlockType Text = _mm_loadu_si128(reinterpret_cast<BlockType*>(PtrToPlaintext));
            _EncryptProcess(Text);
            _mm_storeu_si128(reinterpret_cast<BlockType*>(PtrToPlaintext), Text);
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* PtrToCiphertext) noexcept {
            BlockType Text = _mm_loadu_si128(reinterpret_cast<BlockType*>(PtrToCiphertext));
            _DecryptProcess(Text);
            _mm_storeu_si128(reinterpret_cast<BlockType*>(PtrToCiphertext), Text);
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }
    };

}

#else
#error "aes_aesni.hpp failure! AES feature is not enabled."
#endif

