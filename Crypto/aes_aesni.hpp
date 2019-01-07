#pragma once
#include "../Common/Array.hpp"
#include "../Common/Intrinsic.hpp"

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
        static constexpr size_t BlockSizeValue = 128;
        static constexpr size_t KeySizeValue = __key_bits / 8;
    private:
        static constexpr size_t _Nb = 4;
        static constexpr size_t _Nk = __key_bits / 32;
        static constexpr size_t _Nr = (_Nb > _Nk ? _Nb : _Nk) + 6;

        static constexpr int _Rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        using BlockType = __m128i;
        using RoundKeyType = __m128i;
        
        SecureArray<RoundKeyType, _Nr + 1> _Key;
        SecureArray<RoundKeyType, _Nr + 1> _InvKey;

        //
        //  InverseKeyExpansion stuff
        //

        template<size_t __Index>
        __forceinline
        void _InverseKeyExpansionLoop() noexcept {
            if constexpr (__Index == 0) {
                _mm_storeu_si128(&_InvKey[0], _Key[_Nr]);
            } else if constexpr (__Index == _Nr) {
                _mm_storeu_si128(&_InvKey[_Nr], _Key[0]);
            } else if constexpr (0 < __Index && __Index < _Nr) {
                _mm_storeu_si128(&_InvKey[__Index],
                                 _mm_aesimc_si128(_Key[_Nr - __Index]));
            } else {
                static_assert(__Index < _Nr + 1, 
                              "_InverseKeyExpansionLoop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        __forceinline
        void _InverseKeyExpansionLoops(std::index_sequence<__Indexes...>) noexcept {
            (_InverseKeyExpansionLoop<__Indexes>(), ...);
        }

        void _InverseKeyExpansion() noexcept {
            _InverseKeyExpansionLoops(std::make_index_sequence<_Nr + 1>{});
        }

        //
        //  KeyExpansion stuff
        //

        template<size_t __Index>
        __forceinline
        void _KeyExpansion128Loop(__m128i& assist_key, __m128i& buffer) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer;
            } else if constexpr (0 < __Index && __Index < 11) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer, _Rcon[__Index]),
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
        __forceinline
        void _KeyExpansion128Loops(__m128i& assist_key, 
                                   __m128i& buffer, 
                                   std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion128Loop<__Indexes>(assist_key, buffer), ...);
        }

        template<size_t __Index>
        __forceinline
        void _KeyExpansion192Loop(__m128i& assist_key,
                                  __m128i& buffer_l,
                                  __m128i& buffer_h) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _mm_storel_epi64(&_Key[1], buffer_h);
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, 
                                                                         _Rcon[__Index / 2]), 
                                               _MM_SHUFFLE(1, 1, 1, 1));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _mm_storeu_si128(
                    reinterpret_cast<__m128i*>(_Key.template AsArrayOf<uint64_t, 2 * (_Nr + 1)>().GetPtr() + (__Index / 2) * 3),
                    _mm_xor_si128(buffer_l, assist_key));
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h,
                                         _mm_shuffle_epi32(buffer_l, 
                                                           _MM_SHUFFLE(3, 3, 3, 3)));
                buffer_l = _mm_xor_si128(buffer_l, assist_key);
                buffer_h = _mm_xor_si128(buffer_h, assist_key);
                _mm_storel_epi64(
                    reinterpret_cast<__m128i*>(_Key.template AsArrayOf<uint64_t, 2 * (_Nr + 1)>().GetPtr() + (__Index / 2) * 3 + 2),
                    buffer_h);
            } else {
                static_assert(__Index < (_Nr / 3) * 4 + 1,
                              "_KeyExpansion192Loop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        void _KeyExpansion192Loops(__m128i& assist_key,
                                   __m128i& buffer_l,
                                   __m128i& buffer_h,
                                   std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion192Loop<__Indexes>(assist_key, buffer_l, buffer_h), ...);
        }

        template<size_t __Index>
        __forceinline
        void _KeyExpansion256Loop(__m128i& assist_key, 
                                  __m128i& buffer_l, 
                                  __m128i& buffer_h) noexcept {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _Key[1] = buffer_h;
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, 
                                                                         _Rcon[__Index / 2]), 
                                               _MM_SHUFFLE(3, 3, 3, 3));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _Key[__Index] = buffer_l = _mm_xor_si128(buffer_l, assist_key);
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_l,
                                                                         _Rcon[__Index / 2]),
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
        __forceinline
        void _KeyExpansion256Loops(__m128i& assist_key,
                                   __m128i& buffer_l,
                                   __m128i& buffer_h,
                                   std::index_sequence<__Indexes...>) noexcept {
            (_KeyExpansion256Loop<__Indexes>(assist_key, buffer_l, buffer_h), ...);
        }

        void _KeyExpansion(const void* pUserKey) noexcept {
            if constexpr (__key_bits == 128) {
                __m128i assist_key;
                __m128i buffer;
                buffer = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
                _KeyExpansion128Loops(assist_key, 
                                      buffer, 
                                      std::make_index_sequence<_Nr + 1>{});
            }
            
            if constexpr (__key_bits == 192) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
                buffer_h = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(pUserKey) + 1);
                _KeyExpansion192Loops(assist_key, 
                                      buffer_l, 
                                      buffer_h, 
                                      std::make_index_sequence<(_Nr / 3) * 4 + 1>{});
            } 
            
            if constexpr (__key_bits == 256) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey));
                buffer_h = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pUserKey) + 1);
                _KeyExpansion256Loops(assist_key, 
                                      buffer_l, 
                                      buffer_h, 
                                      std::make_index_sequence<_Nr + 1>{});
            }
        }

        template<size_t __Index>
        __forceinline
        void _EncryptLoop(BlockType& RefText) noexcept {
            if constexpr (__Index == 0) {
                RefText = _mm_xor_si128(RefText, _Key[0]);
            } else if constexpr (__Index == _Nr) {
                RefText = _mm_aesenclast_si128(RefText, _Key[_Nr]);
            } else if constexpr (0 < __Index && __Index < _Nr) {
                RefText = _mm_aesenc_si128(RefText, _Key[__Index]);
            } else {
                static_assert(__Index < _Nr + 1,
                              "_EncryptLoop failure! Out of range.");
            }
        }

        template<size_t __Index>
        __forceinline
            void _DecryptLoop(BlockType& RefText) noexcept {
            if constexpr (__Index == 0) {
                RefText = _mm_xor_si128(RefText, _InvKey[0]);
            } else if constexpr (__Index == _Nr) {
                RefText = _mm_aesdeclast_si128(RefText, _InvKey[_Nr]);
            } else if constexpr (0 < __Index && __Index < _Nr) {
                RefText = _mm_aesdec_si128(RefText, _InvKey[__Index]);
            } else {
                static_assert(__Index < _Nr + 1,
                              "_DecryptLoop failure! Out of range.");
            }
        }

        template<size_t... __Indexes>
        __forceinline
        void _EncryptLoops(BlockType& RefText, std::index_sequence<__Indexes...>) noexcept {
            (_EncryptLoop<__Indexes>(RefText), ...);
        }

        template<size_t... __Indexes>
        __forceinline
        void _DecryptLoops(BlockType& RefText, std::index_sequence<__Indexes...>) noexcept {
            (_DecryptLoop<__Indexes>(RefText), ...);
        }

    public:

        constexpr size_t BlockSize() const noexcept {
            return BlockSizeValue;
        }

        constexpr size_t KeySize() const noexcept {
            return KeySizeValue;
        }

        [[nodiscard]]
        bool SetKey(const void* pUserKey, size_t UserKeySize) noexcept {
            if (UserKeySize != KeySizeValue)
                return false;
            _KeyExpansion(pUserKey);
            _InverseKeyExpansion();
            return true;
        }

        size_t EncryptBlock(void* pPlaintext) noexcept {
            BlockType Text;
            Text = _mm_loadu_si128(reinterpret_cast<BlockType*>(pPlaintext));
            _EncryptLoops(Text, std::make_index_sequence<_Nr + 1>{});
            _mm_storeu_si128(reinterpret_cast<BlockType*>(pPlaintext), Text);
            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pCiphertext) noexcept {
            BlockType Text;
            Text = _mm_loadu_si128(reinterpret_cast<BlockType*>(pCiphertext));
            _DecryptLoops(Text, std::make_index_sequence<_Nr + 1>{});
            _mm_storeu_si128(reinterpret_cast<BlockType*>(pCiphertext), Text);
            return BlockSizeValue;
        }

        void ClearKey() noexcept {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }
    };

}

#else
#error "Architecture feature not specified."
#endif