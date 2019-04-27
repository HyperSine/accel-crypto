#pragma once
#include "../Config.hpp"
#include "../Array.hpp"
#include "../Block.hpp"
#include "../Intrinsic.hpp"

#if ACCEL_AESNI_AVAILABLE

namespace accel::CipherTraits {

    template<size_t __KeyBits>
    class AES_AESNI_ALG {
        static_assert(__KeyBits == 128 || __KeyBits == 192 || __KeyBits == 256, 
                      "AES_AESNI_ALG failure! Unsupported __KeyBits.");
    public:
        static constexpr size_t BlockSizeValue = 16;
        static constexpr size_t KeySizeValue = __KeyBits / 8;
    private:
        static constexpr size_t _Nb = 4;
        static constexpr size_t _Nk = __KeyBits / 32;
        static constexpr size_t _Nr = (_Nb > _Nk ? _Nb : _Nk) + 6;

        static constexpr int _Rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        using BlockType = Block<__m128i, 1>; 
        static_assert(sizeof(BlockType) == BlockSizeValue);

        Array<BlockType, _Nr + 1> _Key;
        Array<BlockType, _Nr + 1> _InvKey;

        //
        //  Calculate `_InvKey`, which will be used in decryption, based on `_Key`.
        //  This function is for internal use only.
        //
        ACCEL_FORCEINLINE
        void _InverseKeyExpansion() ACCEL_NOEXCEPT {
            _InvKey[0] = _Key[_Nr];
            for (size_t i = 1; i < _Nr; ++i)
                _InvKey[i] = _mm_aesimc_si128(_Key[_Nr - i]);
            _InvKey[_Nr] = _Key[0];
        }

        //
        //  Key expansion helper for the case when __KeyBits == 128
        //  This function is for internal use only.
        //
        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
        void _KeyExpansion128Loop(__m128i& assist_key, __m128i& buffer) ACCEL_NOEXCEPT {
            if constexpr (__Index == 0) {
                _Key[0] = buffer;
            } else if constexpr (0 < __Index && __Index < 11) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer, __Rcon), _MM_SHUFFLE(3, 3, 3, 3));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                buffer = _mm_xor_si128(buffer, _mm_slli_si128(buffer, 4));
                _Key[__Index] = buffer = _mm_xor_si128(buffer, assist_key);
            } else {
                static_assert(__Index < 11,
                              "_KeyExpansion128Loop failure! Out of range.");
                ACCEL_UNREACHABLE();
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _KeyExpansion128Loops(__m128i& assist_key, __m128i& buffer, std::index_sequence<__Indexes...>) ACCEL_NOEXCEPT {
            (_KeyExpansion128Loop<__Indexes, _Rcon[__Indexes]>(assist_key, buffer), ...);
        }

        //
        //  Key expansion helper for the case when __KeyBits == 192
        //  This function is for internal use only.
        //
        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
        void _KeyExpansion192Loop(__m128i& assist_key, __m128i& buffer_l, __m128i& buffer_h) ACCEL_NOEXCEPT {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _mm_storel_epi64(&_Key[1], buffer_h);
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, __Rcon), _MM_SHUFFLE(1, 1, 1, 1));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _mm_storeu_si128(reinterpret_cast<__m128i*>(_Key.template AsCArrayOf<uint64_t[2 * (_Nr + 1)]>() + (__Index / 2) * 3),
                                 _mm_xor_si128(buffer_l, assist_key));
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < (_Nr / 3) * 4 + 1) {
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h, _mm_shuffle_epi32(buffer_l, _MM_SHUFFLE(3, 3, 3, 3)));
                buffer_l = _mm_xor_si128(buffer_l, assist_key);
                buffer_h = _mm_xor_si128(buffer_h, assist_key);
                _mm_storel_epi64(reinterpret_cast<__m128i*>(_Key.template AsArrayOf<uint64_t[2 * (_Nr + 1)]>() + (__Index / 2) * 3 + 2),
                                 buffer_h);
            } else {
                static_assert(__Index < (_Nr / 3) * 4 + 1,
                              "_KeyExpansion192Loop failure! Out of range.");
                ACCEL_UNREACHABLE();
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _KeyExpansion192Loops(__m128i& assist_key, __m128i& buffer_l, __m128i& buffer_h, std::index_sequence<__Indexes...>) ACCEL_NOEXCEPT {
            (_KeyExpansion192Loop<__Indexes, _Rcon[__Indexes / 2]>(assist_key, buffer_l, buffer_h), ...);
        }

        //
        //  Key expansion helper for the case when __KeyBits == 256
        //  This function is for internal use only.
        //
        template<size_t __Index, int __Rcon>
        ACCEL_FORCEINLINE
        void _KeyExpansion256Loop(__m128i& assist_key, __m128i& buffer_l, __m128i& buffer_h) ACCEL_NOEXCEPT {
            if constexpr (__Index == 0) {
                _Key[0] = buffer_l;
            } else if constexpr (__Index == 1) {
                _Key[1] = buffer_h;
            } else if constexpr (__Index % 2 == 0 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_h, __Rcon), _MM_SHUFFLE(3, 3, 3, 3));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                buffer_l = _mm_xor_si128(buffer_l, _mm_slli_si128(buffer_l, 4));
                _Key[__Index] = buffer_l = _mm_xor_si128(buffer_l, assist_key);
            } else if constexpr (__Index % 2 == 1 && 2 <= __Index && __Index < _Nr + 1) {
                assist_key = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(buffer_l, __Rcon), _MM_SHUFFLE(2, 2, 2, 2));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                buffer_h = _mm_xor_si128(buffer_h, _mm_slli_si128(buffer_h, 4));
                _Key[__Index] = buffer_h = _mm_xor_si128(buffer_h, assist_key);
            } else {
                static_assert(__Index < _Nr + 1,
                              "_KeyExpansion256Loop failure! Out of range.");
                ACCEL_UNREACHABLE();
            }
        }

        template<size_t... __Indexes>
        ACCEL_FORCEINLINE
        void _KeyExpansion256Loops(__m128i& assist_key, __m128i& buffer_l, __m128i& buffer_h, std::index_sequence<__Indexes...>) ACCEL_NOEXCEPT {
            (_KeyExpansion256Loop<__Indexes, _Rcon[__Indexes / 2]>(assist_key, buffer_l, buffer_h), ...);
        }

        ACCEL_FORCEINLINE
        void _KeyExpansion(const void* pbUserKey) ACCEL_NOEXCEPT {
            if constexpr (__KeyBits == 128) {
                __m128i assist_key;
                __m128i buffer;
                buffer = MemoryReadAs<__m128i>(pbUserKey);
                _KeyExpansion128Loops(assist_key, buffer,
                                      std::make_index_sequence<_Nr + 1>{});
            }

            if constexpr (__KeyBits == 192) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = MemoryReadAs<__m128i>(pbUserKey);
                buffer_h = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(pbUserKey) + 1);    // no alignment requirement
                _KeyExpansion192Loops(assist_key, buffer_l, buffer_h,
                                      std::make_index_sequence<(_Nr / 3) * 4 + 1>{});
            }

            if constexpr (__KeyBits == 256) {
                __m128i assist_key;
                __m128i buffer_l;
                __m128i buffer_h;
                buffer_l = MemoryReadAs<__m128i>(pbUserKey, sizeof(__m128i), 0);
                buffer_h = MemoryReadAs<__m128i>(pbUserKey, sizeof(__m128i), 1);
                _KeyExpansion256Loops(assist_key, buffer_l, buffer_h,
                                      std::make_index_sequence<_Nr + 1>{});
            }
        }

        ACCEL_FORCEINLINE
        void _EncryptProcess(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock = _mm_xor_si128(RefBlock, _Key[0]);
            for (size_t i = 1; i < _Nr; ++i)
                RefBlock = _mm_aesenc_si128(RefBlock, _Key[i]);
            RefBlock = _mm_aesenclast_si128(RefBlock, _Key[_Nr]);
        }

        ACCEL_FORCEINLINE
        void _DecryptProcess(BlockType& RefBlock) ACCEL_NOEXCEPT {
            RefBlock = _mm_xor_si128(RefBlock, _InvKey[0]);
            for (size_t i = 1; i < _Nr; ++i)
                RefBlock = _mm_aesdec_si128(RefBlock, _InvKey[i]);
            RefBlock = _mm_aesdeclast_si128(RefBlock, _InvKey[_Nr]);
        }

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
                _KeyExpansion(pbUserKey);
                _InverseKeyExpansion();
                return true;
            }
        }

        size_t EncryptBlock(void* pbPlaintext) ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::LittleEndian>(pbPlaintext);
            _EncryptProcess(Text);
            Text.template StoreTo<Endianness::LittleEndian>(pbPlaintext);

            return BlockSizeValue;
        }

        size_t DecryptBlock(void* pbCiphertext) ACCEL_NOEXCEPT {
            BlockType Text;

            Text.template LoadFrom<Endianness::LittleEndian>(pbCiphertext);
            _DecryptProcess(Text);
            Text.template StoreTo<Endianness::LittleEndian>(pbCiphertext);

            return BlockSizeValue;
        }

        void ClearKey() ACCEL_NOEXCEPT {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }

        ~AES_AESNI_ALG() ACCEL_NOEXCEPT {
            _Key.SecureZero();
            _InvKey.SecureZero();
        }
    };

}

#else
#error "aes_aesni.hpp failure! AES feature is not enabled."
#endif

