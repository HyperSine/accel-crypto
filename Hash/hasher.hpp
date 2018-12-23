#pragma once
#include <stdint.h>
#include "../Common/Array.hpp"
#include <memory.h>

namespace accel::Hash {

    template<typename __AlgType>
    class Hasher {
    private:
        __AlgType _AlgInstance;
        uint64_t _ProcessedBytes;
        SecureByteArray<__AlgType::BlockSize> _StreamBuffer;
        size_t _StreamLength;
    public:
        static constexpr size_t BlockSize = __AlgType::BlockSize;
        static constexpr size_t DigestSize = __AlgType::DigestSize;

        Hasher() noexcept : _ProcessedBytes(0), _StreamLength(0) {}

        void Update(const void* pData, size_t DataSize) noexcept {
            if (DataSize + _StreamLength < BlockSize) {
                memcpy(_StreamBuffer.AsArray().GetPtr() + _StreamLength, pData, DataSize);
                _StreamLength += DataSize;
                _ProcessedBytes += DataSize;
            } else {
                auto pBytes = reinterpret_cast<const uint8_t*>(pData);
                size_t DataReadPtr = 0;

                {
                    size_t BytesToCopy = BlockSize - _StreamLength;
                    memcpy(_StreamBuffer.AsArray().GetPtr() + _StreamLength, pBytes, BytesToCopy);
                    _AlgInstance.Cycle(_StreamBuffer.AsArray().GetPtr(), 1);
                    _StreamLength = 0;
                    DataReadPtr += BytesToCopy;
                    DataSize -= BytesToCopy;
                }

                {
                    size_t Rounds = DataSize / BlockSize;
                    if (Rounds) {
                        _AlgInstance.Cycle(pBytes + DataReadPtr, Rounds);
                        DataReadPtr += Rounds * BlockSize;
                        DataSize -= Rounds * BlockSize;
                    }
                }

                {
                    if (DataSize) {
                        memcpy(_StreamBuffer.AsArray().GetPtr(), pBytes + DataReadPtr, DataSize);
                        _StreamLength += DataSize;
                        DataReadPtr += DataSize;
                        DataSize = 0;
                    }
                }

                _ProcessedBytes += DataReadPtr;
            }
        }

        ByteArray<DigestSize> Digest() const {
            __AlgType ForkedAlgInstance = _AlgInstance;
            ForkedAlgInstance.Finish(_StreamBuffer.AsArray().GetPtr(), _StreamLength, _ProcessedBytes);
            return ForkedAlgInstance.Digest();
        }
    };

}

