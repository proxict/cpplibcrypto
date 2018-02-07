#ifndef PADDING_PKCS7_H_
#define PADDING_PKCS7_H_

#include <string>
#include <stdexcept>
#include <limits>

#include "padding/Padding.h"
#include "common/DynamicBuffer.h"

namespace crypto {

/// RFC 2315 compliant PKCS#7 padding implementation
class Pkcs7 : public Padding {
public:
    Pkcs7() = default;

    bool pad(DynamicBuffer<Byte>& buf, const Size blockSize) const override {
        return pad<DynamicBuffer<Byte>>(buf, blockSize);
    }
    
    bool pad(StaticByteBufferBase& buf, const Size blockSize) const override {
        return pad<StaticBufferBase<Byte>>(buf, blockSize);
    }

    /// Pads the buffer to the multiple of the given block size
    /// \param buf The buffer to be padded
    /// \param blockSize The block size to which the given buffer will be padded
    template <typename TContainer>
    bool pad(TContainer& buf, const Size blockSize) const {
        const Byte numOfBytesToPad = getPkcs7Size(buf.size(), blockSize);
        buf.insert(buf.end(), numOfBytesToPad, Size(numOfBytesToPad));
        return buf.size() % blockSize == 0;
    }

    void unpad(DynamicBuffer<Byte>& buf) const override {
        unpad<DynamicBuffer<Byte>>(buf);
    }
    
    void unpad(StaticByteBufferBase& buf) const override {
        unpad<StaticBufferBase<Byte>>(buf);
    }

    /// Unpads the given buffer
    /// \param buf The buffer to be unpadded
    template <typename TContainer>
    void unpad(TContainer& buf) const {
        Byte bytesPadded = buf.back();
        while (bytesPadded-- > 0) {
            buf.pop();
        }
    }

private:
    static Byte getPkcs7Size(const Size dataLen, const Size blockSize) {
        const Size padding = blockSize - dataLen % blockSize;
        if (padding > std::numeric_limits<Byte>::max()) {
            throw std::range_error("PKCS7 padding allows maximum block size of " +
                std::to_string(std::numeric_limits<Byte>::max()) + " bytes");
        }
        return static_cast<Byte>(padding);
    }
};

} // namespace crypto

#endif

