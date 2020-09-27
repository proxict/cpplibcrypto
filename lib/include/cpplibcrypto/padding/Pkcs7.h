#ifndef CPPLIBCRYPTO_PADDING_PKCS7_H_
#define CPPLIBCRYPTO_PADDING_PKCS7_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/common/Exception.h"
#include "cpplibcrypto/padding/Padding.h"

#include <limits>

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
    /// \throws Exception in case blockSize is more than UCHAR_MAX
    template <typename TBuffer>
    bool pad(TBuffer& buf, const Size blockSize) const {
        const Byte numOfBytesToPad = getPkcs7Size(buf.size(), blockSize);
        buf.insert(buf.end(), numOfBytesToPad, Size(numOfBytesToPad));
        return buf.size() % blockSize == 0;
    }

    void unpad(DynamicBuffer<Byte>& buf) const override { unpad<DynamicBuffer<Byte>>(buf); }

    void unpad(StaticByteBufferBase& buf) const override { unpad<StaticBufferBase<Byte>>(buf); }

    /// Unpads the given buffer
    /// \param buf The buffer to be unpadded
    template <typename TBuffer>
    void unpad(TBuffer& buf) const {
        Byte bytesPadded = buf.back();
        while (bytesPadded-- > 0) {
            buf.pop();
        }
    }

private:
    static Byte getPkcs7Size(const Size dataLen, const Size blockSize) {
        const Size padding = blockSize - dataLen % blockSize;
        if (padding > std::numeric_limits<Byte>::max()) {
            const std::string stdMax = std::to_string(std::numeric_limits<Byte>::max());
            const String max(stdMax.begin(), stdMax.end());
            throw Exception("PKCS7 padding allows maximum block size of " + max + " bytes");
        }
        return static_cast<Byte>(padding);
    }
};

} // namespace crypto

#endif
