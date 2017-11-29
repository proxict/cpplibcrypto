#ifndef PADDING_PKCS7_H_
#define PADDING_PKCS7_H_

#include <string>
#include <stdexcept>
#include <limits>

#include "padding/Padding.h"
#include "common/ByteBuffer.h"

namespace crypto {

class Pkcs7 : public Padding {
public:
    Pkcs7() = default;

    void pad(StaticByteBufferBase& buf, const std::size_t blockSize) const override {
        const Byte numOfBytesToPad = getPkcs7Size(buf.size(), blockSize);
        for (Byte i = 0; i < numOfBytesToPad; ++i) {
            buf.push(numOfBytesToPad);
        }
    }

    void unpad(StaticByteBufferBase& buf) const override {
        Byte bytesPadded = buf.back();
        while (bytesPadded-- > 0) {
            buf.pop();
        }
    }

private:
    static Byte getPkcs7Size(const std::size_t dataLen, const std::size_t blockSize) {
        const std::size_t padding = blockSize - dataLen % blockSize;
        if (padding > std::numeric_limits<Byte>::max()) {
            throw std::range_error("PKCS7 padding allows maximum block size of " +
                std::to_string(std::numeric_limits<Byte>::max()) + " bytes");
        }
        return static_cast<Byte>(padding);
    }
};

} // namespace crypto

#endif

