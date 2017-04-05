#ifndef PADDING_PKCS7_H_
#define PADDING_PKCS7_H_

#include <stdexcept>
#include <limits>

#include "common/ByteBuffer.h"

namespace crypto {

class Pkcs7 {
public:
    Pkcs7() = default;

    static ByteBuffer pad(const ByteBuffer& buf, const std::size_t blockSize) {
        ByteBuffer bb;

        // Note(ProXicT): ByteBuffer::insert(byte, std::size_t) would fit much more
        const byte numOfBytesToPad = getPkcs7Size(buf.size(), blockSize);
        for (byte i = 0; i < numOfBytesToPad; ++i) {
            bb += numOfBytesToPad;
        }
        return bb;
    }

private:
    static byte getPkcs7Size(const std::size_t dataLen, const std::size_t blockSize) {
        const std::size_t padding = blockSize - dataLen % blockSize;
        if (padding > std::numeric_limits<byte>::max()) {
            throw std::range_error("PKCS7 padding allows maximum block size of 255 bytes");
        }
        return static_cast<byte>(padding);
    }
};

} // namespace crypto

#endif

