#ifndef CPPLIBCRYPTO_COMMON_HEX_H_
#define CPPLIBCRYPTO_COMMON_HEX_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/io/Stream.h"

NAMESPACE_CRYPTO_BEGIN

/// Converted from base-16 to base-10 and vice versa
class Hex final {
public:
    /// Encodes the given buffer to base-16
    /// \returns string representation of the encoded data
    template <typename TBuffer>
    static String encode(const TBuffer& buf);

    /// Decodes the given base-16 string
    /// \returns base-10 buffer of bytes
    /// \throws Exception if hexStr contains an invalid base-16 character
    static ByteBuffer decode(const String& hexStr);

private:
    Hex() = delete;

    constexpr static Byte hex2Byte(const char c);
};

template <typename TBuffer>
String Hex::encode(const TBuffer& buf) {
    constexpr static const char* lookupTable = "0123456789abcdef";
    StringOutputStream bytes;
    for (const Byte b : buf) {
        bytes << lookupTable[b >> 4] << lookupTable[b & 0x0f];
    }
    return bytes.toString();
}

NAMESPACE_CRYPTO_END

#endif
