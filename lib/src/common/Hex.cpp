#include "cpplibcrypto/common/Hex.h"
#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/common/Exception.h"

namespace crypto {

ByteBuffer Hex::decode(const String& hexStr) {
    if (hexStr.size() & 1) {
        throw Exception("Hex: Odd data length passed");
    }

    ByteBuffer output(hexStr.size() / 2);
    for (Size i = 0; i < hexStr.size(); i += 2) {
        output[i / 2] = hex2Byte(hexStr[i]) << 4 | (hex2Byte(hexStr[i + 1]) & 0x0f);
    }
    return output;
}

constexpr Byte Hex::hex2Byte(const char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        throw Exception("Hex: Invalid character passed");
    }
}

} // namespace crypto
