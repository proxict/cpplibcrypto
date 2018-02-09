//------------------------------------------------------------------------------
///
/// \file
/// \brief Provides functions for converting base16 to base10 and vice versa
///
//------------------------------------------------------------------------------
#include "common/Hex.h"
#include "common/Exception.h"

NAMESPACE_CRYPTO_BEGIN

ByteBuffer Hex::decode(const std::string& hexStr) {
    if (hexStr.size() & 1) {
        throw Exception("Odd HEX data length passed");
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
        throw Exception("Invalid HEX char passed");
    }
}

NAMESPACE_CRYPTO_END

