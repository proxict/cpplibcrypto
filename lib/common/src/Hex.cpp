#include "common/Hex.h"

#include <sstream>
#include <stdexcept>

namespace crypto {

std::string Hex::encode(const crypto::ByteBuffer& buf) {
    constexpr static const char* lookupTable = "0123456789abcdef";
    std::ostringstream bytes;
    for (const byte b : buf) {
        bytes << lookupTable[b >> 4] << lookupTable[b & 0x0f];
    }
    return bytes.str();
}

crypto::ByteBuffer Hex::decode(const std::string& hexStr) {
    if (hexStr.size() & 1) {
        throw std::invalid_argument("Odd HEX data length passed");
    }

    ByteBuffer output(hexStr.size() / 2);
    for (std::size_t i = 0; i < hexStr.size(); i += 2) {
        output[i / 2] = hex2Byte(hexStr[i]) << 4 | (hex2Byte(hexStr[i + 1]) & 0x0f);
    }
    return output;
}

constexpr byte Hex::hex2Byte(const char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        throw std::invalid_argument("Invalid HEX char passed");
    }
}

} // namespace crypto
