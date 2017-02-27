#ifndef COMMON_HEX_H_
#define COMMON_HEX_H_

#include <stdexcept>
#include <string>

#include "common/ByteBuffer.h"
#include "common/HexDecodeTable.h"
#include "common/HexEncodeTable.h"

namespace crypto {

class Hex {
public:
    static std::string encode(const ByteBuffer& buf) {
        std::string hexString;
        hexString.reserve(buf.size() * 2);
        for (const auto& it : buf) {
            hexString += HexEncodeTable::byte2char(it);
        }
        return hexString;
    }

    static ByteBuffer decode(const std::string& hexStr) {
        if (hexStr.size() & 1)
            throw std::invalid_argument("Odd HEX data length passed");

        ByteBuffer output(hexStr.size() / 2);
        constexpr HexDecodeTable table;
        for (size_t i = 0; i < hexStr.size(); i += 2) {
            output[i / 2] = table.hex2byte(hexStr[i], hexStr[i + 1]);
        }
        return output;
    }

private:
    Hex() = delete;
};

} // namespace crypto

#endif
