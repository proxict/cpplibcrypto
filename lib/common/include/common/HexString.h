#ifndef COMMON_HEX_STRING_H_
#define COMMON_HEX_STRING_H_

#include "common/ByteBuffer.h"
#include "common/Hex.h"

namespace crypto {

class HexString {
public:
    HexString(const std::string& hexStr) : m_decoded(Hex::decode(hexStr)) {}

    HexString& operator=(HexString&& other) noexcept {
        m_decoded = std::move(other.m_decoded);
        return *this;
    }

    HexString(HexString&& other) noexcept {
        *this = std::move(other);
    }

    std::size_t size() const {
        return m_decoded.size();
    }

    HexString& operator+=(const HexString& rhs) {
        m_decoded += rhs.m_decoded;
        return *this;
    }

    friend ByteBuffer& operator+=(ByteBuffer& lhs, const HexString& rhs) {
        lhs += rhs.m_decoded;
        return lhs;
    }

    friend bool operator==(const ByteBuffer& lhs, const HexString& rhs) {
        return lhs == rhs.m_decoded;
    }

    friend bool operator==(const HexString& lhs, const ByteBuffer& rhs) {
        return lhs.m_decoded == rhs;
    }

    const HexString operator+(const HexString& rhs) const {
        HexString hexString("");
        hexString += *this;
        hexString += rhs;
        return hexString;
    }

    bool operator==(const HexString& rhs) const {
        return m_decoded == rhs.m_decoded;
    }

private:
    HexString() = delete;
    HexString(const HexString&) = delete;
    HexString& operator=(const HexString&) = delete;

    ByteBuffer m_decoded;
};

} // namespace crypto

#endif
