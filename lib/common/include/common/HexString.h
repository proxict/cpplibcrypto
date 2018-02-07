#ifndef COMMON_HEX_STRING_H_
#define COMMON_HEX_STRING_H_

#include "common/DynamicBuffer.h"
#include "common/StaticBuffer.h"
#include "common/bufferUtils.h"
#include "common/Hex.h"

namespace crypto {

/// Represents a base-16 string
class HexString {
    using StaticByteBufferBase = StaticBufferBase<Byte>;
public:
    /// \param hexStr Hexadecimal data in string representation
    /// \throws Exception if hexStr contains an invalid base-16 character
    HexString(const std::string& hexStr) : m_decoded(Hex::decode(hexStr)) {}

    HexString& operator=(HexString&& other) noexcept {
        m_decoded = std::move(other.m_decoded);
        return *this;
    }

    HexString(HexString&& other) noexcept {
        *this = std::move(other);
    }

    /// Returns the number of bytes of the decoded data
    Size size() const {
        return m_decoded.size();
    }

    /// Returns a copy of this HexString with another HexString appended
    HexString operator+(const HexString& rhs) const {
        HexString hexString("");
        hexString += *this;
        hexString += rhs;
        return hexString;
    }

    /// Appends data from the given HexString to this HexString
    /// \returns Reference to this object
    HexString& operator+=(const HexString& rhs) {
        m_decoded += rhs.m_decoded;
        return *this;
    }

    /// Appends data from this HexString to the given buffer
    template <typename TContainer>
    friend TContainer& operator+=(TContainer& lhs, const HexString& rhs) {
        lhs.insert(lhs.end(), rhs.m_decoded.begin(), rhs.m_decoded.end());
        return lhs;
    }

    /// Returns whether or not the two HexStrings are equal
    bool operator==(const HexString& rhs) const {
        return m_decoded == rhs.m_decoded;
    }

    /// Returns whether or not the given buffer is equal to the data from this HexString
    template <typename TContainer>
    friend bool operator==(const TContainer& lhs, const HexString& rhs) {
        return bufferUtils::equal(lhs, rhs.m_decoded);
    }

    /// \copydoc operator==()
    template <typename TContainer>
    friend bool operator!=(const TContainer& lhs, const HexString& rhs) {
        return !bufferUtils::equal(lhs, rhs.m_decoded);
    }

    /// \copydoc operator==()
    template <typename TContainer>
    friend bool operator==(const HexString& lhs, const TContainer& rhs) {
        return bufferUtils::equal(lhs.m_decoded, rhs);
    }

    /// \copydoc operator==()
    template <typename TContainer>
    friend bool operator!=(const HexString& lhs, const TContainer& rhs) {
        return !bufferUtils::equal(lhs.m_decoded, rhs);
    }

private:
    HexString() = delete;
    HexString(const HexString&) = delete;
    HexString& operator=(const HexString&) = delete;

    ByteBuffer m_decoded;
};

} // namespace crypto

#endif
