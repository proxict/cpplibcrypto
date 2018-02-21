#ifndef COMMON_HEX_STRING_H_
#define COMMON_HEX_STRING_H_

#include "common/DynamicBuffer.h"
#include "common/Hex.h"
#include "common/StaticBuffer.h"
#include "common/String.h"
#include "common/bufferUtils.h"

NAMESPACE_CRYPTO_BEGIN

/// Represents a base-16 string
class HexString {
    using StaticByteBufferBase = StaticBufferBase<Byte>;

public:
    /// \param hexStr Hexadecimal data in string representation
    /// \throws Exception if hexStr contains an invalid base-16 character
    HexString(const String& hexStr) : mDecoded(Hex::decode(hexStr)) {}

    HexString& operator=(HexString&& other) noexcept {
        mDecoded = std::move(other.mDecoded);
        return *this;
    }

    HexString(HexString&& other) noexcept { *this = std::move(other); }

    /// Returns the number of bytes of the decoded data
    Size size() const { return mDecoded.size(); }

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
        mDecoded += rhs.mDecoded;
        return *this;
    }

    /// Appends data from this HexString to the given buffer
    template <typename TBuffer>
    friend TBuffer& operator+=(TBuffer& lhs, const HexString& rhs) {
        lhs.insert(lhs.end(), rhs.mDecoded.begin(), rhs.mDecoded.end());
        return lhs;
    }

    /// Returns whether or not the two HexStrings are equal
    bool operator==(const HexString& rhs) const { return mDecoded == rhs.mDecoded; }

    /// Returns whether or not the given buffer is equal to the data from this HexString
    template <typename TBuffer>
    friend bool operator==(const TBuffer& lhs, const HexString& rhs) {
        return bufferUtils::equal(lhs, rhs.mDecoded);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator!=(const TBuffer& lhs, const HexString& rhs) {
        return !bufferUtils::equal(lhs, rhs.mDecoded);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator==(const HexString& lhs, const TBuffer& rhs) {
        return bufferUtils::equal(lhs.mDecoded, rhs);
    }

    /// \copydoc operator==()
    template <typename TBuffer>
    friend bool operator!=(const HexString& lhs, const TBuffer& rhs) {
        return !bufferUtils::equal(lhs.mDecoded, rhs);
    }

private:
    HexString() = delete;
    HexString(const HexString&) = delete;
    HexString& operator=(const HexString&) = delete;

    ByteBuffer mDecoded;
};

NAMESPACE_CRYPTO_END

#endif
