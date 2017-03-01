#ifndef COMMON_AES_H_
#define COMMON_AES_H_

#include <stdexcept>
#include <limits>

#include "common/common.h"
#include "common/ByteBuffer.h"

namespace crypto {

namespace padding {

class PaddingBase {
public:
    PaddingBase() = default;
    virtual ~PaddingBase() = default;

    constexpr static std::size_t getPaddingSize(const std::size_t dataLen, const std::size_t blockSize) {
      return blockSize - dataLen % blockSize;
    }
};

class PKCS7 : public PaddingBase {
public:
    PKCS7() = default;

    static ByteBuffer pad(const ByteBuffer& buf, const std::size_t blockSize) {
        ByteBuffer bb;
        bb += buf;

        // ByteBuffer::insert(byte, std::size_t) would fit much more
        const byte numOfBytesToPad = getPkcs7Size(buf.size(), blockSize);
        for (byte i = 0; i < numOfBytesToPad; ++i) {
            bb += numOfBytesToPad;
        }
        return bb;
    }

    static ByteBuffer unpad(const ByteBuffer& buf) {
        ByteBuffer bb;
        // bb.insert(bb.end(), buf.begin(), buf.end() - static_cast<std::size_t>(buf.back()));
        return bb;
    }

private:
    static byte getPkcs7Size(const std::size_t dataLen, const std::size_t blockSize) {
        const std::size_t padding = getPaddingSize(dataLen, blockSize);
        if (padding > std::numeric_limits<byte>::max()) {
            throw std::range_error("PKCS7 padding allows maximum block size of 255");
        }
        return static_cast<byte>(padding);
    }
};

} // namespace padding

namespace cipher_operation_mode {

enum Mode { ECB, CBC, PCBC, CFB, OFB, CTR };

} // namespace cipher_operation_mode

namespace aes_key_size {

enum KeySize { AES128 = 128, AES192 = 192, AES256 = 256 };

} // namespace aes_key_size

class CipherTypeAes {
public:
    CipherTypeAes() = default;

    static ByteBuffer encryptBlock(const ByteBuffer&) {
        return ByteBuffer{};
    }

    static ByteBuffer decryptBlock(const ByteBuffer&) {
        return ByteBuffer{};
    }

private:
    CipherTypeAes& operator=(const CipherTypeAes&) = delete;
    CipherTypeAes(const CipherTypeAes&) = delete;
};

template <typename CipherTypeT, typename PaddingT, std::size_t blockSize>
class BlockCiphersBase {
public:
    BlockCiphersBase() = default;

    virtual ~BlockCiphersBase() = default;

    static ByteBuffer encrypt(const ByteBuffer&) {
        return CipherTypeT::encryptBlock({0, 0});
    }

    static ByteBuffer decrypt(const ByteBuffer&) {
        return CipherTypeT::decryptBlock({0, 0});
    }
};

template <aes_key_size::KeySize, cipher_operation_mode::Mode, typename PaddingT>
class AES : public BlockCiphersBase<CipherTypeAes, PaddingT, 16> {
public:
    AES() = default;
};

} // namespace crypto

#endif

