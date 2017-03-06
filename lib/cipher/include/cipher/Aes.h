#ifndef COMMON_AES_H_
#define COMMON_AES_H_

#include <stdexcept>
#include <limits>

#include "common/common.h"
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
            throw std::range_error("PKCS7 padding allows maximum block size of 255");
        }
        return static_cast<byte>(padding);
    }
};

enum class AesKeySize { Aes128 = 128, Aes192 = 192, Aes256 = 256 };

template <AesKeySize keySize>
class Aes {
public:
    constexpr static int BlockSize = 16;

    Aes() = default;

    // TODO(ProXicT): use fixed sized buffers
    static ByteBuffer encrypt(const ByteBuffer&) {
        return ByteBuffer{};
    }

    static ByteBuffer decrypt(const ByteBuffer&) {
        return ByteBuffer{};
    }

private:
    Aes& operator=(const Aes&) = delete;
    Aes(const Aes&) = delete;
};

enum class Rc5BlockSize { Rc532 = 32, Rc564 = 64, Rc5128 = 128 };

// Note(ProXicT): Rc5 keySize is within range <0, 2048>, variable block size {32, 64, 128}, # of rounds <0, 255>
template <short keySize, Rc5BlockSize blockSize, short rounds>
class Rc5 {
public:
    constexpr static int BlockSize = static_cast<int>(blockSize);

    Rc5() = default;

    // TODO(ProXicT): use fixed sized buffers
    static ByteBuffer encrypt(const ByteBuffer&) {
        return ByteBuffer{};
    }

    static ByteBuffer decrypt(const ByteBuffer&) {
        return ByteBuffer{};
    }

private:
    Rc5& operator=(const Rc5&) = delete;
    Rc5(const Rc5&) = delete;
};

template <typename BlockCipherType, typename PaddingT>
class EcbCipher {
public:
    static ByteBuffer encrypt(const ByteBuffer& bb) {
        ByteBuffer padded;
        padded += PaddingT::pad(bb, BlockCipherType::BlockSize);
        return BlockCipherType::encrypt(bb + padded);
    }

    static ByteBuffer decrypt(const ByteBuffer& bb) {
        return BlockCipherType::decrypt(bb);
    }

    void init(const ByteBuffer& /*key*/) {

    }

    // Note(ProXicT): Needs data length in multiple of BlockSize (because of padding)?
    ByteBuffer update(const ByteBuffer& /*data*/) {
        return ByteBuffer{};
    }

    ByteBuffer finish() {
        return ByteBuffer{};
    }
};

template <typename BlockCipherType, typename PaddingT>
class CbcCipher {
public:
    static ByteBuffer encrypt(const ByteBuffer& bb) {
        ByteBuffer padded;
        padded += PaddingT::pad(bb, BlockCipherType::BlockSize);
        return BlockCipherType::encrypt(bb + padded);
    }

    static ByteBuffer decrypt(const ByteBuffer& bb) {
        return BlockCipherType::decrypt(bb);
    }

    ByteBuffer init(const ByteBuffer& /*key*/, const ByteBuffer& /*iv*/) {
        return ByteBuffer{};
    }

    // Note(ProXicT): Needs data length in multiple of BlockSize (because of padding)?
    ByteBuffer update(const ByteBuffer& /*data*/) {
        return ByteBuffer{};
    }

    ByteBuffer finish() {
        return ByteBuffer{};
    }
};

} // namespace crypto

#endif

