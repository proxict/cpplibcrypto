#ifndef CIPHER_BLOCKCIPHER_H_
#define CIPHER_BLOCKCIPHER_H_

#include "cipher/SymmetricAlgorithm.h"
#include "cipher/KeySize.h"
#include "common/ByteBuffer.h"

namespace crypto {

class BlockCipher : public SymmetricAlgorithm {
public:
    BlockCipher() = default;

    virtual std::size_t getBlockSize() const = 0;

    virtual ByteBuffer encryptBlock(const ByteBuffer&) = 0;

    virtual ByteBuffer decryptBlock(const ByteBuffer&) = 0;
};

} // namespace crypto

#endif

