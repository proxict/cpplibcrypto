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

    virtual void encryptBlock(ByteBuffer&) = 0;

    virtual void decryptBlock(ByteBuffer&) = 0;
};

} // namespace crypto

#endif

