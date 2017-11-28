#ifndef CIPHER_BLOCKCIPHER_H_
#define CIPHER_BLOCKCIPHER_H_

#include "cipher/SymmetricAlgorithm.h"

#include "common/StaticByteBuffer.h"
#include "common/Key.h"

namespace crypto {

class BlockCipher : public SymmetricAlgorithm {
public:
    BlockCipher() = default;

    virtual std::size_t getBlockSize() const = 0;

    virtual void encryptBlock(StaticByteBufferBase&) = 0;

    virtual void decryptBlock(StaticByteBufferBase&) = 0;
};

} // namespace crypto

#endif

