#ifndef CPPLIBCRYPTO_CIPHER_BLOCKCIPHERSIZED_H_
#define CPPLIBCRYPTO_CIPHER_BLOCKCIPHERSIZED_H_

#include "cpplibcrypto/cipher/BlockCipher.h"

NAMESPACE_CRYPTO_BEGIN

/// Base class for block ciphers
///
/// Block cipher implementations should inherit from this class
template <Size TBlockSize>
class BlockCipherSized : public BlockCipher {
public:
    /// Returns the block size of this cipher
    Size getBlockSize() const override { return TBlockSize; }

    virtual ~BlockCipherSized() = default;

protected:
    BlockCipherSized() = default;
};

NAMESPACE_CRYPTO_END

#endif
