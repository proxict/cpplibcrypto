#ifndef CIPHER_BLOCKCIPHERSIZED_H_
#define CIPHER_BLOCKCIPHERSIZED_H_

#include "cipher/BlockCipher.h"

NAMESPACE_CRYPTO_BEGIN

/// Base class for block ciphers
///
/// Block cipher implementations should inherit from this class
template <Size TBlockSize>
class BlockCipherSized : public BlockCipher {
public:
    /// Returns the block size of this cipher
    Size getBlockSize() const override { return TBlockSize; }

protected:
    BlockCipherSized() = default;
};

NAMESPACE_CRYPTO_END

#endif
