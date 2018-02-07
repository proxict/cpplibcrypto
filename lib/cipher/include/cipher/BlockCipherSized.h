#ifndef CIPHER_BLOCKCIPHERSIZED_H_
#define CIPHER_BLOCKCIPHERSIZED_H_

#include "cipher/BlockCipher.h"

namespace crypto {

/// Base class for block ciphers
///
/// Block cipher implementations should inherit from this class
template<Size TBlockSize>
class BlockCipherSized : public BlockCipher {
public:
    /// Returns the block size of this cipher
    Size getBlockSize() const override { return TBlockSize; }

protected:
    BlockCipherSized() = default;
};

} // namespace crypto

#endif

