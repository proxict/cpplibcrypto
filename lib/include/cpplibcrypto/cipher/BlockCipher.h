#ifndef CPPLIBCRYPTO_CIPHER_BLOCKCIPHER_H_
#define CPPLIBCRYPTO_CIPHER_BLOCKCIPHER_H_

#include "cpplibcrypto/common/SymmetricAlgorithm.h"

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/common/Key.h"

namespace crypto {

/// Interface for block ciphers.
///
/// Cipher implementations, however, should not inherit directly from this class, but rather from \ref
/// BlockCipherSized
class BlockCipher : public SymmetricAlgorithm {
public:
    using ByteBufferSlice = BufferSlice<Byte>;

    BlockCipher() = default;

    virtual ~BlockCipher() = default;

    /// Returns the block size of this cipher
    virtual Size getBlockSize() const = 0;

    /// Encrypts one block
    ///
    /// \param buffer The buffer which will get encrypted. Note that the buffer can be overwritten with the
    /// encrypted data.
    virtual void encryptBlock(ByteBufferSlice) const = 0;

    /// Encrypts one block
    ///
    /// \param buffer The buffer which will get decrypted. Note that the buffer can be overwritten with the
    /// decrypted data.
    virtual void decryptBlock(ByteBufferSlice) const = 0;
};

} // namespace crypto

#endif
