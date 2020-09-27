#ifndef CPPLIBCRYPTO_CIPHER_SYMMETRICALGORITHM_H_
#define CPPLIBCRYPTO_CIPHER_SYMMETRICALGORITHM_H_

#include "cpplibcrypto/buffer/BufferSlice.h"
#include "cpplibcrypto/buffer/DynamicBuffer.h"
#include "cpplibcrypto/common/Key.h"

namespace crypto {

class SymmetricAlgorithm {
public:
    using ConstByteBufferSlice = BufferSlice<const Byte>;
    SymmetricAlgorithm()
        : mKeySize(0) {}

    virtual ~SymmetricAlgorithm() = default;

    /// Performs a key schedule using the key provided
    /// \param key The key to use for key schedule
    void setKey(const Key& key) {
        mKeySize = key.size();
        keySchedule(key.getBytes());
    }

    /// Returns the key size
    Size getKeySize() const { return mKeySize; }

protected:
    /// Performs key schedule using the key provided
    /// \param key The key to use for key schedule
    virtual void keySchedule(const ConstByteBufferSlice& key) = 0;

    Size mKeySize;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_CIPHER_SYMMETRICALGORITHM_H_
