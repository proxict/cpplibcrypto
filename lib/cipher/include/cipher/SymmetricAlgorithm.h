#ifndef CIPHER_SYMMETRICALGORITHM_H_
#define CIPHER_SYMMETRICALGORITHM_H_

#include "common/BufferView.h"
#include "common/DynamicBuffer.h"
#include "common/Key.h"

NAMESPACE_CRYPTO_BEGIN

class SymmetricAlgorithm {
public:
    using ConstByteBufferView = BufferView<const Byte>;
    SymmetricAlgorithm() : mKeySize(0) {}

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
    virtual void keySchedule(const ConstByteBufferView& key) = 0;

    Size mKeySize;
};

NAMESPACE_CRYPTO_END

#endif
