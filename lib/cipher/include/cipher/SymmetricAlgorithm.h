#ifndef CIPHER_SYMMETRICALGORITHM_H_
#define CIPHER_SYMMETRICALGORITHM_H_

#include "common/BufferView.h"
#include "common/DynamicBuffer.h"
#include "common/Key.h"

namespace crypto {

class SymmetricAlgorithm {
public:
    using ConstByteBufferView = BufferView<const Byte>;
    SymmetricAlgorithm() : mKeySize(0) {}

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

} // namespace crypto

#endif
