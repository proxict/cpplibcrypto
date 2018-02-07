#ifndef CIPHER_SYMMETRICALGORITHM_H_
#define CIPHER_SYMMETRICALGORITHM_H_

#include "common/DynamicBuffer.h"
#include "common/Key.h"
#include "common/BufferView.h"

namespace crypto {

class SymmetricAlgorithm {
public:
    using ConstByteBufferView = BufferView<const Byte>;
    SymmetricAlgorithm() : m_keySize(0) {}

    /// Performs a key schedule using the key provided
    /// \param key The key to use for key schedule
    void setKey(const Key& key) {
        m_keySize = key.size();
        keySchedule(key.getBytes());
    }

    /// Returns the key size
    Size getKeySize() const {
        return m_keySize;
    }

protected:
    /// Performs key schedule using the key provided
    /// \param key The key to use for key schedule
    virtual void keySchedule(const ConstByteBufferView& key) = 0;

    Size m_keySize;
};

} // namespace crypto

#endif

