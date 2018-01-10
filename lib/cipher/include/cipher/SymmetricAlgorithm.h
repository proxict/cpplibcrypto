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

    void setKey(const Key& key) {
        m_keySize = key.size();
        keySchedule(key.getBytes());
    }

    Size getKeySize() const {
        return m_keySize;
    }

private:
    virtual void keySchedule(const ConstByteBufferView& key) = 0;

    Size m_keySize;
};

} // namespace crypto

#endif

