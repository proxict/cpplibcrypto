#ifndef CIPHER_SYMMETRICALGORITHM_H_
#define CIPHER_SYMMETRICALGORITHM_H_

#include "common/ByteBuffer.h"
#include "common/Key.h"

namespace crypto {

class SymmetricAlgorithm {
public:
    SymmetricAlgorithm() : m_keySize(0) {}

    void setKey(Key&& key) {
        m_keySize = key.size();
        keySchedule(key.getKeyBytes());
    }

    std::size_t getKeySize() const {
        return m_keySize;
    }

private:
    virtual void keySchedule(const ByteBuffer& key) = 0;

    std::size_t m_keySize;
};

} // namespace crypto

#endif

