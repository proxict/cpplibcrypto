#ifndef CIPHER_SYMMETRICALGORITHM_H_
#define CIPHER_SYMMETRICALGORITHM_H_

#include <stdexcept>

#include "cipher/KeySize.h"
#include "common/ByteBuffer.h"

namespace crypto {

class SymmetricAlgorithm {
public:
    virtual KeySize getKeySize() const = 0;

    std::size_t getMaxKeySize() const {
        return getKeySize().getMax();
    }

    std::size_t getMinKeySize() const {
        return getKeySize().getMin();
    }

    bool isKeySizeValid(const std::size_t keySize) const {
        return getKeySize().isValid(keySize);
    }

    void setKey(ByteBuffer&& key) {
        if(!isKeySizeValid(key.size()))
            throw std::invalid_argument("Invalid key size");
        keySchedule(key);
    }

private:
    virtual void keySchedule(const ByteBuffer& key) = 0;
};

} // namespace crypto

#endif

