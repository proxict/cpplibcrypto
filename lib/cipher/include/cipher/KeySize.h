#ifndef CIPHER_KEYSIZE_H_
#define CIPHER_KEYSIZE_H_

#include <cstddef> // std::size_t

namespace crypto {

class KeySize {
public:
    KeySize(const std::size_t keySize) :
        m_minKeySize(keySize), m_maxKeySize(keySize), m_keySizeMod(1) {}

    KeySize(const std::size_t min_k, const std::size_t max_k, const std::size_t k_mod = 1) :
        m_minKeySize(min_k), m_maxKeySize(max_k ? max_k : min_k), m_keySizeMod(k_mod) {}

    bool isValid(const std::size_t keySize) const {
        return ((keySize >= m_minKeySize) && (keySize <= m_maxKeySize) && (keySize % m_keySizeMod == 0));
    }

    std::size_t getMin() const {
        return m_minKeySize;
    }

    std::size_t getMax() const {
        return m_maxKeySize;
    }

    std::size_t getMod() const {
        return m_keySizeMod;
    }

private:
    std::size_t m_minKeySize;
    std::size_t m_maxKeySize;
    std::size_t m_keySizeMod;
};

} // namespace crypto

#endif

