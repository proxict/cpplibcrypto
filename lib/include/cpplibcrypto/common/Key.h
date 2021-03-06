#ifndef CPPLIBCRYPTO_COMMON_KEY_H_
#define CPPLIBCRYPTO_COMMON_KEY_H_

#include "cpplibcrypto/buffer/DynamicBuffer.h"

namespace crypto {

class Key {
public:
    Key() = default;

    virtual ~Key() = default;

    /// Tells whether or not the given size is valid for this key
    virtual bool isValid(const Size) const = 0;

    /// Returns the size of this key
    virtual Size size() const = 0;

    /// Returns the byte representation of the key
    virtual const ByteBuffer& getBytes() const = 0;
};

} // namespace crypto

#endif
