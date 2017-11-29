#ifndef COMMON_KEY_H_
#define COMMON_KEY_H_

#include <cstddef>

#include "common/ByteBuffer.h"

namespace crypto {

class Key {
public:
    Key() = default;

    virtual bool isValid(const Size) const = 0;

    virtual Size size() const = 0;

    virtual const ByteBuffer& getBytes() const = 0;
};

} // namespace crypto

#endif
