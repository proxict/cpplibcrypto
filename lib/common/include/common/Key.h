#ifndef COMMON_KEY_H_
#define COMMON_KEY_H_

#include <cstddef>

#include "common/ByteBuffer.h"

namespace crypto {

class Key {
public:
    Key() = default;

    virtual bool isValid(const std::size_t) const = 0;

    virtual std::size_t size() const = 0;

    virtual const ByteBuffer& getBytes() const = 0;
};

} // namespace crypto

#endif
