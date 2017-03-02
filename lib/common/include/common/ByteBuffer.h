#ifndef COMMON_BYTEBUFFER_H_
#define COMMON_BYTEBUFFER_H_

#include <utility>
#include <vector>

#include "common/common.h"

namespace crypto {

class ByteBuffer {

public:
    using iterator = std::vector<byte>::iterator;
    using const_iterator = std::vector<byte>::const_iterator;
    using size_type = std::vector<byte>::size_type;

public:
    ByteBuffer() = default;

    explicit ByteBuffer(size_type size) : data(size) {
    }

    ByteBuffer(std::initializer_list<byte> list) : data(std::move(list)) {
    }

    ByteBuffer(ByteBuffer&& src) noexcept : data(std::move(src.data)) {
    }

    ByteBuffer& operator=(ByteBuffer&& src) noexcept {
        data = std::move(src.data);
        return *this;
    }

    const_iterator begin() const {
        return data.begin();
    }

    const_iterator end() const {
        return data.end();
    }

    byte& operator[](size_type index) {
        return data[index];
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        data.insert(data.end(), b.data.begin(), b.data.end());
        return *this;
    }

    ByteBuffer& operator+=(const byte b) {
        data.push_back(b);
        return *this;
    }

    const ByteBuffer operator+(const ByteBuffer& rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    const ByteBuffer operator+(const byte rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    friend const ByteBuffer operator+(const byte lhs, const ByteBuffer& rhs) {
        ByteBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    bool operator==(const ByteBuffer& rhs) const {
        return data.size() == rhs.data.size() && std::equal(data.begin(), data.end(), rhs.data.begin());
    }

    bool operator!=(const ByteBuffer& rhs) const {
        return !(*this == rhs);
    }

    size_type size() const {
        return data.size();
    }

private:
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

private:
    std::vector<byte> data;
};

} // namespace crypto

#endif // COMMON_BYTEBUFFER_H_
