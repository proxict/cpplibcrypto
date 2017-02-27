#ifndef COMMON_BYTE_BUFFER_H_
#define COMMON_BYTE_BUFFER_H_

#include <string>
#include <utility>
#include <memory>

#include "common/common.h"

namespace crypto {

class ByteBuffer {
public:
    ByteBuffer() = default;

    ByteBuffer(const std::size_t n) noexcept {
        m_allocator.allocate(n);
    }

    ByteBuffer(ByteBuffer&& other) noexcept {
        *this = std::move(other);
    }

    ByteBuffer& operator=(ByteBuffer&& other) noexcept {
        m_allocator = std::move(other.m_allocator);
        return *this;
    }

    ~ByteBuffer() {
        m_allocator.deallocate(nullptr);
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        insert(this->end(), b.begin(), b.end());
        return *this;
    }

    ByteBuffer& operator+=(const byte b) {
        append(b);
        return *this;
    }

    const ByteBuffer operator+(const byte rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    const ByteBuffer operator+(const ByteBuffer& rhs) const {
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
        return size() == rhs.size() && std::equal(begin(), end(), rhs.begin());
    }

    std::size_t size() const {
        return 0;
    }

    byte* begin() const {
        return 0;
    }

    byte* end() const {
        return 0;
    }

    template <typename T>
    void insert(const T& pos, const T& begin, const T& end) {

    }

    void append(const byte b) {

    }

private:
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

    std::allocator<byte> m_allocator;
};

} // namespace crypto

#endif

