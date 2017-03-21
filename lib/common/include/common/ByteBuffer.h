#ifndef COMMON_BYTE_BUFFER_H_
#define COMMON_BYTE_BUFFER_H_

#include <string>
#include <utility>
#include <vector>
#include <limits>
#include <iostream>

#include "common/common.h"

namespace crypto {

template <class T>
class Allocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    template <class U>
    struct rebind {
        using other = Allocator<U>;
    };

    pointer address(reference value) const {
        return &value;
    }

    const_pointer address(const_reference value) const {
        return &value;
    }

    Allocator() throw() = default;

    Allocator(const Allocator&) throw() = default;

    template <class U>
    Allocator(const Allocator<U>&) throw() {}

    ~Allocator() throw() = default;

    size_type max_size() const throw() {
        return std::numeric_limits<std::size_t>::max() / sizeof(T);
    }

    pointer allocate(const size_type num, const void* = 0) {
        pointer ret = static_cast<pointer>(::operator new(num * sizeof(T)));
        return ret;
    }

    void construct(pointer p, const value_type& value) {
        new(static_cast<void*>(p))T(value);
    }

    void destroy(pointer p) {
        p->~T();
    }

    void deallocate(pointer p, const size_type) {
        ::operator delete((void*)p);
    }
};

template <class T1, class T2>
bool operator==(const Allocator<T1>&,
                 const Allocator<T2>&) throw() {
    return true;
}
template <class T1, class T2>
bool operator!=(const Allocator<T1>&,
                 const Allocator<T2>&) throw() {
    return false;
}

class ByteBuffer {
public:
    using const_iterator = std::vector<byte>::const_iterator;
    using iterator = std::vector<byte>::iterator;

    ByteBuffer() = default;

    ByteBuffer(const std::size_t n) {
        m_data.resize(n);
    }

    ByteBuffer(const std::initializer_list<byte>& il) {
        m_data.insert(m_data.end(), il.begin(), il.end());
    }

    ByteBuffer(const byte* begin, const byte* end) {
        m_data.insert(m_data.end(), begin, end);
    }

    ByteBuffer(ByteBuffer&& other) noexcept {
        *this = std::move(other);
    }

    ByteBuffer& operator=(ByteBuffer&& other) noexcept {
        m_data = std::move(other.m_data);
        return *this;
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        m_data.insert(end(), b.begin(), b.end());
        return *this;
    }

    ByteBuffer& operator+=(const byte b) {
        m_data.push_back(b);
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

    std::size_t size() const {
        return m_data.size();
    }

    const_iterator begin() const {
        return m_data.begin();
    }

    const_iterator end() const {
        return m_data.end();
    }

    byte& operator[](const std::size_t idx) {
        return m_data[idx];
    }

    const byte& operator[](const std::size_t idx) const {
        return m_data[idx];
    }

    bool operator==(const ByteBuffer& rhs) const {
        return size() == rhs.size() && std::equal(begin(), end(), rhs.begin());
    }

private:
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

    std::vector<byte> m_data;
};

} // namespace crypto

#endif

