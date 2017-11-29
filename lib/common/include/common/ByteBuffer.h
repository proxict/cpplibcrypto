#ifndef COMMON_BYTEBUFFER_H_
#define COMMON_BYTEBUFFER_H_

#include <limits>
#include <utility>
#include <vector>

#include "common/common.h"

namespace crypto {

template <class T>
class SecureAllocator {
public:
    using value_type = T;
    using pointer = value_type*;
    using const_pointer = const value_type*;
    using reference = value_type&;
    using const_reference = const value_type&;
    using size_type = Size;
    using difference_type = std::ptrdiff_t;

    template <class TargetT>
    class rebind {
    public:
        using other = SecureAllocator<TargetT>;
    };

    SecureAllocator(const bool sensitive = false) : m_wipe(sensitive) {}

    ~SecureAllocator() = default;

    template <class T2>
    SecureAllocator(const SecureAllocator<T2>& other) : m_wipe(other.m_wipe) {}

    pointer address(reference ref) {
        return &ref;
    }

    const_pointer address(const_reference ref) {
        return &ref;
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof(value_type);
    }

    pointer allocate(const size_type count, const void* = 0) {
        return static_cast<pointer>(::operator new(count * sizeof(value_type)));
    }

    void deallocate(pointer ptr, const size_type) {
        ::operator delete((void*)ptr);
    }

    void construct(pointer ptr, const value_type& value) {
        new(static_cast<void*>(ptr))T(value);
    }

    void destroy(pointer ptr) {
        if (m_wipe) {
            Byte* bytePtr = reinterpret_cast<Byte*>(ptr);
            for (Size i = 0; i < sizeof(value_type); ++i) {
                bytePtr[i] = 0;
            }
        }
        ptr->~T();
    }

    template <class T2> bool
    operator==(SecureAllocator<T2> const&) const {
        return true;
    }

    template <class T2> bool
    operator!=(SecureAllocator<T2> const&) const {
        return false;
    }

protected:
    bool m_wipe;
};

class ByteBuffer {
public:
    using iterator = std::vector<Byte, SecureAllocator<Byte>>::iterator;
    using const_iterator = std::vector<Byte, SecureAllocator<Byte>>::const_iterator;
    using size_type = std::vector<Byte, SecureAllocator<Byte>>::size_type;

public:
    ByteBuffer(const bool sensitive = true) : m_allocator(sensitive), m_data(m_allocator) {}

    explicit ByteBuffer(const size_type size, const bool sensitive = true) : m_allocator(sensitive), m_data(size, m_allocator) {}

    ByteBuffer(std::initializer_list<Byte>&& list, const bool sensitive = true) : m_allocator(sensitive), m_data(std::move(list)) {}

    ByteBuffer& operator=(ByteBuffer&& other) noexcept {
        m_allocator = std::move(other.m_allocator);
        m_data = std::move(other.m_data);
        return *this;
    }

    ByteBuffer(ByteBuffer&& other) noexcept {
        *this = std::move(other);
    }

    const_iterator begin() const {
        return m_data.begin();
    }

    const_iterator end() const {
        return m_data.end();
    }

    iterator begin() {
        return m_data.begin();
    }

    iterator end() {
        return m_data.end();
    }

    Byte* data() {
        return m_data.data();
    }

    const Byte* data() const {
        return m_data.data();
    }

    Byte& operator[](size_type index) {
        return m_data[index];
    }

    const Byte operator[](const Size idx) const {
        return m_data[idx];
    }

    ByteBuffer& operator+=(const ByteBuffer& b) {
        m_data.insert(m_data.end(), b.m_data.begin(), b.m_data.end());
        return *this;
    }

    ByteBuffer& operator+=(const Byte b) {
        m_data.push_back(b);
        return *this;
    }

    const ByteBuffer operator+(const ByteBuffer& rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    const ByteBuffer operator+(const Byte rhs) const {
        ByteBuffer bb;
        bb += *this;
        bb += rhs;
        return bb;
    }

    friend const ByteBuffer operator+(const Byte lhs, const ByteBuffer& rhs) {
        ByteBuffer bb;
        bb += lhs;
        bb += rhs;
        return bb;
    }

    bool operator==(const ByteBuffer& rhs) const {
        return m_data.size() == rhs.m_data.size() && std::equal(m_data.begin(), m_data.end(), rhs.m_data.begin());
    }

    bool operator!=(const ByteBuffer& rhs) const {
        return !(*this == rhs);
    }

    size_type size() const {
        return m_data.size();
    }

    void clear() {
        m_data.clear();
    }

    template<typename TInputIterator, typename = std::_RequireInputIter<TInputIterator>>
    iterator insert(const_iterator position, TInputIterator first, TInputIterator last) {
        return m_data.insert(position, first, last);
    }

private:
    ByteBuffer(const ByteBuffer&) = delete;
    ByteBuffer& operator=(const ByteBuffer&) = delete;

private:
    SecureAllocator<Byte> m_allocator;
    std::vector<Byte, SecureAllocator<Byte>> m_data;
};

} // namespace crypto

#endif // COMMON_BYTEBUFFER_H_
