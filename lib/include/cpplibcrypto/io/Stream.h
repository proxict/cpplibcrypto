#ifndef CPPLIBCRYPTO_IO_STREAM_H_
#define CPPLIBCRYPTO_IO_STREAM_H_

#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/buffer/utils/SecureAllocator.h"
#include "cpplibcrypto/io/File.h"

#include <sstream>
#include <utility>

NAMESPACE_CRYPTO_BEGIN

/// Base class for input streams
class InputStream {
public:
    virtual ~InputStream() = default;

    /// Reads \ref count bytes from input
    /// \param output The destination memory to save the data to
    /// \param count The number of bytes to read from the stream
    /// \returns The number of bytes read. This should be equal to \ref count in case \ref count bytes was
    /// available in the stream. If the return value is less than \ref count, EOF must have been reached.
    virtual Size read(void* output, const Size count) = 0;

    /// Tells whether or not the stream is at the EOF
    virtual bool eof() const = 0;

    /// Closes the input stream.
    virtual void close() = 0;

protected:
    InputStream() = default;

private:
    InputStream(const InputStream&) = delete;
    InputStream& operator=(const InputStream&) = delete;
};

/// Base class for output streams
class OutputStream {
public:
    virtual ~OutputStream() = default;

    /// Writes the given data to the stream
    /// \param source Pointer to the data to write
    /// \param count The number of bytes to write to the stream
    virtual void write(const void* source, const Size count) = 0;

    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the
    /// requested destination. This function flushes this buffer so it reaches the destination immediately.
    virtual void flush() = 0;

    virtual void close() = 0;

protected:
    OutputStream() = default;

private:
    OutputStream(const OutputStream&) = delete;
    OutputStream& operator=(const OutputStream&) = delete;
};

class FileInputStream : public InputStream {
public:
    /// Opens the given file for reading
    explicit FileInputStream(String fileName)
        : mFile(File::open(std::move(fileName), File::OpenMode::READ)) {}

    Size read(void* output, const Size count) override { return mFile.read(output, count); }

    bool eof() const override { return mFile.eof(); }

    void close() override { mFile.close(); }

private:
    File mFile;
};

class FileOutputStream : public OutputStream {
public:
    enum class OpenMode { OVERWRITE, APPEND };

public:
    ~FileOutputStream() noexcept {
        try {
            flush();
        } catch (...) {
        }
    }

    /// Opens the given file in the given mode
    explicit FileOutputStream(String fileName, const OpenMode mode = OpenMode::OVERWRITE)
        : mFile(File::open(std::move(fileName), toBaseOpenMode(mode))) {}

    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the
    /// requested destination. This function flushes this buffer so it reaches the destination immediately.
    void flush() override { mFile.flush(); }

    void write(const void* source, const Size count) override { mFile.write(source, count); }

    void close() override { mFile.close(); }

private:
    static File::OpenMode toBaseOpenMode(const OpenMode mode) {
        switch (mode) {
        case OpenMode::OVERWRITE:
            return File::OpenMode::WRITE;
        case OpenMode::APPEND:
            return File::OpenMode::APPEND;
        default:
            ASSERT(false);
            return File::OpenMode::APPEND; // The least destructive
        }
    }

    File mFile;
};

class StringInputStream : public InputStream {
public:
    StringInputStream() = default;

    explicit StringInputStream(String string)
        : mStream(std::move(string)) {}

    Size read(void* output, const Size count) override {
        mStream.read(static_cast<char*>(output), count);
        return mStream.gcount();
    }

    bool eof() const override { return mStream.eof(); }

    void close() override {}

    String toString() const { return mStream.str(); }

private:
    using sstream = std::basic_istringstream<char, std::char_traits<char>, SecureAllocator<char>>;
    sstream mStream;
};

class StringOutputStream : public OutputStream {
public:
    enum class OpenMode { OVERWRITE, APPEND };

public:
    ~StringOutputStream() noexcept {
        try {
            flush();
        } catch (...) {
        }
    }

    StringOutputStream() = default;

    /// Opens the given file in the given mode
    explicit StringOutputStream(String string, const OpenMode mode = OpenMode::OVERWRITE)
        : mStream(std::move(string), toBaseOpenMode(mode)) {}

    void flush() override { mStream.flush(); }

    void write(const void* source, const Size count) override {
        mStream.write(static_cast<const char*>(source), count);
    }

    void close() override {}

    String toString() const { return mStream.str(); }

    template <typename T>
    StringOutputStream& operator<<(T&& arg) {
        mStream << std::forward<T>(arg);
        return *this;
    }

private:
    static std::ios_base::openmode toBaseOpenMode(const OpenMode mode) {
        switch (mode) {
        case OpenMode::OVERWRITE:
            return std::ostringstream::out;
        case OpenMode::APPEND:
            return std::ostringstream::out | std::ostringstream::ate;
        default:
            ASSERT(false);
            return std::ostringstream::out | std::ostringstream::ate; // The least destructive
        }
    }

    using sstream = std::basic_ostringstream<char, std::char_traits<char>, SecureAllocator<char>>;
    sstream mStream;
};

NAMESPACE_CRYPTO_END

#endif // CPPLIBCRYPTO_IO_STREAM_H_
