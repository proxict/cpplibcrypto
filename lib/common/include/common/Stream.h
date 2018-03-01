#ifndef COMMON_STREAM_H_
#define COMMON_STREAM_H_

#include <utility>

#include "common/Exception.h"
#include "common/File.h"
#include "common/String.h"

NAMESPACE_CRYPTO_BEGIN

// Base class for input streams
class InputStream {

public:
    virtual ~InputStream() = default;

    /// Reads \ref count bytes from input
    /// \param output The destination memory to save the data to
    /// \param count The number of bytes to read from the stream
    /// \returns The number of bytes read. This should be equal to \ref count in case \ref count bytes was available in
    /// the stream. If the return value is less than \ref count, EOF must have been reached.
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

class OutputStream {

public:
    virtual ~OutputStream() {}

    /// Writes the given data to the stream
    /// \param source Pointer to the data to write
    /// \param count The number of bytes to write to the stream
    virtual void write(const void* source, const Size count) = 0;

    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the requested
    /// destination. This function flushes this buffer so it reaches the destination immediately.
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
    explicit FileInputStream(String fileName) : mFile(File::open(std::move(fileName), File::OpenMode::READ)) {}

    Size read(void* output, const Size count) override {
        return mFile.read(output, count);
    }

    bool eof() const override {
        return mFile.eof();
    }

    void close() override {
        mFile.close();
    }

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
            : mFile(File::open(std::move(fileName), toBaseOpenMode(mode))) {
    }
    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the requested
    /// destination. This function flushes this buffer so it reaches the destination immediately.
    void flush() override {
        mFile.flush();
    }

    void write(const void* source, const Size count) override {
        mFile.write(source, count);
    }

    void close() override {
        mFile.close();
    }

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

private:
    File mFile;
};

NAMESPACE_CRYPTO_END

#endif // COMMON_STREAM_H_
