#ifndef COMMON_STREAM_H_
#define COMMON_STREAM_H_

#include "common/Exception.h"
#include "common/String.h"

#include <cstdio>

NAMESPACE_CRYPTO_BEGIN

// Base class for input streams
class InputStream {
public:
    InputStream() = default;

    virtual ~InputStream() {}

    /// Reads \ref count bytes from input
    /// \param output The destinaion memory to save the data to
    /// \param count The number of bytes to read from the stream
    /// \returns The number of bytes read. This should be equal to \ref count in case \ref count bytes was available in
    /// the stream. If the return value is less than \ref count, EOF must have been reached.
    Size read(void* output, const Size count) {
        ASSERT(output != nullptr || count == 0);
        if (count == 0 || output == nullptr) {
            return 0;
        }
        Byte* destination = reinterpret_cast<Byte*>(output);
        return readImpl(destination, count);
    }

    /// Tells whether or not the stream is at the EOF
    bool eof() const { return eofImpl(); }

protected:
    virtual Size readImpl(void* output, const Size count) = 0;

    virtual bool eofImpl() const = 0;
};

class OutputStream {
public:
    OutputStream() = default;

    virtual ~OutputStream() {}

    /// Writes the given data to the stream
    /// \param source Pointer to the data to write
    /// \param count The number of bytes to write to the stream
    void write(const void* source, const Size count) {
        ASSERT(source != nullptr || count == 0);
        if (source == nullptr || count == 0) {
            return;
        }
        writeImpl(source, count);
    }

    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the requested
    /// destination. This function flushes this buffer so it reaches the destination immediately.
    virtual void flush() = 0;

protected:
    virtual void writeImpl(const void* source, const Size count) = 0;
};

enum class SeekPosition { BEGINNING, CURRENT, END };

class SeekableInputStream : public InputStream {
public:
    /// Returns the position in the input stream
    virtual Size getPosition() const = 0;

    /// Sets the current read position
    /// \param offset The offset from the specified position
    /// \param position The position origin
    void seek(const Size offset, const SeekPosition position = SeekPosition::BEGINNING) {
        return seekImpl(offset, position);
    }

protected:
    virtual void seekImpl(const Size offset, const SeekPosition position) = 0;
};

class SeekableOutputStream : public OutputStream {
public:
    /// Returns the position in the output stream
    virtual Size getPosition() const = 0;

    /// Sets the current write position
    /// \param offset The offset from the specified position
    /// \param position The position origin
    void seek(const Size offset, const SeekPosition position = SeekPosition::BEGINNING) {
        return seekImpl(offset, position);
    }

protected:
    virtual void seekImpl(const Size offset, const SeekPosition position) = 0;
};

class FileStreamBase {
public:
    virtual ~FileStreamBase() {
        if (mFile != nullptr) {
            close();
        }
    }

    /// Closes the file
    void close() {
        if (mFile == nullptr) {
            throw Exception("Closing file that has not been open");
        }
        const int closeResult = fclose(mFile);
        mFile = nullptr;
        mFileName.clear();
        mFileSize = 0;
        if (closeResult != 0) {
            throw Exception("Failed to close file (" + mFileName + ')');
        }
    }

    /// Returns whether or not the file is open
    bool isOpen() const { return mFile != nullptr; }

protected:
    enum class OpenMode {
        READ,
        WRITE,
        APPEND
    };

    FileStreamBase() = default;

    FileStreamBase(FileStreamBase&& other) : mFileName(std::move(other.mFileName)), mFile(other.mFile) {
        other.mFile = nullptr;
    }

    FileStreamBase& operator=(FileStreamBase&& other) {
        if (&other == this) {
            return *this;
        }
        if (mFile != nullptr) {
            close();
        }
        mFileName = std::move(other.mFileName);
        std::swap(mFile, other.mFile);
        return *this;
    }

    /// Opens a file in the given mode
    /// \param filename The path to the file to open
    /// \param mode The mode to open the file in. Could be either READ, WRITE or APPEND
    /// \throws Exception in case the file coudn't be open for any reason
    void open(const String& filename, const OpenMode mode) {
        if (mFile) {
            throw Exception("Opening an instance of FileStream that has already been open. Current file (" + mFileName +
                            ") Requested file (" + filename + ')');
        }

        const char* openFlags = toFileOpenFlags(mode);
        ASSERT(openFlags != nullptr);
        mFile = fopen(filename.c_str(), openFlags);

        if (!mFile) {
            throw Exception("Could not open the file specified (" + filename + ')');
        }

        mFileName = filename;
        seek(0, SeekPosition::END);
        mFileSize = getPosition();
        if (mode != OpenMode::APPEND) {
            seek(0, SeekPosition::BEGINNING);
        }
    }

    /// Returns the position in the current file
    Size getPosition() const {
        if (!isOpen()) {
            throw Exception("Getting position on a FileInputStream that has not been open");
        }
        return ftello(mFile);
    }

    /// Sets the current position in the file
    /// \param offset The offset from the specified position
    /// \param position The position origin
    /// \throws Exception if the file is not open and in case the seek fails
    void seek(const Size offset, const SeekPosition position) {
        if (!isOpen()) {
            throw Exception("Seeking in a FileInputStream that has not been open");
        }
        int whence = 0;
        switch (position) {
        case SeekPosition::BEGINNING:
            ASSERT(offset >= 0);
            whence = SEEK_SET;
            break;
        case SeekPosition::CURRENT:
            whence = SEEK_CUR;
            break;
        case SeekPosition::END:
            ASSERT(offset <= 0);
            whence = SEEK_END;
            break;
        default:
            ASSERT(false);
        }
        if (fseeko(mFile, offset, whence) != 0) {
            throw Exception("Could not seek in the file specified (" + mFileName + ')');
        }
    }

private:
    static const char* toFileOpenFlags(const OpenMode mode) {
        switch (mode) {
            case OpenMode::READ:
                return "rb";
            case OpenMode::WRITE:
                return "wb";
            case OpenMode::APPEND:
                return "ab";
            default:
                ASSERT(false);
                return nullptr;
        }
    }

protected:
    String mFileName;
    FILE* mFile = nullptr;
    Size mFileSize = 0;
};

class FileInputStream : public FileStreamBase, public SeekableInputStream {
public:
    FileInputStream() {}

    /// Opens the given file for reading
    explicit FileInputStream(const String& filename) { open(filename); }

    FileInputStream(FileInputStream&& other) : FileStreamBase(std::move(other)) {}

    FileInputStream& operator=(FileInputStream&& rhs) {
        FileStreamBase::operator=(std::move(rhs));
        return *this;
    }

    /// \copydoc FileInputStream(const String&)
    void open(const String& filename) { FileStreamBase::open(filename, FileStreamBase::OpenMode::READ); }

    /// Returns the file size
    Size getFileSize() const { return mFileSize; }

protected:
    virtual Size getPosition() const override { return FileStreamBase::getPosition(); }

    virtual void seekImpl(const Size offset, SeekPosition position) override {
        Size requestedPosition = 0;
        switch (position) {
        case SeekPosition::BEGINNING:
            requestedPosition = offset;
            break;
        case SeekPosition::CURRENT:
            requestedPosition = getPosition() + offset;
            break;
        case SeekPosition::END:
            requestedPosition = mFileSize + offset;
            break;
        default:
            ASSERT(false);
        }
        if (requestedPosition > mFileSize) {
            throw Exception("Trying to read past the file size");
        }
        FileStreamBase::seek(offset, position);
    }

    virtual Size readImpl(void* output, const Size count) override {
        if (!isOpen()) {
            throw Exception("Trying to read FileInputStream that has not been open");
        }
        return fread(reinterpret_cast<Byte*>(output), 1, count, mFile);
    }

    virtual bool eofImpl() const override {
        if (!isOpen()) {
            throw Exception("Getting EOF on a FileInputStream that has not been open");
        }
        return feof(mFile) != 0;
    }
};

class FileOutputStream : public FileStreamBase, public SeekableOutputStream {
public:
    enum class OpenMode { OVERWRITE, APPEND };

    FileOutputStream() = default;

    ~FileOutputStream() { flush(); }

    /// Opens the given file in the given mode
    explicit FileOutputStream(const String& filename, const OpenMode mode = OpenMode::OVERWRITE) {
        open(filename, mode);
    }

    FileOutputStream(FileOutputStream&& other) : FileStreamBase(std::move(other)) {}

    FileOutputStream& operator=(FileOutputStream&& rhs) {
        FileStreamBase::operator=(std::move(rhs));
        return *this;
    }

    /// \copdoc FileOutputStream(const String&, const OpenMode)
    void open(const String& filename, const OpenMode mode = OpenMode::OVERWRITE) {
        FileStreamBase::open(filename, toBaseOpenMode(mode));
    }

    /// Flushes the stream
    ///
    /// When data is written to some stream, it can be buffered and thus not be written directly to the requested
    /// destination. This function flushes this buffer so it reaches the destination immediately.
    void flush() override {
        if (fflush(mFile) != 0) {
            throw Exception("Failed to flush FileOutputStream");
        }
    }

protected:
    virtual Size getPosition() const override { return FileStreamBase::getPosition(); }

    virtual void seekImpl(const Size offset, SeekPosition position) override { FileStreamBase::seek(offset, position); }

    virtual void writeImpl(const void* source, const Size count) override {
        if (!isOpen()) {
            throw Exception("Writing to FileInputStream that has not been open");
        }
        const auto written = fwrite(reinterpret_cast<const char*>(source), sizeof(char), count, mFile);
        if (written != count) {
            throw Exception("Could not write to the file specified");
        }
    }

private:
    static FileStreamBase::OpenMode toBaseOpenMode(const OpenMode mode) {
        switch (mode) {
        case OpenMode::OVERWRITE:
            return FileStreamBase::OpenMode::WRITE;
        case OpenMode::APPEND:
            return FileStreamBase::OpenMode::APPEND;
        default:
            ASSERT(false);
            return FileStreamBase::OpenMode::APPEND; // The least destructive
        }
    }
};

NAMESPACE_CRYPTO_END

#endif
