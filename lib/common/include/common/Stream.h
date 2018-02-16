#ifndef COMMON_STREAM_H_
#define COMMON_STREAM_H_

#include "common/Exception.h"

#include <cstdio>
#include <string>

NAMESPACE_CRYPTO_BEGIN

class InputStream {
public:
    InputStream() = default;

    virtual ~InputStream() {}

    Size read(void* output, const Size count) {
        ASSERT(output != nullptr || count == 0);
        if (count == 0 || output == nullptr) {
            return 0;
        }
        Byte* destination = reinterpret_cast<Byte*>(output);
        return readImpl(destination, count);
    }

    bool eof() const { return eofImpl(); }

protected:
    virtual Size readImpl(void* output, const Size count) = 0;

    virtual bool eofImpl() const = 0;
};

class OutputStream {
public:
    OutputStream() = default;

    virtual ~OutputStream() {}

    void write(const void* source, const Size count) {
        ASSERT(source != nullptr || count == 0);
        if (source == nullptr || count == 0) {
            return;
        }
        writeImpl(source, count);
    }

    virtual void flush() = 0;

protected:
    virtual void writeImpl(const void* source, const Size count) = 0;
};

enum class SeekPosition { BEGINNING, CURRENT, END };

class SeekableInputStream : public InputStream {
public:
    virtual Size getPosition() const = 0;

    void seek(const Size offset, const SeekPosition position = SeekPosition::BEGINNING) {
        return seekImpl(offset, position);
    }

protected:
    virtual void seekImpl(const Size offset, const SeekPosition position) = 0;
};

class SeekableOutputStream : public OutputStream {
public:
    virtual Size getPosition() const = 0;

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

    bool isOpen() const { return mFile != nullptr; }

protected:
    enum OpenMode : int {
        READ = 1 << 0,
        WRITE = 1 << 1,
        APPEND = 1 << 2,
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

    void open(const std::string& filename, const int mode) {
        if (mFile) {
            throw Exception("Opening an instance of FileStream that has already been open. Current file (" + mFileName +
                            ") Requested file (" + filename + ')');
        }

        const char* openMode = nullptr;
        if ((mode & READ) != 0) {
            openMode = "rb";
        } else if ((mode & APPEND) != 0) {
            openMode = "ab";
        } else if ((mode & WRITE) != 0) {
            openMode = "wb";
        }
        ASSERT(openMode != nullptr);

        mFile = fopen(filename.c_str(), openMode);

        if (!mFile) {
            throw Exception("Could not open the file specified (" + filename + ')');
        }

        mFileName = filename;
        seek(0, SeekPosition::END);
        mFileSize = getPosition();
        if ((mode & APPEND) == 0) {
            seek(0, SeekPosition::BEGINNING);
        }
    }

    Size getPosition() const {
        if (!isOpen()) {
            throw Exception("Getting position on a FileInputStream that has not been open");
        }
        return ftello(mFile);
    }

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

    std::string mFileName;
    FILE* mFile = nullptr;
    Size mFileSize = 0;
};

class FileInputStream : public FileStreamBase, public SeekableInputStream {
public:
    FileInputStream() {}

    explicit FileInputStream(const std::string& filename) { open(filename); }

    FileInputStream(FileInputStream&& other) : FileStreamBase(std::move(other)) {}

    FileInputStream& operator=(FileInputStream&& rhs) {
        FileStreamBase::operator=(std::move(rhs));
        return *this;
    }

    void open(const std::string& filename) { FileStreamBase::open(filename, FileStreamBase::READ); }

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

protected:
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

    explicit FileOutputStream(const std::string& filename, const OpenMode mode = OpenMode::OVERWRITE) {
        open(filename, mode);
    }

    FileOutputStream(FileOutputStream&& other) : FileStreamBase(std::move(other)) {}

    FileOutputStream& operator=(FileOutputStream&& rhs) {
        FileStreamBase::operator=(std::move(rhs));
        return *this;
    }

    void open(const std::string& filename, const OpenMode mode = OpenMode::OVERWRITE) {
        FileStreamBase::open(filename, toBaseOpenMode(mode));
    }

    virtual Size getPosition() const override { return FileStreamBase::getPosition(); }

    virtual void seekImpl(const Size offset, SeekPosition position) override { FileStreamBase::seek(offset, position); }

    void flush() override {
        if (fflush(mFile) != 0) {
            throw Exception("Failed to flush FileOutputStream");
        }
    }

protected:
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
            return FileStreamBase::OpenMode::APPEND;
        }
    }
};

NAMESPACE_CRYPTO_END

#endif
