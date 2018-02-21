#ifndef FILEMANIP_UTILS_H_
#define FILEMANIP_UTILS_H_

#include "common/Exception.h"
#include "common/Stream.h"
#include "common/String.h"

NAMESPACE_CRYPTO_BEGIN
namespace utils {

/// Returns whether or not the file specified exists
inline bool fileExists(const String& filename) {
    try {
        FileInputStream(filename);
    } catch (const Exception& e) {
        return false;
    }
    return true;
}

/// Returns the size of the file specified
/// \throws Exceotion in case the file doesn't exist
inline Size getFileSize(const String& filename) {
    FileInputStream input(filename);
    return input.getFileSize();
}

} // namespace utils
NAMESPACE_CRYPTO_END

#endif
