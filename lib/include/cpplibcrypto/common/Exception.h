#ifndef CPPLIBCRYPTO_COMMON_EXCEPTION_H_
#define CPPLIBCRYPTO_COMMON_EXCEPTION_H_

#include "cpplibcrypto/buffer/String.h"
#include "cpplibcrypto/common/common.h"

#include <utility>

namespace crypto {

/// Object expected to be thrown
///
/// Holds an error message in string format. This message is being dynamically allocated which means this
/// object is not suitable for throwing in situations where memory allocation is failing due its low state
class Exception {
public:
    explicit Exception(String str)
        : mStr(std::move(str)) {}

    virtual ~Exception() = default;

    Exception(Exception&&) = default;

    /// Returns a reference to the message telling what went wrong
    virtual const String& what() const noexcept { return mStr; }

private:
    Exception(const Exception&) = delete;
    Exception& operator=(const Exception&) = delete;

    const String mStr;
};

} // namespace crypto

#endif // CPPLIBCRYPTO_COMMON_EXCEPTION_H_
