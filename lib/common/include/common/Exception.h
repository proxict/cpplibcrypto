#ifndef COMMON_EXCEPTION_H_
#define COMMON_EXCEPTION_H_

#include <utility>
#include "common/String.h"
#include "common/common.h"

NAMESPACE_CRYPTO_BEGIN

/// Object expected to be thrown
///
/// Holds an error message in string format. This message is being dynamically allocated which means this object is not
/// suitable for throwing in situations where memory allocation is failing due its low state
class Exception {
public:
    explicit Exception(String str) : mStr(std::move(str)) {}

    virtual ~Exception() = default;

    Exception(Exception&&) = default;
    Exception& operator=(Exception&&) = default;

    /// Returns a reference to the message telling what went wrong
    virtual const String& what() const noexcept { return mStr; }

private:
    Exception(const Exception&) = delete;
    Exception& operator=(const Exception&) = delete;

private:
    const String mStr;
};

NAMESPACE_CRYPTO_END

#endif // COMMON_EXCEPTION_H_
