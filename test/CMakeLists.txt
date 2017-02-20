add_executable(unittests
    main.cpp
    common/SquareTest.cpp
)

target_link_libraries(unittests
    PRIVATE common
    PRIVATE gtest
    PRIVATE gmock
)
