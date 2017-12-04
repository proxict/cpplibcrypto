add_executable(sandbox
    main.cpp
)

target_include_directories(sandbox
    PRIVATE ${common_includes}
    PRIVATE ${cipher_includes}
    PRIVATE ${padding_includes}
    PRIVATE ${filemanip_includes}
)

message(STATUS "Includes ${common_includes}")

target_link_libraries(sandbox
    PRIVATE cpplibcrypto
)
