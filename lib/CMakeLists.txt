add_subdirectory(common)
add_subdirectory(cipher)
add_subdirectory(hash)
add_subdirectory(padding)

add_library(cpplibcrypto STATIC
    $<TARGET_OBJECTS:common_objects>
    $<TARGET_OBJECTS:cipher_objects>
    $<TARGET_OBJECTS:hash_objects>
    $<TARGET_OBJECTS:padding_objects>
)

target_include_directories(cpplibcrypto
    PUBLIC ${common_includes}
    PUBLIC ${cipher_includes}
    PUBLIC ${hash_includes}
    PUBLIC ${padding_includes}
)

