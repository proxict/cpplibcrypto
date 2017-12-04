add_subdirectory(common)
add_subdirectory(cipher)
add_subdirectory(padding)
add_subdirectory(filemanip)

add_library(cpplibcrypto STATIC
    $<TARGET_OBJECTS:common_objects>
    $<TARGET_OBJECTS:cipher_objects>
    $<TARGET_OBJECTS:filemanip_objects>
    $<TARGET_OBJECTS:padding_objects>
)

target_include_directories(cpplibcrypto
    PUBLIC ${common_includes}
    PUBLIC ${cipher_includes}
    PUBLIC ${padding_includes}
    PUBLIC ${filemanip_includes}
)

