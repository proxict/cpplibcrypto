add_executable(sandbox
    main.cpp
)

target_link_libraries(sandbox
    PRIVATE common
    PRIVATE cipher
    PRIVATE filemanip
)
