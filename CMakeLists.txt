cmake_minimum_required(VERSION 3.16)

project(libdedsec VERSION 1.0.0 LANGUAGES C)

include(CTest)

set(LIBDEDSEC_SOURCES
    src/core.c
    src/utf8.c
    src/features.c
    src/search.c
    src/module_encoding.c
    src/module_unicode.c
    src/module_layout.c
    src/module_surface.c
    src/module_structure.c
    src/module_markdown.c
)

add_library(dedsec STATIC ${LIBDEDSEC_SOURCES})
add_library(libdedsec::dedsec ALIAS dedsec)

target_include_directories(dedsec
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(dedsec PUBLIC c_std_11)
target_compile_options(dedsec PRIVATE -pedantic -Wall -Wextra -Werror)

if(BUILD_TESTING)
    add_executable(dedsec_tests tests/test.c)
    target_link_libraries(dedsec_tests PRIVATE libdedsec::dedsec)
    target_compile_options(dedsec_tests PRIVATE -pedantic -Wall -Wextra -Werror)
    add_test(NAME dedsec_tests COMMAND dedsec_tests)
endif()
