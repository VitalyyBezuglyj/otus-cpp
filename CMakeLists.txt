cmake_minimum_required(VERSION 3.12)

include(FetchContent)

FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG        e69e5f977d458f2650bb346dadf2ad30c5320281) # 10.2.1
FetchContent_MakeAvailable(fmt)


set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)


option(UPDATE_VERSION "whether to update version in <version.txt>" OFF)
if (UPDATE_VERSION)
    set(UPDATE_VERSION ON)
endif()


# Auto update the version
# Read the version from version.txt
include(${CMAKE_SOURCE_DIR}/cmake/update_version.cmake)

# Now PROJECT_VERSION contains the current version
set(PROJECT_VERSION_PATCH "${PATCH_VERSION}" CACHE INTERNAL "Patch version")
set(PROJECT_VERSION "${PROJECT_VERSION}")
message(STATUS "PROJECT_VERSION_PATCH: ${PROJECT_VERSION_PATCH}")


project(ipfilter VERSION ${PROJECT_VERSION})

option(WITH_GTEST "Whether to build Google test" ON)
message(STATUS "PROJECT_VERSION_PATCH: ${PROJECT_VERSION_PATCH}")

configure_file(${CMAKE_SOURCE_DIR}/lib/version.h.in ${CMAKE_BINARY_DIR}/version.h @ONLY)

add_library(ipfilterlib ipfilter/ipfilter.cpp)
add_library(versionlib lib/lib.cpp)
add_executable(ipfilter_cli main.cpp)

set_target_properties(ipfilter_cli ipfilterlib versionlib PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(versionlib
    PRIVATE 
    "${CMAKE_SOURCE_DIR}"
    "${CMAKE_BINARY_DIR}"
)

target_link_libraries(ipfilterlib PRIVATE fmt::fmt)

target_include_directories(ipfilter_cli PRIVATE "${CMAKE_SOURCE_DIR}")

target_link_libraries(ipfilter_cli PRIVATE
    ipfilterlib
    fmt::fmt
)

if(WITH_GTEST)
    find_package(GTest REQUIRED)
    add_compile_definitions(TEST_FILE_PATH="${CMAKE_BINARY_DIR}/tests/data/ip_filter.tsv")

    # test version
    add_executable(gtest_version tests/gtest_version.cpp)

    target_include_directories(gtest_version PRIVATE "${CMAKE_SOURCE_DIR}" ${GTEST_INCLUDE_DIRS})

    set_target_properties(gtest_version PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )

    target_link_libraries(gtest_version PRIVATE versionlib ${GTEST_LIBRARIES} pthread)

    # test ipfilter
    add_executable(gtest_ipfilter tests/gtest_ipfilter.cpp)

    target_include_directories(gtest_ipfilter PRIVATE "${CMAKE_SOURCE_DIR}" ${GTEST_INCLUDE_DIRS})

    set_target_properties(gtest_ipfilter PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )

    target_link_libraries(gtest_ipfilter PRIVATE ipfilterlib ${GTEST_LIBRARIES} gtest_main pthread ssl crypto fmt::fmt)

endif()

if (MSVC)
    target_compile_options(ipfilter_cli PRIVATE
        /W4
    )

    target_compile_options(ipfilterlib PRIVATE
        /W4)

    target_compile_options(versionlib PRIVATE
        /W4
    )

    if(WITH_GTEST)
        target_compile_options(gtest_version PRIVATE
            /W4
        )

        target_compile_options(gtest_ipfilter PRIVATE
            /W4
        )
    endif()
else ()
    target_compile_options(ipfilter_cli PRIVATE
        -Wall -Wextra -pedantic -Werror
    )

    target_compile_options(ipfilterlib PRIVATE
        -Wall -Wextra -pedantic -Werror
    )

    target_compile_options(versionlib PRIVATE
        -Wall -Wextra -pedantic -Werror
    )
    if(WITH_GTEST)
        target_compile_options(gtest_version PRIVATE
            -Wall -Wextra -pedantic -Werror
        )

        target_compile_options(gtest_ipfilter PRIVATE
            -Wall -Wextra -pedantic -Werror
        )
    endif()
endif()

install(TARGETS ipfilter_cli RUNTIME DESTINATION bin)

# Define a CMake option for package type
set(CPACK_SUPPORTED_GENERATORS "DEB" "RPM" "WIN" "ZIP")
set(PACKAGE_TYPE "DEB" CACHE STRING "Type of package to generate (${CPACK_SUPPORTED_GENERATORS})")

# Validate the PACKAGE_TYPE
if(NOT PACKAGE_TYPE IN_LIST CPACK_SUPPORTED_GENERATORS)
    message(FATAL_ERROR "Unsupported PACKAGE_TYPE: ${PACKAGE_TYPE}. Supported types: ${CPACK_SUPPORTED_GENERATORS}")
endif()

# Set CPack generator based on PACKAGE_TYPE
if(PACKAGE_TYPE STREQUAL "DEB")
    set(CPACK_GENERATOR "DEB")
elseif(PACKAGE_TYPE STREQUAL "RPM")
    set(CPACK_GENERATOR "RPM")
    elseif(PACKAGE_TYPE STREQUAL "WIN")
    set(CPACK_GENERATOR "NSIS")
elseif(PACKAGE_TYPE STREQUAL "ZIP")
    set(CPACK_GENERATOR "ZIP")
else()
    message(FATAL_ERROR "Unsupported PACKAGE_TYPE: ${PACKAGE_TYPE}")
endif()

set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT bevidm@yandex.ru)


# Windows-specific CPack configurations
if(WIN32)
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "Otus-ipfilter")
    set(CPACK_NSIS_DISPLAY_NAME "Otus-ipfilter")
    set(CPACK_NSIS_CONTACT "bevidm@yandex.ru")
    set(CPACK_NSIS_MODIFY_PATH ON)  # Option to modify system PATH
endif()

# Linux-specific dependencies
if(CPACK_GENERATOR STREQUAL "DEB")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-all-dev (>= 1.65.1), libgcc-s1")
elseif(CPACK_GENERATOR STREQUAL "RPM")
    set(CPACK_RPM_PACKAGE_REQUIRES "boost-devel >= 1.65.1, gcc")
endif()

include(CPack)

if(WITH_GTEST)
    file(COPY ${CMAKE_SOURCE_DIR}/tests/data DESTINATION ${CMAKE_BINARY_DIR}/tests)

    enable_testing()
    add_test(gtest_version gtest_version)
    add_test(gtest_ipfilter gtest_ipfilter)
    include(GoogleTest)
    gtest_discover_tests(gtest_version)
endif()
