# update_version.cmake

file(READ "${CMAKE_SOURCE_DIR}/.version.txt" CURRENT_VERSION)
string(STRIP "${CURRENT_VERSION}" CURRENT_VERSION)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${CURRENT_VERSION})
set(MAJOR_VERSION "${CMAKE_MATCH_1}")
set(MINOR_VERSION "${CMAKE_MATCH_2}")

if(NOT DEFINED PATCH_VERSION)
    set(PATCH_VERSION "${CMAKE_MATCH_3}")
else()
    set(PATCH_VERSION "${PATCH_VERSION}")
    set(CURRENT_VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
endif()

# Optionally, update the version only if requested
if(UPDATE_VERSION)
    math(EXPR PATCH_VERSION "${PATCH_VERSION} + 1")

    set(PROJECT_VERSION "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")

    file(WRITE "${CMAKE_SOURCE_DIR}/.version.txt" "${PROJECT_VERSION}")

    message(STATUS "Updated to version ${PROJECT_VERSION}")
else()
    set(PROJECT_VERSION "${CURRENT_VERSION}")
    message(STATUS "Current version is ${PROJECT_VERSION}")
endif()
