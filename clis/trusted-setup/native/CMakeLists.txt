cmake_minimum_required(VERSION "3.17.2")

#-----------------------------------------------------------------------------
# Cross / toolchain settings (c.f. the rust-ffi-demo CMakeLists)
#-----------------------------------------------------------------------------
set(CMAKE_HOST_SYSTEM_PROCESSOR X86_64)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)

# CUDA support is opt-in and requires nvcc on the host. It is *not* wired into
# the kernels yet — see the README for the roadmap.
option(BUILD_BLS_BACKEND_CUDA "Compile the (future) CUDA kernel" OFF)

#-----------------------------------------------------------------------------
# Project settings
#-----------------------------------------------------------------------------
project("bls-backend")

# Native library consumed by the Rust crate through the C ABI in
# include/bls_backend.h (built as a *static* library so the final Rust
# binaries carry no .so dependency).
set(LIBRARY_NAME "bls_backend")
set(LIBRARY_HEADER_FILE "include/bls_backend.h")

#-----------------------------------------------------------------------------
# Vendored blst (Apache-2.0, pinned checkout) — built with its own build.sh
# so the per-arch assembly selection stays upstream-owned.
#-----------------------------------------------------------------------------
set(BLST_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendored/blst")
set(BLST_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}")
set(BLST_LIB "${BLST_BUILD_DIR}/libblst.a")
file(MAKE_DIRECTORY "${BLST_BUILD_DIR}")

file(GLOB BLST_SOURCES
     "${BLST_SRC_DIR}/src/*.c"
     "${BLST_SRC_DIR}/src/*.h"
     "${BLST_SRC_DIR}/build/assembly.S"
     "${BLST_SRC_DIR}/build.sh")

add_custom_command(
  OUTPUT "${BLST_LIB}"
  COMMAND "${CMAKE_COMMAND}" -E env
          "CC=${CMAKE_C_COMPILER}"
          "AR=${CMAKE_AR}"
          "RANLIB=${CMAKE_RANLIB}"
          bash "${BLST_SRC_DIR}/build.sh"
  DEPENDS ${BLST_SOURCES}
  WORKING_DIRECTORY "${BLST_BUILD_DIR}"
  COMMENT "Building vendored blst static library"
  VERBATIM)

add_custom_target(blst_lib ALL DEPENDS "${BLST_LIB}")

#-----------------------------------------------------------------------------
# The native backend library
#-----------------------------------------------------------------------------
add_library("${LIBRARY_NAME}" STATIC "src/bls_backend.cpp")

target_include_directories("${LIBRARY_NAME}" PUBLIC
                           "${CMAKE_CURRENT_SOURCE_DIR}/include"
                           "${BLST_SRC_DIR}/bindings")

add_dependencies("${LIBRARY_NAME}" blst_lib)
target_link_libraries("${LIBRARY_NAME}" PRIVATE "${BLST_LIB}")

if(BUILD_BLS_BACKEND_CUDA)
  target_compile_definitions("${LIBRARY_NAME}" PRIVATE BLS_BACKEND_CUDA)
endif()

#-----------------------------------------------------------------------------
# Tests
#-----------------------------------------------------------------------------
include(CTest)
if(BUILD_TESTING)
  enable_testing()
  add_executable("${LIBRARY_NAME}_tests" "tests/test_bls_backend.cpp")
  target_link_libraries("${LIBRARY_NAME}_tests" PRIVATE "${LIBRARY_NAME}")
  add_test(NAME "${LIBRARY_NAME}_tests" COMMAND "${LIBRARY_NAME}_tests")
endif()

#-----------------------------------------------------------------------------
# Install rules (used when building with CMake directly rather than build.rs)
#-----------------------------------------------------------------------------
install(TARGETS "${LIBRARY_NAME}" DESTINATION lib/)
install(FILES "${LIBRARY_HEADER_FILE}" DESTINATION include/)