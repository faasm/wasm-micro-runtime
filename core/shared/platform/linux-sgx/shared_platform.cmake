# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

add_definitions(-DBH_PLATFORM_LINUX_SGX)

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

if ("$ENV{SGX_SDK}" STREQUAL "")
  set (SGX_SDK_DIR "/opt/intel/sgxsdk")
else()
  set (SGX_SDK_DIR $ENV{SGX_SDK})
endif()

#We must include these dependencies in src/sgx/CMakeLists.txt to handle the different include scopes
#include_directories (${SGX_SDK_DIR}/include)
#if (NOT BUILD_UNTRUST_PART EQUAL 1)
  #include_directories (${SGX_SDK_DIR}/include/tlibc
  #                     ${SGX_SDK_DIR}/include/libcxx)
#endif ()

if (NOT WAMR_BUILD_THREAD_MGR EQUAL 1)
  add_definitions(-DSGX_DISABLE_PTHREAD)
endif ()

file (GLOB source_all ${PLATFORM_SHARED_DIR}/*.c)

if (NOT WAMR_BUILD_LIBC_WASI EQUAL 1)
  add_definitions(-DSGX_DISABLE_WASI)
else()
  list(APPEND source_all
      ${PLATFORM_SHARED_DIR}/../common/posix/posix_file.c
      ${PLATFORM_SHARED_DIR}/../common/posix/posix_clock.c
  )
  include (${CMAKE_CURRENT_LIST_DIR}/../common/libc-util/platform_common_libc_util.cmake)
  set(source_all ${source_all} ${PLATFORM_COMMON_LIBC_UTIL_SOURCE})
endif()

include (${CMAKE_CURRENT_LIST_DIR}/../common/memory/platform_api_memory.cmake)
set (source_all ${source_all} ${PLATFORM_COMMON_MEMORY_SOURCE})

file (GLOB source_all_untrusted ${PLATFORM_SHARED_DIR}/untrusted/*.c)

set (PLATFORM_SHARED_SOURCE ${source_all})

set (PLATFORM_SHARED_SOURCE_UNTRUSTED ${source_all_untrusted})

