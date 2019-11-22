cmake_minimum_required(VERSION 2.6)

project(Coverage)

find_package(DynamoRIO REQUIRED)

add_library(coverage SHARED
  coverage.c
  )

configure_DynamoRIO_client(coverage)

use_DynamoRIO_extension(coverage drmgr)
use_DynamoRIO_extension(coverage drx)
use_DynamoRIO_extension(coverage drcontainers)
use_DynamoRIO_extension(coverage drreg)
use_DynamoRIO_extension(coverage drwrap)
use_DynamoRIO_extension(coverage drsyms)


if(WIN32)
  # VS2015 Fix
  if(NOT (MSVC_VERSION LESS 1900))
    target_link_libraries(coverage "libucrt.lib")
    target_link_libraries(coverage "libvcruntime.lib")
  endif()
else()
  set(CMAKE_C_FLAGS   "-g -w")
endif()



