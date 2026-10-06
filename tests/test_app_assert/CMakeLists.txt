cmake_minimum_required(VERSION 3.21)
include($ENV{XMOS_CMAKE_PATH}/xcommon.cmake)

project(test_app_assert)

set(APP_COMMON_BUILD_FLAGS
    -O3
    -g
    -report
    -Wall
    -DLIBXCORE_XASSERT_IS_ASSERT
)

set(XMOS_SANDBOX_DIR        ${CMAKE_CURRENT_LIST_DIR}/../..)

set(APP_HW_TARGET           XK-EVK-XU416)

set(APP_COMPILER_FLAGS      ${APP_COMMON_BUILD_FLAGS})


XMOS_REGISTER_APP()
