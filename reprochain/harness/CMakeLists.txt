# reprochain/harness/CMakeLists.txt
#
# Builds the libFuzzer + AddressSanitizer harness against an external
# libwebp source tree. The libwebp tree is checked out separately (one
# directory per pin) by reprochain/build.sh, which then invokes this
# CMakeLists once per pin with a different LIBWEBP_SRC and out dir.
#
# Required cache variables (set by build.sh -DXXX=...):
#   LIBWEBP_SRC      : path to a checked-out libwebp source tree (the
#                      git worktree of either the vulnerable or fixed
#                      pin from reprochain/vendor/libwebp/COMMIT_PINS.md)
#   HARNESS_NAME     : output binary name, e.g. fuzz_webp_decode_vuln
#                      or fuzz_webp_decode_fix.
#   LIBWEBP_ARCHIVE  : output static archive name, e.g. libwebp-vuln.a
#                      or libwebp-fix.a (just the basename — emitted
#                      into the current binary dir).
#
# Compiler is fixed to clang/clang++ at the top so this file is honest
# about its requirements; build.sh will refuse to invoke cmake unless
# clang is found.

cmake_minimum_required(VERSION 3.20)

# Force clang. libFuzzer + ASan require clang; gcc -fsanitize=fuzzer
# does not work. We set this BEFORE project() so CMake picks it up.
if(NOT DEFINED ENV{CC})
    set(ENV{CC}  clang)
endif()
if(NOT DEFINED ENV{CXX})
    set(ENV{CXX} clang++)
endif()

project(reprochain_libwebp_harness LANGUAGES C CXX)

# --- required inputs ---------------------------------------------------------

if(NOT DEFINED LIBWEBP_SRC)
    message(FATAL_ERROR "LIBWEBP_SRC must be passed via -DLIBWEBP_SRC=<path>")
endif()
if(NOT DEFINED HARNESS_NAME)
    message(FATAL_ERROR "HARNESS_NAME must be passed via -DHARNESS_NAME=<name>")
endif()
if(NOT DEFINED LIBWEBP_ARCHIVE)
    message(FATAL_ERROR "LIBWEBP_ARCHIVE must be passed via -DLIBWEBP_ARCHIVE=<basename>")
endif()
if(NOT EXISTS "${LIBWEBP_SRC}/src/webp/decode.h")
    message(FATAL_ERROR "LIBWEBP_SRC does not look like a libwebp source tree (missing src/webp/decode.h): ${LIBWEBP_SRC}")
endif()

# --- sanitizer + fuzzer flags ------------------------------------------------
#
# -O1 keeps the optimizer light enough that ASan stack frames stay
# legible while still allowing libwebp's internal inlining/vectorization
# loops to compile. -g preserves source line numbers in the ASan
# report. -fno-omit-frame-pointer makes ASan stack traces actually
# walkable. -fsanitize=address,fuzzer-no-link instruments TUs without
# adding the libFuzzer entrypoint (only the harness TU links it).

set(SANITIZER_FLAGS
    "-O1 -g -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link"
)
set(SANITIZER_LINK_FLAGS
    "-fsanitize=address,fuzzer"
)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${SANITIZER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")

# --- libwebp static archive --------------------------------------------------
#
# We don't use libwebp's own CMakeLists directly — it pulls in encoder,
# mux, and demux paths we don't exercise. We compile only the decoder
# plus supporting utils into a single static archive. The TU list was
# derived by walking WebPDecode entrypoints in the pinned vulnerable
# tree (commit 7ba44f8). If a pin is added in the future that
# restructures the decoder this list may need updating.

set(LIBWEBP_DEC_SOURCES
    "${LIBWEBP_SRC}/src/dec/alpha_dec.c"
    "${LIBWEBP_SRC}/src/dec/buffer_dec.c"
    "${LIBWEBP_SRC}/src/dec/frame_dec.c"
    "${LIBWEBP_SRC}/src/dec/idec_dec.c"
    "${LIBWEBP_SRC}/src/dec/io_dec.c"
    "${LIBWEBP_SRC}/src/dec/quant_dec.c"
    "${LIBWEBP_SRC}/src/dec/tree_dec.c"
    "${LIBWEBP_SRC}/src/dec/vp8_dec.c"
    "${LIBWEBP_SRC}/src/dec/vp8l_dec.c"
    "${LIBWEBP_SRC}/src/dec/webp_dec.c"
)
set(LIBWEBP_DSP_SOURCES
    "${LIBWEBP_SRC}/src/dsp/alpha_processing.c"
    "${LIBWEBP_SRC}/src/dsp/cpu.c"
    "${LIBWEBP_SRC}/src/dsp/dec.c"
    "${LIBWEBP_SRC}/src/dsp/dec_clip_tables.c"
    "${LIBWEBP_SRC}/src/dsp/filters.c"
    "${LIBWEBP_SRC}/src/dsp/lossless.c"
    "${LIBWEBP_SRC}/src/dsp/rescaler.c"
    "${LIBWEBP_SRC}/src/dsp/upsampling.c"
    "${LIBWEBP_SRC}/src/dsp/yuv.c"
)
set(LIBWEBP_UTILS_SOURCES
    "${LIBWEBP_SRC}/src/utils/bit_reader_utils.c"
    "${LIBWEBP_SRC}/src/utils/color_cache_utils.c"
    "${LIBWEBP_SRC}/src/utils/filters_utils.c"
    "${LIBWEBP_SRC}/src/utils/huffman_utils.c"
    "${LIBWEBP_SRC}/src/utils/quant_levels_dec_utils.c"
    "${LIBWEBP_SRC}/src/utils/random_utils.c"
    "${LIBWEBP_SRC}/src/utils/rescaler_utils.c"
    "${LIBWEBP_SRC}/src/utils/thread_utils.c"
    "${LIBWEBP_SRC}/src/utils/utils.c"
)

add_library(webp_static STATIC
    ${LIBWEBP_DEC_SOURCES}
    ${LIBWEBP_DSP_SOURCES}
    ${LIBWEBP_UTILS_SOURCES}
)

target_include_directories(webp_static
    PUBLIC
        "${LIBWEBP_SRC}"
        "${LIBWEBP_SRC}/src"
)

# Some libwebp TUs include "src/dsp/lossless_common.h" expecting the
# upstream define to be set before SSE/NEON paths choose their
# implementation. We compile portable C; turn off the arch dispatch
# explicitly so libwebp's runtime CPU-feature shim doesn't pull in
# files we didn't list.
target_compile_definitions(webp_static PRIVATE
    WEBP_USE_THREAD=0
    # WEBP_DISABLE_STATS removes the global stats counters that confuse
    # libFuzzer's coverage instrumentation when several iterations
    # interleave.
    WEBP_DISABLE_STATS
)

# Rename the archive to the requested basename. CMake puts archives in
# the current binary dir by default; rename it post-build so the build
# script can pick up libwebp-vuln.a / libwebp-fix.a deterministically.
add_custom_command(TARGET webp_static POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:webp_static>"
        "${CMAKE_BINARY_DIR}/${LIBWEBP_ARCHIVE}"
    COMMENT "copy webp_static -> ${LIBWEBP_ARCHIVE}"
)

# --- harness binary ----------------------------------------------------------

add_executable(${HARNESS_NAME}
    "${CMAKE_CURRENT_SOURCE_DIR}/fuzz_webp_decode.cc"
)

target_include_directories(${HARNESS_NAME}
    PRIVATE
        "${LIBWEBP_SRC}"
        "${LIBWEBP_SRC}/src"
)

target_link_libraries(${HARNESS_NAME}
    PRIVATE webp_static
)

# Link with full libFuzzer + ASan runtime for the harness binary only.
set_target_properties(${HARNESS_NAME} PROPERTIES
    LINK_FLAGS "${SANITIZER_LINK_FLAGS}"
)

# --- smoke check tooling sentinel -------------------------------------------
#
# build.sh runs `nm <harness_binary> | grep __asan_init` after build to
# confirm ASan was linked in. This is intentionally checked from the
# script (not from CMake) so a missing nm is reported as a build
# failure with a useful error rather than as a CMake configure failure.
