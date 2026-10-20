project(darlingserver)

cmake_minimum_required(VERSION 3.13)

option(DSERVER_TOOLS "Build darlingserver tools (for debugging)" OFF)
option(DSERVER_ASAN "Build darlingserver with ASAN" OFF)
option(DSERVER_UBSAN "Build darlingserver with UBSAN" OFF)
if (DSERVER_TOOLS)
	add_subdirectory(tools)
endif()

if (DSERVER_ASAN)
	add_compile_definitions(
		DSERVER_ASAN=1
	)
else()
	add_compile_definitions(
		DSERVER_ASAN=0
	)
endif()

if (DSERVER_UBSAN)
	add_compile_definitions(
		DSERVER_UBSAN=1
	)
else()
	add_compile_definitions(
		DSERVER_UBSAN=0
	)
endif()

set(dserver_sanitizers "")
if (DSERVER_ASAN)
	if (NOT (dserver_sanitizers STREQUAL ""))
		set(dserver_sanitizers "${dserver_sanitizers},")
	endif()
	set(dserver_sanitizers "${dserver_sanitizers}address")
endif()
if (DSERVER_UBSAN)
	if (NOT (dserver_sanitizers STREQUAL ""))
		set(dserver_sanitizers "${dserver_sanitizers},")
	endif()
	set(dserver_sanitizers "${dserver_sanitizers}undefined")
endif()

option(DSERVER_EXTENDED_DEBUG "Build darlingserver with extended debugging support" OFF)

if (DSERVER_EXTENDED_DEBUG)
	add_compile_definitions(
		DSERVER_EXTENDED_DEBUG=1
	)
else()
	add_compile_definitions(
		DSERVER_EXTENDED_DEBUG=0
	)
endif()

# Darling builds with no CMAKE_BUILD_TYPE by default, so with no -O flag at all: clang's -O0. darlingserver is the one
# process every Mach call and trap of every Darling process goes through, so its cost per call is every caller's; XNU
# itself builds at -O2 (makedefs/MakeInc.def). This applies to darlingserver and duct-tape (the targets below; not the
# tools above, nor Darling's libsimple), only when the build chose no optimization itself: no build type, no -O in the
# C or C++ flags, and no debug or sanitizer build. Line tables and frame pointers keep gdb backtraces and perf call
# graphs usable.
option(DSERVER_OPTIMIZE "Build darlingserver and its duct-tape at -O2 when the build sets no optimization" ON)

if (DSERVER_OPTIMIZE AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES
		AND NOT DSERVER_ASAN AND NOT DSERVER_UBSAN AND NOT DSERVER_EXTENDED_DEBUG
		AND NOT "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}" MATCHES "(^| )-O")
	message(STATUS "darlingserver: -O2 (DSERVER_OPTIMIZE)")
	add_compile_options(-O2 -gline-tables-only -fno-omit-frame-pointer)
endif()

# the nice value darlingserver's threads run at (absolute; 0 leaves it unchanged); src/darlingserver.cpp says how
set(DSERVER_NICE "-10" CACHE STRING "Nice value for darlingserver's threads (0 leaves it unchanged)")

option(DSERVER_CALL_HIST "Count darlingserver's calls by number; SIGUSR2 writes them to <prefix>/private/var/log/dserver-callhist.txt" OFF)

if (DSERVER_CALL_HIST)
	add_compile_definitions(
		DSERVER_CALL_HIST=1
	)
endif()

option(DSERVER_SINGLE_THREADED "Only use a single thread per workqueue in darlingserver" ON)

if (DSERVER_SINGLE_THREADED)
	add_compile_definitions(
		DSERVER_SINGLE_THREADED=1
	)
else()
	add_compile_definitions(
		DSERVER_SINGLE_THREADED=0
	)
endif()

add_subdirectory(duct-tape)

set(DARLINGSERVER_INIT_PROCESS "/sbin/launchd" CACHE STRING "The init process darlingserver should execute (default is \"/sbin/launchd\")")
set(DARLINGSERVER_XDG_USER_DIR_CMD "xdg-user-dir" CACHE STRING "The xdg-user-dir binary darlingserver should execute (default is \"xdg-user-dir\")")

include_directories(
	include
	internal-include
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_CURRENT_BINARY_DIR}/internal-include
	${CMAKE_BINARY_DIR}/src/startup # for `rtsig.h`
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
	COMMAND
		${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-rpc-wrappers.py
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
		\"../include/darlingserver/rpc.h\"
	VERBATIM
	MAIN_DEPENDENCY
		${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate-rpc-wrappers.py
)

add_custom_target(generate_dserver_rpc_wrappers
	ALL
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/include/darlingserver/rpc.h
		${CMAKE_CURRENT_BINARY_DIR}/internal-include/darlingserver/rpc.internal.h
		${CMAKE_CURRENT_BINARY_DIR}/src/rpc.c
)

add_executable(darlingserver
	src/darlingserver.cpp
	src/server.cpp
	src/message.cpp
	src/call.cpp
	src/registry.cpp
	src/logging.cpp
	src/process.cpp
	src/thread.cpp
	src/utility.cpp
	src/kqchan.cpp
	src/async-writer.cpp
	src/stack-pool.cpp
	src/memorystatus.cpp
)

add_dependencies(darlingserver
	generate_dserver_rpc_wrappers
	rtsig_h
)

target_link_libraries(darlingserver PRIVATE
	darlingserver_duct_tape
)

target_compile_options(darlingserver PRIVATE
	-pthread
	-std=c++17
)
target_link_options(darlingserver PRIVATE
	-pthread
	-Wl,--gc-sections
)

if (DSERVER_ASAN OR DSERVER_UBSAN)
	target_compile_options(darlingserver PRIVATE
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
		-fno-omit-frame-pointer
		-g
		-Og
	)
	target_link_options(darlingserver PRIVATE
		-fsanitize=${dserver_sanitizers}
		-fsanitize-recover=all
	)
endif()

if (DSERVER_EXTENDED_DEBUG)
	target_compile_options(darlingserver PRIVATE
		-fno-omit-frame-pointer
	)
endif()

install(TARGETS darlingserver DESTINATION bin)

#file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver")
#create_symlink(
#	"${DARLING_ROOT_RELATIVE_TO_SDK}/../../../src/darlingserver/include/darlingserver/rpc.h"
#	"${CMAKE_BINARY_DIR}/${DARLING_SDK_RELATIVE_PATH}/usr/include/darlingserver/rpc.h"
#)

target_compile_definitions(darlingserver PRIVATE
	DSERVER_NICE=${DSERVER_NICE}
)

if (NOT "${DARLINGSERVER_INIT_PROCESS}" STREQUAL "")
	target_compile_definitions(darlingserver PRIVATE
		DARLINGSERVER_INIT_PROCESS="${DARLINGSERVER_INIT_PROCESS}"
	)
endif()

if (NOT "${DARLINGSERVER_XDG_USER_DIR_CMD}" STREQUAL "")
	target_compile_definitions(darlingserver PRIVATE
		DARLINGSERVER_XDG_USER_DIR_CMD="${DARLINGSERVER_XDG_USER_DIR_CMD}"
	)
endif()
