# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project Name
project(wakey C)

# --- Compiler Settings (Specifically for GCC) ---
# Set the compiler to GCC explicitly if needed
# set(CMAKE_C_COMPILER gcc)

# Add common warning flags and debug symbols for GCC
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -g")

# Add definitions (optional, enable based on needs)
# add_compile_definitions(DEBUG)         # Enable extra debug logs
# add_compile_definitions(ENABLE_STACKTRACE) # Enable stack traces on error

# --- Source Files ---
# List all your .c source files, now prefixed with src/
set(SOURCES
    src/utils.c
    src/config.c
    src/logger.c
    src/metrics.c
    src/arp_cache.c
    src/network.c
    src/wakey.c
)

# --- Executable ---
# Define the executable target and link the source files
add_executable(wakey ${SOURCES})

# --- Include Directories ---
# Tell CMake where to find the header files (.h)
target_include_directories(wakey PUBLIC includes) # PUBLIC makes includes available to this target

# --- Libraries ---
# Link necessary libraries for POSIX systems
# pthread: For threading (logger, metrics)
# dl: Needed for backtrace_symbols if ENABLE_STACKTRACE is defined
if(UNIX AND NOT APPLE) # Linux specific checks
    find_library(PTHREAD_LIB pthread)
    find_library(DL_LIB dl)
    find_library(RT_LIB rt)

    if(PTHREAD_LIB)
        target_link_libraries(wakey PRIVATE ${PTHREAD_LIB})
        message(STATUS "Linking with pthreads")
    else()
        message(WARNING "pthread library not found!")
    endif()

    if(DL_LIB)
        target_link_libraries(wakey PRIVATE ${DL_LIB})
        message(STATUS "Linking with dl")
    else()
         message(WARNING "dl library not found! Stack traces might not work.")
    endif()

    # Link rt if found (optional)
    # if(RT_LIB)
    #     target_link_libraries(wakey PRIVATE ${RT_LIB})
    #     message(STATUS "Linking with rt")
    # endif()

elseif(APPLE)
    # On macOS, pthread is usually implicitly linked, dl might be too.
     target_link_libraries(wakey PRIVATE "-lpthread" "-ldl")
      message(STATUS "Linking with pthread and dl for macOS")
endif()

# Optional: Install step
# install(TARGETS wakey DESTINATION bin)

# --- Output ---
message(STATUS "Configured wakey project for GCC.")
message(STATUS "Source directory: ${CMAKE_SOURCE_DIR}/src")
message(STATUS "Include directory: ${CMAKE_SOURCE_DIR}/includes")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "C Flags: ${CMAKE_C_FLAGS}")