# Need CMake 3.16.0
cmake_minimum_required (VERSION 3.16.0)

# The name of the repository
project ("code_gen")

# Set the correct paths
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_PREFIX_PATH ${CMAKE_SOURCE_DIR}/extern/)

# Set compiler warnings
if(MSVC)
    # TODO
else()

    # For clang
    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lrt -std=gnu99 -Wall -Wextra  -Weverything -Wno-declaration-after-statement -Ofast")

    # For GCC
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -O3 -pthread -lpthread")
    add_compile_definitions(__USE_POSIX199309)
    add_compile_options(-Wall -Wextra -Wpointer-arith -Wstrict-prototypes -Wformat-security -Wfloat-equal -Wshadow -Wconversion -pthread -lpthread -Wlogical-not-parentheses -Wnull-dereference)
endif()

# Comment out for Debug mode
set(IS_DEBUG_BUILD CMAKE_BUILD_TYPE STREQUAL "Debug")

# Build code gen with x86_64
add_compile_definitions(BUILD_CODE_GEN_WITH_X86_64)

# Set debug mode
if (${IS_DEBUG_BUILD})
    add_compile_definitions(NDEBUG)
endif()

# Find the log module
if ( NOT "${HAS_LOG}")

    # Add the log directory
    add_subdirectory(${CMAKE_SOURCE_DIR}/extern/log ${CMAKE_SOURCE_DIR}/build/log)

    # Let any parent project know that this project has log
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_LOG true PARENT_SCOPE)
        set(LOG_INCLUDE_DIR ${LOG_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Find the sync module
if ( NOT "${HAS_SYNC}")

    # Add the sync directory
    add_subdirectory(${CMAKE_SOURCE_DIR}/extern/sync ${CMAKE_SOURCE_DIR}/build/sync)

    # Let any parent project know that this project has sync
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_SYNC true PARENT_SCOPE)
        set(SYNC_INCLUDE_DIR ${SYNC_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Find the pack module
if ( NOT "${HAS_PACK}")
    
    # Add the pack directory
    add_subdirectory(${CMAKE_SOURCE_DIR}/extern/pack ${CMAKE_SOURCE_DIR}/build/pack)

    # Let any parent project know that this project has pack
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_PACK true PARENT_SCOPE)
        set(PACK_INCLUDE_DIR ${PACK_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Find the hash cache module
if ( NOT "${HAS_HASH_CACHE}")

    # Add the hash cache directory
    add_subdirectory(${CMAKE_SOURCE_DIR}/extern/hash-cache ${CMAKE_SOURCE_DIR}/build/hash-cache)

    # Let any parent project know that this project has hash cache
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_HASH_CACHE true PARENT_SCOPE)
        set(HASH_CACHE_INCLUDE_DIR ${HASH_CACHE_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Find the dict module
if ( NOT "${HAS_DICT}")
    
    # Add the dict directory
    add_subdirectory(${CMAKE_SOURCE_DIR}/extern/dict ${CMAKE_SOURCE_DIR}/build/dict)

    # Let any parent project know that this project has dict
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_DICT true PARENT_SCOPE)
        set(DICT_INCLUDE_DIR ${DICT_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Add the code_gen project
if ( NOT "${HAS_CODE_GEN}")

    # Log
    message("[code gen] Adding code gen project")
    
    set(CODE_GEN_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

    # Let any parent project know that it has the code_gen project
    if(NOT PROJECT_IS_TOP_LEVEL)
        set(HAS_CODE_GEN true PARENT_SCOPE)
        set(CODE_GEN_INCLUDE_DIR ${CODE_GEN_INCLUDE_DIR} PARENT_SCOPE)
    endif()
endif()

# Add source to the executable
add_executable(code_gen_example "main.c")
add_dependencies(code_gen_example code_gen pack dict hash_cache sync log)
target_include_directories(code_gen_example PUBLIC ${CODE_GEN_INCLUDE_DIR} ${PACK_INCLUDE_DIR} ${SYNC_INCLUDE_DIR} ${LOG_INCLUDE_DIR})
target_link_libraries(code_gen_example code_gen pack dict hash_cache sync log pthread)

# Mac already includes rt, so its not needed on Mac
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	target_link_libraries(code_gen_example rt)
endif()

# Add source to the library
add_library(code_gen SHARED "code_gen.c" "x86_64.c")
add_dependencies(code_gen pack dict hash_cache sync log)
target_include_directories(code_gen PUBLIC ${CODE_GEN_INCLUDE_DIR} ${PACK_INCLUDE_DIR} ${SYNC_INCLUDE_DIR} ${LOG_INCLUDE_DIR})
target_link_libraries(code_gen pack dict hash_cache sync log pthread)

# Mac already includes rt, so its not needed on Mac
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	target_link_libraries(code_gen rt)
endif()

