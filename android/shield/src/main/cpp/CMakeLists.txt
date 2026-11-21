cmake_minimum_required(VERSION 3.22.1)
project(forgemirror LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_C_VISIBILITY_PRESET hidden)
add_link_options(-Wl,-z,max-page-size=16384)
add_library(shield_core SHARED core.cpp)
add_library(shield_dummy SHARED dummy.cpp)
add_library(shield_boot SHARED boot.cpp selfdecrypt.c native_loader.cpp elf_loader.cpp tls_runtime.cpp)
target_link_options(shield_boot PRIVATE -Wl,-init=fm_selfdecrypt_init -Wl,-u,fm_selfdecrypt_init)
add_library(abi_compile_check OBJECT abi_compile_check.c)

file(GLOB YARA_CORE_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/tlshc/*.c)
list(APPEND YARA_CORE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/proc/none.c)
file(GLOB YARA_MODULE_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/tests/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/math/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/time/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/console/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/string/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/dex/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/elf/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/modules/hash/*.c)
add_library(yara STATIC ${YARA_CORE_SOURCES} ${YARA_MODULE_SOURCES})
target_include_directories(yara
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/yara/libyara)
target_compile_definitions(yara PRIVATE DEX_MODULE ELF_MODULE HASH_MODULE USE_NO_PROC BUCKETS_256 CHECKSUM_3B)
target_compile_options(yara PRIVATE -w)

add_library(shield_yara SHARED yara_jni.cpp selfdecrypt.c)
target_link_options(shield_yara PRIVATE -Wl,-init=fm_selfdecrypt_init -Wl,-u,fm_selfdecrypt_init)
target_include_directories(shield_yara PRIVATE include)
target_link_libraries(shield_yara PRIVATE yara log)
target_compile_options(shield_yara PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
target_link_options(shield_yara PRIVATE -Wl,-z,relro -Wl,-z,now)

if(ANDROID_ABI STREQUAL "x86_64")
    set(DOBBY_GENERATE_SHARED OFF CACHE BOOL "" FORCE)
    add_subdirectory(third_party/dobby)
    add_library(shield_hook SHARED file_hooks.cpp selfdecrypt.c)
    target_link_options(shield_hook PRIVATE -Wl,-init=fm_selfdecrypt_init -Wl,-u,fm_selfdecrypt_init)
    target_link_libraries(shield_hook PRIVATE dobby log dl)
    target_compile_definitions(shield_hook PRIVATE FM_HOOK_DOBBY=1)
    target_compile_options(shield_hook PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
    target_link_options(shield_hook PRIVATE -Wl,-z,relro -Wl,-z,now)
elseif(ANDROID_ABI STREQUAL "arm64-v8a" OR ANDROID_ABI STREQUAL "armeabi-v7a")
    add_subdirectory(third_party/shadowhook)
    add_library(shield_hook SHARED file_hooks.cpp selfdecrypt.c)
    target_link_options(shield_hook PRIVATE -Wl,-init=fm_selfdecrypt_init -Wl,-u,fm_selfdecrypt_init)
    target_include_directories(shield_hook PRIVATE third_party/shadowhook/include)
    target_link_libraries(shield_hook PRIVATE shadowhook log dl)
    target_compile_options(shield_hook PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
    target_link_options(shield_hook PRIVATE -Wl,-z,relro -Wl,-z,now)
endif()

foreach(target shield_core shield_boot shield_dummy abi_compile_check)
    target_include_directories(${target} PRIVATE include)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -fstack-protector-strong)
endforeach()
foreach(target shield_core shield_boot shield_dummy)
    target_link_options(${target} PRIVATE -Wl,-z,relro -Wl,-z,now)
endforeach()
add_dependencies(shield_boot shield_core)
target_link_libraries(shield_boot PRIVATE log dl)
