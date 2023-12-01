cmake_minimum_required(VERSION 3.10)
project(thttp LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
find_package(MbedTLS REQUIRED)

add_library(thttp STATIC  thttp.c
                             tinyhttp/chunk.c
                             tinyhttp/header.c
                             tinyhttp/http.c
                             jsmn/jsmnutil.c
                             jsmn/jsmn.c
                             trest.c
                             trail.c)

target_link_libraries(thttp PRIVATE
    MbedTLS::MbedTLS
    MbedTLS::MbedX509
    MbedTLS::MbedCrypto
)

install(TARGETS thttp
        LIBRARY DESTINATION lib)

install(FILES thttp.h
              thttp-enums.h
              trest.h
              trail.h
        DESTINATION include)

install(FILES jsmn/jsmnutil.h
              jsmn/jsmn.h
        DESTINATION include/jsmn)

install(DIRECTORY certs/
        DESTINATION /certs)

