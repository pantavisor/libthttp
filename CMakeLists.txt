cmake_minimum_required(VERSION 3.10)
project(thttp LANGUAGES C)

include(FindPackageHandleStandardArgs)

find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)
find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)


include_directories(${MBEDTLS_INCLUDE_DIR})

add_library(thttp STATIC  thttp.c
                             tinyhttp/chunk.c
                             tinyhttp/header.c
                             tinyhttp/http.c
                             jsmn/jsmnutil.c
                             jsmn/jsmn.c
                             trest.c
                             trail.c)

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

