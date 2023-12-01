include(FindPackageHandleStandardArgs)

find_path(MbedTLS_INCLUDE_DIR mbedtls/ssl.h)
find_library(MbedTLS_LIBRARY mbedtls)
find_library(MbedX509_LIBRARY mbedx509)
find_library(MbedCrypto_LIBRARY mbedcrypto)
find_package_handle_standard_args(MbedTLS DEFAULT_MSG
    MbedTLS_INCLUDE_DIR MbedTLS_LIBRARY MbedX509_LIBRARY MbedCrypto_LIBRARY)
mark_as_advanced(MbedTLS_INCLUDE_DIR MbedTLS_LIBRARY MbedX509_LIBRARY MbedCrypto_LIBRARY)

if (NOT TARGET MbedTLS::MbedTLS)
    add_library(MbedTLS::MbedTLS UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::MbedTLS PROPERTIES
        IMPORTED_LOCATION "${MbedTLS_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    )
endif()

if (NOT TARGET MbedTLS::MbedX509)
    add_library(MbedTLS::MbedX509 UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::MbedX509 PROPERTIES
        IMPORTED_LOCATION "${MbedX509_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    )
endif()

if (NOT TARGET MbedTLS::MbedCrypto)
    add_library(MbedTLS::MbedCrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::MbedCrypto PROPERTIES
        IMPORTED_LOCATION "${MbedCrypto_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MbedTLS_INCLUDE_DIR}"
    )
endif()
