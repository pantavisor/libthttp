LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libthttp
LOCAL_DESCRIPTION := trest C library
LOCAL_LIBRARIES := mbedtls

LOCAL_LDFLAGS := --static

LOCAL_SRC_FILES := thttp.c \
					tinyhttp/chunk.c \
					tinyhttp/header.c \
					tinyhttp/http.c \
					jsmn/jsmnutil.c \
					jsmn/jsmn.c \
					trest.c \
					trail.c

LOCAL_INSTALL_HEADERS := thttp.h \
						thttp-enums.h \
						jsmn/jsmnutil.h:usr/include/jsmn/jsmnutil.h \
						jsmn/jsmn.h:usr/include/jsmn/jsmn.h \
						trest.h \
						trail.h

LOCAL_COPY_FILES := \
					certs/AppSpotGoogleCloudChain-long.pem:certs/ \
					certs/BaltimoreCyberTrustRoot.crt:certs/ \
					certs/DigiCertBaltimoreCA-2G2.crt:certs/ \
					certs/DSTRootCAX3.crt:certs/ \
					certs/"Let'sEncryptAuthorityX3.crt":certs/ \
					certs/localhost.chain.pem:certs/

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := thttp-example1
LOCAL_DESCRIPTION := thttp example 1
LOCAL_LIBRARIES := mbedtls libthttp
LOCAL_LDFLAGS := --static
LOCAL_SRC_FILES := $(LOCAL_MODULE).c
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := thttp-example1-tls
LOCAL_DESCRIPTION := thttp example 1 tls
LOCAL_LIBRARIES := mbedtls libthttp
LOCAL_LDFLAGS := --static
LOCAL_SRC_FILES := $(LOCAL_MODULE).c
include $(BUILD_EXECUTABLE)
