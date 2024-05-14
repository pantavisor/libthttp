LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libthttp
LOCAL_DESCRIPTION := trest C library
LOCAL_LIBRARIES := mbedtls

include $(BUILD_CMAKE)

include $(CLEAR_VARS)
LOCAL_MODULE := thttp-example1-tls
LOCAL_DESCRIPTION := thttp example 1 tls
LOCAL_LIBRARIES := mbedtls libthttp
LOCAL_LDFLAGS := --static
LOCAL_SRC_FILES := $(LOCAL_MODULE).c
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := trest-example1-tls
LOCAL_DESCRIPTION := trest example 1 tls
LOCAL_LIBRARIES := mbedtls libthttp
LOCAL_LDFLAGS := --static
LOCAL_SRC_FILES := $(LOCAL_MODULE).c
include $(BUILD_EXECUTABLE)
