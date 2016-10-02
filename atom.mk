
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libthttp
LOCAL_MODULE_FILENAME := $(LOCAL_MODULE).done
LOCAL_CATEGORY_PATH := system

LIBTHTTP_CFLAGS := \
	$(TARGET_GLOBAL_CFLAGS) \
	-Wno-sign-compare -Wno-error=format-security -static \
	$(call normalize-c-includes,$(TARGET_GLOBAL_C_INCLUDES))

LIBTHTTP_SRC_DIR := $(LOCAL_PATH)
LIBTHTTP_BUILD_DIR := $(call local-get-build-dir)

# Make arguments
LIBTHTTP_MAKE_ARGS := \
	ARCH=$(TARGET_ARCH) \
	CC="$(CCACHE) $(TARGET_CC)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	CROSS="$(TARGET_CROSS)" \
	CONFIG_PREFIX="$(TARGET_OUT_STAGING)" \
	PREFIX="$(TARGET_OUT_STAGING)" \
	CFLAGS="$(LIBTHTTP_CFLAGS)" \
	LDFLAGS="$(TARGET_GLOBAL_LDFLAGS)" \
	V=$(V)

# Build
$(LIBTHTTP_BUILD_DIR)/$(LOCAL_MODULE_FILENAME):
	@echo "Building libthttp"
	$(Q) $(MAKE) $(LIBTHTTP_MAKE_ARGS) -C $(LIBTHTTP_SRC_DIR) 
	@echo "Installing libthttp"
	$(Q) $(MAKE) $(LIBTHTTP_MAKE_ARGS) -C $(LIBTHTTP_SRC_DIR) install
	@touch $@

# Custom clean rule. LOCAL_MODULE_FILENAME already deleted by common rule
.PHONY: libthttp-clean
libthttp-clean:
	$(Q)if [ -d $(LIBTHTTP_SRC_DIR) ]; then \
		$(MAKE) $(LIBTHTTP_MAKE_ARGS) -C $(LIBTHTTP_SRC_DIR) uninstall \
			|| echo "Ignoring uninstall errors"; \
		$(MAKE) $(LIBTHTTP_MAKE_ARGS) -C $(LIBTHTTP_SRC_DIR) clean \
			|| echo "Ignoring clean errors"; \
	fi

include $(BUILD_CUSTOM)
