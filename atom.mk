
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := busybox
LOCAL_MODULE_FILENAME := $(LOCAL_MODULE).done
LOCAL_CATEGORY_PATH := system

# Variables
BUSYBOX_DIR := $(LOCAL_PATH)
BUSYBOX_VERSION := 1.20.2
BUSYBOX_ARCHIVE_FILE := $(LOCAL_PATH)/busybox-$(BUSYBOX_VERSION).tar.bz2

# Busybox configuration file
BUSYBOX_CONFIG_FILE := $(call module-get-config,$(LOCAL_MODULE))

BUSYBOX_CFLAGS := \
	$(TARGET_GLOBAL_CFLAGS) \
	-Wno-sign-compare -Wno-error=format-security \
	$(call normalize-c-includes,$(TARGET_GLOBAL_C_INCLUDES))

BUSYBOX_SRC_DIR := $(LOCAL_PATH)
BUSYBOX_BUILD_DIR := $(call local-get-build-dir)

# Make arguments
BUSYBOX_MAKE_ARGS := \
	ARCH=$(TARGET_ARCH) \
	CC="$(CCACHE) $(TARGET_CC)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	CROSS="$(TARGET_CROSS)" \
	CONFIG_PREFIX="$(TARGET_OUT_STAGING)" \
	PREFIX="$(TARGET_OUT_STAGING)" \
	CFLAGS="$(BUSYBOX_CFLAGS)" \
	LDFLAGS="$(TARGET_GLOBAL_LDFLAGS)" \
	V=$(V)

# Copy config in build dir
$(LOCAL_PATH)/.config: $(BUSYBOX_CONFIG_FILE)
	@mkdir -p $(dir $@)
	@cp -af $< $@

# Build
$(BUSYBOX_BUILD_DIR)/$(LOCAL_MODULE_FILENAME): $(BUSYBOX_SRC_DIR)/.config
	@echo "Checking busybox config: $(BUSYBOX_CONFIG_FILE)"
	$(Q) yes "" 2>/dev/null | $(MAKE) $(BUSYBOX_MAKE_ARGS) -C $(BUSYBOX_SRC_DIR) oldconfig
	@echo "Building busybox"
	$(Q) $(MAKE) $(BUSYBOX_MAKE_ARGS) -C $(BUSYBOX_SRC_DIR) SKIP_STRIP=y
	@echo "Installing busybox"
	$(Q) $(MAKE) $(BUSYBOX_MAKE_ARGS) -C $(BUSYBOX_SRC_DIR) install
	@rm -rf $(TARGET_OUT_STAGING)/linuxrc
	@touch $@

# Custom clean rule. LOCAL_MODULE_FILENAME already deleted by common rule
.PHONY: busybox-clean
busybox-clean:
	$(Q)if [ -d $(BUSYBOX_SRC_DIR) ]; then \
		$(MAKE) $(BUSYBOX_MAKE_ARGS) -C $(BUSYBOX_SRC_DIR) uninstall \
			|| echo "Ignoring uninstall errors"; \
		$(MAKE) $(BUSYBOX_MAKE_ARGS) -C $(BUSYBOX_SRC_DIR) clean \
			|| echo "Ignoring clean errors"; \
	fi

include $(BUILD_CUSTOM)
