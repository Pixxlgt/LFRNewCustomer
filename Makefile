ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = LFRNewCustomer
LFRNewCustomer_FILES = Tweak.x
LFRNewCustomer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
LFRNewCustomer_LDFLAGS = -undefined dynamic_lookup
LFRNewCustomer_FRAMEWORKS = Foundation UIKit AdSupport AppTrackingTransparency Security

include $(THEOS_MAKE_PATH)/tweak.mk
