LOCAL_PATH:= $(call my-dir)


include $(CLEAR_VARS)

LOCAL_SRC_FILES:= main.c data.c ipconfig.c

#LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CFLAGS += -Wall -Wno-unused-parameter -Wextra
# -Wno-implicit-function-declaration
LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog \
    libandroidfw \
    libutils \
    libbinder \
    libjsoncpp

LOCAL_MODULE := ipcnfigstore

include $(BUILD_EXECUTABLE)
