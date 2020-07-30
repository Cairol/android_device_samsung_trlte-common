LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)                                                  
LOCAL_SRC_FILES := gps/loc_api.cpp   
LOCAL_MODULE := libshim_loc
LOCAL_MODULE_TAGS := optional
include $(BUILD_SHARED_LIBRARY)
