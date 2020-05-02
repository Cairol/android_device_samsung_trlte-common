/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (C) 2016 The Mokee Project
 * Copyright (C) 2016 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "FingerprintHal_apq8084"
#define LOG_NDEBUG 1

#include <errno.h>
#include <endian.h>
#include <inttypes.h>
#include <malloc.h>
#include <string.h>
#include <cutils/log.h>
#include <cutils/sockets.h>
#include <hardware/hardware.h>
#include <hardware/fingerprint.h>
#include <unistd.h>

#include "fp_trlte.h"

#define MAX_COMM_CHARS 128
#define MAX_NUM_FINGERS 5
#define VCS_FINGER_INDEX_ALL 21
#define SOCKET_NAME_SEND "validityservice"
#define SOCKET_NAME_RECEIVE "validityservice_callback"

/******************************************************************************/
static void waitForInit(vcs_fingerprint_device_t* vdev) { //wait for hal connect validity service
    while(!vdev->init)
        sleep(1);
}

static int sendcommand(vcs_fingerprint_device_t* vdev, uint8_t* command, int num) {
    int ret = -1;
    char answer[255];

    pthread_mutex_lock(&vdev->lock);

    if (fd_write(vdev->send_fd, command, num) != num) {
        ALOGE("%s: cannot send command to service", __FUNCTION__);
        //close(vdev->send_fd);
    }
    else if (fd_read(vdev->send_fd, answer, 255))
        ret = atoi(answer);

    pthread_mutex_unlock(&vdev->lock);

    return ret;
}

static int getfingermask(vcs_fingerprint_device_t* vdev) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    uint8_t command_getlist[2] = {CALL_GET_ENROLLED_FINGER_LIST, (uint8_t)vdev->active_gid};
    int ret = sendcommand(vdev, command_getlist, 2);
    ALOGV("%s: current fingermask: %#0x", __FUNCTION__, ret);
    return ret;
}

static int initService(vcs_fingerprint_device_t* vdev) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    while (vdev->send_fd <= 0) {
        pthread_mutex_lock(&vdev->lock);
        vdev->send_fd = socket_local_client(SOCKET_NAME_SEND, ANDROID_SOCKET_NAMESPACE_ABSTRACT,SOCK_STREAM);
        pthread_mutex_unlock(&vdev->lock);
        if (vdev->send_fd < 0) {
            ALOGW("%s: cannot open validity service!", __FUNCTION__);
            sleep(1);
        }
    }

    uint8_t command[1] = {CALL_INITSERVICE};
    int ret = sendcommand(vdev, command, 1);
    ALOGV("%s: command CALL_INITSERVICE returned: %x", __FUNCTION__, ret);

    int fingermask = getfingermask(vdev);

    pthread_mutex_lock(&vdev->lock);

    vdev->authenticator_id = fingermask;
    vdev->init = true;

    pthread_mutex_unlock(&vdev->lock);

    return ret;
}

static void send_error_notice(vcs_fingerprint_device_t* vdev, fingerprint_error_t error_info) {
    ALOGV("----------------> %s -----------------> error_info=%d", __FUNCTION__, (int)error_info);

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_ERROR;
    msg.data.error = error_info;

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

static void send_acquired_notice(vcs_fingerprint_device_t* vdev, fingerprint_acquired_info_t acquired_info) {
    ALOGV("----------------> %s -----------------> acqu_info=%d", __FUNCTION__, (int)acquired_info);

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_ACQUIRED;
    msg.data.acquired.acquired_info = acquired_info;

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

static void send_enroll_notice(vcs_fingerprint_device_t* vdev, int fid, int remaining) {
    ALOGV("----------------> %s -----------------> fid %d,remaining=%d", __FUNCTION__, fid, remaining);

    if (fid == 0) {
        ALOGD("Fingerprint ID is zero (invalid)");
        return;
    }
    if (vdev->secure_user_id == 0) {
        ALOGD("Secure user ID is zero (invalid)");
        return;
    }

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_TEMPLATE_ENROLLING;
    msg.data.enroll.finger.fid = fid;
    msg.data.enroll.samples_remaining = remaining;

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->listener.state = STATE_SCAN;
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

static void send_authenticated_notice(vcs_fingerprint_device_t* vdev, int fid) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);

    send_acquired_notice(vdev, FINGERPRINT_ACQUIRED_GOOD);

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_AUTHENTICATED;
    msg.data.authenticated.finger.fid = fid;
    msg.data.authenticated.finger.gid = 0;  // unused
    msg.data.authenticated.hat.version = HW_AUTH_TOKEN_VERSION;
    msg.data.authenticated.hat.authenticator_type =
            htobe32(HW_AUTH_FINGERPRINT);
    msg.data.authenticated.hat.challenge = vdev->op_id;
    msg.data.authenticated.hat.authenticator_id = vdev->authenticator_id;
    msg.data.authenticated.hat.user_id = vdev->secure_user_id;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    msg.data.authenticated.hat.timestamp =
            htobe64((uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

static void send_remove_notice(vcs_fingerprint_device_t* vdev, int fid, int remaining) {
    ALOGV("----------------> %s ----------------->fid=%d,remaining=%d", __FUNCTION__, fid, remaining);

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_TEMPLATE_REMOVED;
    msg.data.removed.finger.fid = fid;
    msg.data.removed.remaining_templates = remaining;

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

static void send_enumerating_notice(vcs_fingerprint_device_t* vdev, int fid, int remaining) {
    ALOGV("----------------> %s ----------------->fid=%d,remaining=%d", __FUNCTION__, fid, remaining);

    fingerprint_msg_t msg = {0};
    msg.type = FINGERPRINT_TEMPLATE_ENUMERATING;
    msg.data.enumerated.finger.fid = fid;
    msg.data.enumerated.finger.gid = (uint32_t)vdev->active_gid;
    msg.data.enumerated.remaining_templates = remaining;

    if (vdev->device.notify) {
        pthread_mutex_lock(&vdev->lock);
        vdev->device.notify(&msg);
        pthread_mutex_unlock(&vdev->lock);
    }
    else
        ALOGD("%s: Notifier callback function not set!", __FUNCTION__);

    return;
}

/******************************************************************************/

static uint64_t get_64bit_rand() {
    uint64_t r = (((uint64_t)rand()) << 32) | ((uint64_t)rand());
    return r != 0 ? r : 1;
}

static uint64_t fingerprint_get_auth_id(struct fingerprint_device* device) {
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    uint64_t authenticator_id = 0;

    waitForInit(vdev);

    authenticator_id = getfingermask(vdev);

    pthread_mutex_lock(&vdev->lock);

    vdev->authenticator_id = authenticator_id;

    pthread_mutex_unlock(&vdev->lock);

    return authenticator_id;
}

static int fingerprint_set_active_group(struct fingerprint_device *device, uint32_t gid,
        const char __unused *path) {
    ALOGV("----------------> %s -----------------> gid=%d,path=%s", __FUNCTION__, gid, path);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    pthread_mutex_lock(&vdev->lock);

    vdev->active_gid = gid;

    pthread_mutex_unlock(&vdev->lock);

    return 0;
}

static int fingerprint_authenticate(struct fingerprint_device *device,
    uint64_t operation_id, __unused uint32_t gid)
{
    ALOGV("----------------> %s -----------------> auth: op_id=%llu", __FUNCTION__, operation_id);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    uint8_t command[2] = {CALL_IDENTIFY, (uint8_t)vdev->active_gid};
    int ret = sendcommand(vdev, command, 2);
    ALOGV("%s: CALL_IDENTIFY command returned: %d", __FUNCTION__, ret);

    pthread_mutex_lock(&vdev->lock);

    vdev->op_id = operation_id;
    vdev->listener.state = STATE_SCAN;

    pthread_mutex_unlock(&vdev->lock);

    // Always return successful
    return 0;
}

static int fingerprint_enroll(struct fingerprint_device *device,
        const hw_auth_token_t *hat,
        uint32_t __unused gid,
        uint32_t __unused timeout_sec) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    if (!hat) {
        ALOGD("%s: null auth token", __FUNCTION__);
        return -EPROTONOSUPPORT;
    }
    if (hat->challenge == vdev->challenge) {
        pthread_mutex_lock(&vdev->lock);
        vdev->secure_user_id = hat->user_id;
        pthread_mutex_unlock(&vdev->lock);
    } else {
        ALOGD("%s: invalid auth token", __FUNCTION__);
    }

    if (hat->version != HW_AUTH_TOKEN_VERSION) {
        return -EPROTONOSUPPORT;
    }
    if (hat->challenge != vdev->challenge && !(hat->authenticator_type & HW_AUTH_FINGERPRINT)) {
        return -EPERM;
    }

    int fingermask = getfingermask(vdev);
    int idx = 1;
    while (((fingermask >> idx) & 1) && idx <= MAX_NUM_FINGERS)
        idx++;
    uint8_t command[3] = {CALL_ENROLL, (uint8_t)vdev->active_gid, (uint8_t)idx};
    int ret = sendcommand(vdev, command, 3);
    ALOGV("%s: CALL_ENROLL command for bit %d returned: %d", __FUNCTION__, idx, ret);
    //fingermask = getfingermask(vdev);
    
    pthread_mutex_lock(&vdev->lock);

    //vdev->authenticator_id = fingermask;
    vdev->user_id = hat->user_id;
    vdev->listener.state = STATE_ENROLL;

    pthread_mutex_unlock(&vdev->lock);

    // workaround to filter out non relevant errors (enrolling works although ret!=0)
    switch (ret) {
        case EINTR: // EINTR 4 Interrupted system call
            ret = 0;
    }

    return -ret;
}

static uint64_t fingerprint_pre_enroll(struct fingerprint_device *device) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    uint64_t challenge = 0;
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    challenge = get_64bit_rand();

    pthread_mutex_lock(&vdev->lock);
    vdev->challenge = challenge;
    pthread_mutex_unlock(&vdev->lock);

    return challenge;
}

static int fingerprint_post_enroll(struct fingerprint_device* device) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    pthread_mutex_lock(&vdev->lock);
    vdev->challenge = 0;
    pthread_mutex_unlock(&vdev->lock);

    return 0;
}

static int fingerprint_cancel(struct fingerprint_device *device) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    uint8_t command[1] = {CALL_CANCEL};
    int ret = sendcommand(vdev, command, 1);
    ALOGV("%s: CALL_CANCEL command returned: %d", __FUNCTION__, ret);

    pthread_mutex_lock(&vdev->lock);

    vdev->listener.state = STATE_IDLE;

    pthread_mutex_unlock(&vdev->lock);

#ifndef CALL_NOTIFY_ON_CANCEL
    // if TARGET_SEC_FP_CALL_NOTIFY_ON_CANCEL=true is set in Makefiles,
    //  the android.hardware.biometrics.fingerprint service will send the cancel error notice
    send_error_notice(vdev, FINGERPRINT_ERROR_CANCELED);
#endif

    return ret;
}

static int fingerprint_enumerate(struct fingerprint_device *device) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    if (device == NULL) {
        ALOGE("Cannot enumerate saved fingerprints with uninitialized device");
        return -1;
    }

    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    int fingermask = getfingermask(vdev);

    // 1st loop to initialize remaining
    int remaining = 0;
    for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++)
        if ((fingermask >> idx) & 1)
            remaining++;
    if (remaining == 0) {
        // no fingerprints found
        send_enumerating_notice(vdev, 0, 0);
    }
    else {
        // 2nd loop to send notice
        for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++)
            if ((fingermask >> idx) & 1)
                send_enumerating_notice(vdev, idx, --remaining);
    }

    return 0;
}

static int fingerprint_remove(struct fingerprint_device *device,
        uint32_t __unused gid, uint32_t fid) {
    int ret = 0;
    ALOGV("----------------> %s -----------------> fid %d", __FUNCTION__, fid);
    if (device == NULL) {
        ALOGE("Can't remove fingerprint (gid=%d, fid=%d); "
              "device not initialized properly",
              gid, fid);
        return -1;
    }

    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    uint8_t command[3] = {CALL_REMOVE, (uint8_t)vdev->active_gid, 0};

    if (fid == 0) {
        // Delete all fingerprint templates
        int fingermask = getfingermask(vdev);
        // 1st loop to initialize remaining
        int remaining = 0;
        for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++)
            if ((fingermask >> idx) & 1)
                remaining++;
        if (remaining != 0) {
            // send command
            command[2] = VCS_FINGER_INDEX_ALL;
            ret = sendcommand(vdev, command, 3);
            ALOGV("%s: CALL_REMOVE command for all templates returned: %d", __FUNCTION__, ret);
            // 2nd loop to send notice
            for (int idx = 1; idx <= MAX_NUM_FINGERS; idx++)
                if ((fingermask >> idx) & 1) {
                    // Send remove notice
                    send_remove_notice(vdev, idx, --remaining);
                }
        }
        pthread_mutex_lock(&vdev->lock);
        vdev->listener.state = STATE_IDLE;
        pthread_mutex_unlock(&vdev->lock);
    } else {
        // Delete one fingerprint template
        command[2] = (uint8_t)fid;
        ret = sendcommand(vdev, command, 3);
        ALOGV("%s: CALL_REMOVE command for fid=%d returned: %d", __FUNCTION__, fid, ret);
        pthread_mutex_lock(&vdev->lock);
        vdev->listener.state = STATE_IDLE;
        pthread_mutex_unlock(&vdev->lock);
        // Send remove notice
        send_remove_notice(vdev, fid, 0);
    }

    if (ret) {
        send_error_notice(vdev, FINGERPRINT_ERROR_UNABLE_TO_REMOVE);
    }

    return ret;
}

static int set_notify_callback(struct fingerprint_device *device,
                               fingerprint_notify_t notify) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    if (device == NULL || notify == NULL) {
        ALOGE("Failed to set notify callback @ %p for fingerprint device %p",
              device, notify);
        return -1;
    }

    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;
    pthread_mutex_lock(&vdev->lock);
    vdev->listener.state = STATE_IDLE;
    vdev->device.notify = notify;
    pthread_mutex_unlock(&vdev->lock);
    ALOGD("%s: fingerprint callback notification set", __FUNCTION__);

    return 0;
}

static worker_state_t getListenerState(vcs_fingerprint_device_t* vdev) {
    worker_state_t state = STATE_IDLE;

    pthread_mutex_lock(&vdev->lock);
    state = vdev->listener.state;
    pthread_mutex_unlock(&vdev->lock);

    return state;
}

static void* listenerSocket(void* data) {
    ALOGI("----------------> %s ----------------->", __FUNCTION__);
    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)data;

    while (vdev->receive_fd <= 0) {
        pthread_mutex_lock(&vdev->lock);
        vdev->receive_fd = socket_local_client(SOCKET_NAME_RECEIVE, ANDROID_SOCKET_NAMESPACE_ABSTRACT,SOCK_STREAM);
        pthread_mutex_unlock(&vdev->lock);
        if (vdev->receive_fd < 0) {
            ALOGD("listener cannot open fingerprint listener service");
            sleep(1);
        }
    }
    initService(vdev);

    pthread_mutex_lock(&vdev->lock);
    vdev->listener.state = STATE_IDLE;
    pthread_mutex_unlock(&vdev->lock);

    int size = 1; // must be initialized to >1
    char buffer[MAX_COMM_CHARS] = {0};
    int type, info, info_ex;
    while (getListenerState(vdev) != STATE_EXIT && size > 0) {
        size = fd_read(vdev->receive_fd, buffer, sizeof(buffer) - 1);
        if (size > 0) {
            buffer[size] = '\0';
            sscanf(buffer, "%d:%d:%d", &type, &info, &info_ex);
            switch (type) {
                case CB_ERROR: //error
                    ALOGV("%s: Received error notice: info=%d, info_ex=%d", __FUNCTION__, info, info_ex);
                    send_error_notice(vdev, info);
                    break;
                case CB_ENROLL: //enroll
                    ALOGV("%s: Received enroll notice: info=%d, info_ex=%d", __FUNCTION__, info, info_ex);
                    send_enroll_notice(vdev, info, info_ex);
                    break;
                case CB_REMOVED: //removed
                    ALOGV("%s: Received removed notice: info=%d, info_ex=%d", __FUNCTION__, info, info_ex);
                    send_remove_notice(vdev, info, info_ex);
                    break;
                case CB_ACQUIRED: //acquired
                    ALOGV("%s: Received acquired notice: info=%d, info_ex=%d", __FUNCTION__, info, info_ex);
                    send_acquired_notice(vdev, info);
                    break;
                case CB_AUTHENTICATED: //authenticated
                    ALOGV("%s: Received authenticated notice: info=%d, info_ex=%d", __FUNCTION__, info, info_ex);
                    send_authenticated_notice(vdev, info);
                    break;
                default:
                    ALOGW("%s: Received unknown (type=%d) notice: info=%d, info_ex=%d", __FUNCTION__, type, info, info_ex);
            }
        } else {
            ALOGE("%s: fingerprint listener receive failure", __FUNCTION__);
        }
    }

    if (getListenerState(vdev) == STATE_EXIT) {
        ALOGD("Received request to exit listener thread");
    }

    ALOGD("Listener exit !!");
    return NULL;
}

static int fingerprint_close(hw_device_t* device) {
    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    if (device == NULL) {
        ALOGE("fingerprint hw device is NULL");
        return -1;
    }

    vcs_fingerprint_device_t* vdev = (vcs_fingerprint_device_t*)device;

    waitForInit(vdev);

    pthread_mutex_lock(&vdev->lock);

    // Ask listener thread to exit
    vdev->listener.state = STATE_EXIT;

    pthread_mutex_unlock(&vdev->lock);

    uint8_t command[1] = {CALL_CLEANUP};
    int ret = sendcommand(vdev, command, 1);
    ALOGV("%s: CALL_CLEANUP command returned: %d", __FUNCTION__, ret);

    pthread_join(vdev->listener.thread, NULL);
    pthread_mutex_destroy(&vdev->lock);
    close(vdev->send_fd);
    free(vdev);

    return 0;
}

static int fingerprint_open(const hw_module_t* module, const char __unused *id,
                            hw_device_t** device)
{

    ALOGV("----------------> %s ----------------->", __FUNCTION__);
    if (device == NULL) {
        ALOGE("NULL device on open");
        return -EINVAL;
    }
    vcs_fingerprint_device_t *vdev = (vcs_fingerprint_device_t*)calloc(
            1, sizeof(vcs_fingerprint_device_t));

    if (vdev == NULL) {
        ALOGE("Insufficient memory for fingerprint device");
        return -ENOMEM;
    }

    vdev->device.common.tag = HARDWARE_DEVICE_TAG;
    vdev->device.common.version = FINGERPRINT_MODULE_API_VERSION_2_1;
    vdev->device.common.module = (struct hw_module_t*)module;
    vdev->device.common.close = fingerprint_close;

    vdev->device.pre_enroll = fingerprint_pre_enroll;
    vdev->device.enroll = fingerprint_enroll;
    vdev->device.post_enroll = fingerprint_post_enroll;
    vdev->device.get_authenticator_id = fingerprint_get_auth_id;
    vdev->device.set_active_group = fingerprint_set_active_group;
    vdev->device.authenticate = fingerprint_authenticate;
    vdev->device.cancel = fingerprint_cancel;
    vdev->device.enumerate = fingerprint_enumerate;
    vdev->device.remove = fingerprint_remove;
    vdev->device.set_notify = set_notify_callback;
    vdev->device.notify = NULL;

    vdev->active_gid = 0;
    vdev->init = false;

    pthread_mutex_init(&vdev->lock, NULL);
    if (pthread_create(&vdev->listener.thread, NULL, listenerSocket, vdev) != 0)
        return -1;

    // wait for init
    waitForInit(vdev);

    *device = &vdev->device.common;

    return 0;
}

static struct hw_module_methods_t fingerprint_module_methods = {
    .open = fingerprint_open,
};

fingerprint_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag                = HARDWARE_MODULE_TAG,
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_1,
        .hal_api_version    = HARDWARE_HAL_API_VERSION,
        .id                 = FINGERPRINT_HARDWARE_MODULE_ID,
        .name               = "TRLTE Fingerprint HAL",
        .author             = "ljzyal(ljzyal@gmail.com)",
        .methods            = &fingerprint_module_methods,
    },
};
