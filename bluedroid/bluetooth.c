/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "bluedroid"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cutils/log.h>
#include <cutils/properties.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <bluedroid/bluetooth.h>

#define HCI_ENABLE_DEVICE_UNDER_TEST_MODE_OGF 0x06
#define HCI_ENABLE_DEVICE_UNDER_TEST_MODE_OCF 0x03
#define HCI_SET_EVENT_FILTER_OGF              0x03
#define HCI_SET_EVENT_FILTER_OCF              0x05
#define HCI_WRITE_SCAN_ENABLE_OGF             0x03
#define HCI_WRITE_SCAN_ENABLE_OCF             0x1A
#define HCI_WRITE_AUTHENTICATION_ENABLE_OGF   0x03
#define HCI_WRITE_AUTHENTICATION_ENABLE_OCF   0x20
#define HCI_WRITE_ENCRYPTION_MODE_OGF         0x03
#define HCI_WRITE_ENCRYPTION_MODE_OCF         0x22

#ifndef HCI_DEV_ID
#define HCI_DEV_ID 0
#endif

#define HCID_STOP_DELAY_USEC 500000
#define DELAY_USEC 2000000

#define MIN(x,y) (((x)<(y))?(x):(y))
#define HCISMD_MOD_PARAM "/sys/module/hci_smd/parameters/hcismd_set"

/*Variables to identify the transport using msm type*/
static char transport_type[PROPERTY_VALUE_MAX];
static int is_transportSMD;

static int rfkill_id = -1;
static char *rfkill_state_path = NULL;

static int init_rfkill() {
    char path[64];
    char buf[16];
    int fd;
    int sz;
    int id;
    for (id = 0; ; id++) {
        snprintf(path, sizeof(path), "/sys/class/rfkill/rfkill%d/type", id);
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            LOGW("open(%s) failed: %s (%d)\n", path, strerror(errno), errno);
            return -1;
        }
        sz = read(fd, &buf, sizeof(buf));
        close(fd);
        if (sz >= 9 && memcmp(buf, "bluetooth", 9) == 0) {
            rfkill_id = id;
            break;
        }
    }

    asprintf(&rfkill_state_path, "/sys/class/rfkill/rfkill%d/state", rfkill_id);
    return 0;
}

static int check_bluetooth_power() {
    int sz;
    int fd = -1;
    int ret = -1;
    char buffer;

    if (rfkill_id == -1) {
        if (init_rfkill()) goto out;
    }

    fd = open(rfkill_state_path, O_RDONLY);
    if (fd < 0) {
        LOGE("open(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
             errno);
        goto out;
    }
    sz = read(fd, &buffer, 1);
    if (sz != 1) {
        LOGE("read(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
             errno);
        goto out;
    }

    switch (buffer) {
    case '1':
        ret = 1;
        break;
    case '0':
        ret = 0;
        break;
    }

out:
    if (fd >= 0) close(fd);
    return ret;
}

static int set_bluetooth_power(int on) {
    int sz;
    int fd = -1;
    int ret = -1;
    const char buffer = (on ? '1' : '0');

    if (rfkill_id == -1) {
        if (init_rfkill()) goto out;
    }

    fd = open(rfkill_state_path, O_WRONLY);
    if (fd < 0) {
        LOGE("open(%s) for write failed: %s (%d)", rfkill_state_path,
             strerror(errno), errno);
        goto out;
    }
    sz = write(fd, &buffer, 1);
    if (sz < 0) {
        LOGE("write(%s) failed: %s (%d)", rfkill_state_path, strerror(errno),
             errno);
        goto out;
    }
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}

static int set_hci_smd_transport(int on) {
    int sz;
    int fd = -1;
    int ret = -1;
    const char buffer = (on ? '1' : '0');

    fd = open(HCISMD_MOD_PARAM, O_WRONLY);
    if (fd < 0) {
        LOGE("open(%s) for write failed: %s (%d)", HCISMD_MOD_PARAM,
             strerror(errno), errno);
        goto out;
    }
    sz = write(fd, &buffer, 1);
    if (sz < 0) {
        LOGE("write(%s) failed: %s (%d)", HCISMD_MOD_PARAM, strerror(errno),
             errno);
        goto out;
    }
    ret = 0;

out:
    if (fd >= 0) close(fd);
    return ret;
}
static inline int create_hci_sock() {
    int sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (sk < 0) {
        LOGE("Failed to create bluetooth hci socket: %s (%d)",
             strerror(errno), errno);
    }
    return sk;
}

int hci_cmd(uint8_t ogf, uint16_t ocf,
            uint16_t params_len, uint8_t *params)
{

    int dd, ret, dev_id = -1;

    LOGI("Getting Device ID");
    dev_id = hci_get_route(NULL);
    if(dev_id < 0) {
        LOGE("No Device found");
        return dev_id;
    }

    dd = hci_open_dev(dev_id);
    if(dd < 0) {
        LOGE("Device open failed");
        return dd;
    }

    LOGV("HCI Command: ogf 0x%02x, ocf 0x%04x, plen %d\n",
          ogf, ocf, params_len);

    if((ret = hci_send_cmd(dd, ogf, ocf, params_len, params)) < 0) {
        LOGE("HCI command send failed");
    } else {
        LOGV("HCI command send success");
        ret = 1;
    }

    hci_close_dev(dd);
    return ret;
}


int bt_enable() {
    LOGV(__FUNCTION__);

    int ret = -1;
    int hci_sock = -1;
    int attempt;
    static int bt_on_once;

    ret = property_get("ro.qualcomm.bt.hci_transport", transport_type, NULL);
    if (ret == 0)
        LOGE("ro.qualcomm.bt.hci_transport not set\n");
    else
        LOGI("ro.qualcomm.bt.hci_transport %s \n", transport_type);

    if (!strcasecmp(transport_type, "smd"))
        is_transportSMD = 1;
    else
        is_transportSMD = 0;

    if (!is_transportSMD)
        if (set_bluetooth_power(1) < 0)
            goto out;

    LOGI("Starting hciattach daemon");
    if (property_set("ctl.start", "hciattach") < 0) {
        LOGE("Failed to start hciattach");
        if (!is_transportSMD)
            set_bluetooth_power(0);
        goto out;
    }

    if (is_transportSMD) {
    /* TODO : added sleep to accomodate the consistant on-time across
       iterations, since hci dev registration happening only 1st iteration */
        if (!bt_on_once)
            bt_on_once = 1;
        else
            usleep(DELAY_USEC);
    }
    // Try for 10 seconds, this can only succeed once hciattach has sent the
    // firmware and then turned on hci device via HCIUARTSETPROTO ioctl
    for (attempt = 1000; attempt > 0;  attempt--) {
        hci_sock = create_hci_sock();
        if (hci_sock < 0) goto out;

        ret = ioctl(hci_sock, HCIDEVUP, HCI_DEV_ID);
        if (!ret) {
            break;
        }
        close(hci_sock);
        usleep(10000);  // 10 ms retry delay
    }
    if (attempt == 0) {
        LOGE("%s: Timeout waiting for HCI device to come up, error- %d, ",
            __FUNCTION__, ret);
        if (!is_transportSMD) {
            if (property_set("ctl.stop", "hciattach") < 0) {
                LOGE("Error stopping hciattach");
            }
            set_bluetooth_power(0);
        }
        goto out;
    }

    LOGI("Starting bluetoothd deamon");
    if (property_set("ctl.start", "bluetoothd") < 0) {
        LOGE("Failed to start bluetoothd");
        if (!is_transportSMD)
            set_bluetooth_power(0);
        goto out;
    }

    ret = 0;

out:
    if (hci_sock >= 0) close(hci_sock);
    return ret;
}

int bt_disable() {
    LOGV(__FUNCTION__);

    int ret = -1;
    int hci_sock = -1;

    LOGI("Stopping bluetoothd deamon");
    if (property_set("ctl.stop", "bluetoothd") < 0) {
        LOGE("Error stopping bluetoothd");
        goto out;
    }
    usleep(HCID_STOP_DELAY_USEC);

    hci_sock = create_hci_sock();
    if (hci_sock < 0) goto out;
    ioctl(hci_sock, HCIDEVDOWN, HCI_DEV_ID);
    if (!is_transportSMD) {
        LOGI("Stopping hciattach deamon");
        if (property_set("ctl.stop", "hciattach") < 0) {
            LOGE("Error stopping hciattach");
            goto out;
        }
    }

    if (!is_transportSMD) {
        if (set_bluetooth_power(0) < 0)
            goto out;
    } else {
        set_hci_smd_transport(0);
    }

    ret = 0;

out:
    if (hci_sock >= 0) close(hci_sock);
    return ret;
}

int bt_is_enabled() {
    LOGV(__FUNCTION__);

    int hci_sock = -1;
    int ret = -1;
    struct hci_dev_info dev_info;

    ret = property_get("ro.qualcomm.bt.hci_transport", transport_type, NULL);
    if (ret == 0)
        LOGE("ro.qualcomm.bt.hci_transport not set\n");
    else
        LOGI("ro.qualcomm.bt.hci_transport %s \n", transport_type);

    if (!strcasecmp(transport_type, "smd"))
        is_transportSMD = 1;
    else
        is_transportSMD = 0;

    // Check power first
    if (!is_transportSMD) {
        ret = check_bluetooth_power();
        if (ret == -1 || ret == 0) goto out;
    }
    ret = -1;

    // Power is on, now check if the HCI interface is up
    hci_sock = create_hci_sock();
    if (hci_sock < 0) goto out;

    dev_info.dev_id = HCI_DEV_ID;
    if (ret = ioctl(hci_sock, HCIGETDEVINFO, (void *)&dev_info) < 0) {
        LOGE("ioctl error: ret=%d", ret);
        ret = 0;
        goto out;
    }

    if (dev_info.flags & (1 << (HCI_UP & 31))) {
        ret = 1;
    } else {
        ret = 0;
    }

out:
    if (hci_sock >= 0) close(hci_sock);
    return ret;
}

int bt_dut_mode_enable() {
    int ret = -1;
    uint8_t cmd_set_event_filter_params[] = {
        /* FILTER_TYPE: 02 - Connection Setup */
        /* FILTER_CONDITION_TYPE: 00 - Allow All Connections */
        /* AUTO ACCEPT FLAG: 02 - Auto accept: Role switch disabled */
        0x02, 0x00, 0x02
    };
    uint8_t cmd_write_scan_enable_params[] = {
        /* SCAN_ENABLE: 3 - PageScan & InquiryScan Enabled */
        0x03
    };
    uint8_t cmd_write_auth_enable_params[] = {
        /* AUTHENTICATION: 0 - Disabled */
        0x00
    };
    uint8_t cmd_write_encrpt_enable_params[] = {
        /* ENCRYPTION MODE: 0 - Disabled */
        0x00
    };

    LOGV(__FUNCTION__);
    if((ret = hci_cmd(HCI_ENABLE_DEVICE_UNDER_TEST_MODE_OGF,
                  HCI_ENABLE_DEVICE_UNDER_TEST_MODE_OCF,
                  0, /* No params */
                  NULL)) < 0) {
        LOGE("HCI_ENABLE_DEVICE_UNDER_TEST_MODE failed");
    } else if((ret = hci_cmd(HCI_SET_EVENT_FILTER_OGF,
                         HCI_SET_EVENT_FILTER_OCF,
                         sizeof(cmd_set_event_filter_params),
                         cmd_set_event_filter_params)) < 0) {
        LOGE("HCI_SET_EVENT_FILTER failed");
    } else if((ret = hci_cmd(HCI_WRITE_SCAN_ENABLE_OGF,
                         HCI_WRITE_SCAN_ENABLE_OCF,
                         sizeof(cmd_write_scan_enable_params),
                         cmd_write_scan_enable_params)) < 0) {
        LOGE("HCI_WRITE_SCAN_ENABLE failed");
    } else if((ret = hci_cmd(HCI_WRITE_AUTHENTICATION_ENABLE_OGF,
                         HCI_WRITE_AUTHENTICATION_ENABLE_OCF,
                         sizeof(cmd_write_auth_enable_params),
                         cmd_write_auth_enable_params)) < 0) {
        LOGE("HCI_WRITE_AUTHENTICATION_ENABLE failed");
    } else if((ret = hci_cmd(HCI_WRITE_ENCRYPTION_MODE_OGF,
                         HCI_WRITE_ENCRYPTION_MODE_OCF,
                         sizeof(cmd_write_encrpt_enable_params),
                         cmd_write_encrpt_enable_params)) < 0) {
        LOGE("HCI_WRITE_ENCRYPTION_MODE failed");
    } else {
        LOGE("Enable DUT mode success");
        ret = 1; //implies enable DUT mode is successful
    }

    return ret;
}

int ba2str(const bdaddr_t *ba, char *str) {
    return sprintf(str, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
                ba->b[5], ba->b[4], ba->b[3], ba->b[2], ba->b[1], ba->b[0]);
}

int str2ba(const char *str, bdaddr_t *ba) {
    int i;
    for (i = 5; i >= 0; i--) {
        ba->b[i] = (uint8_t) strtoul(str, &str, 16);
        str++;
    }
    return 0;
}
