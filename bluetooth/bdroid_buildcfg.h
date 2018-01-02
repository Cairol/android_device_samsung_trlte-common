/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (C) 2014 The CyanogenMod Project <http://www.cyanogenmod.org>
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

#ifndef _BDROID_BUILDCFG_H
#define _BDROID_BUILDCFG_H

#define BTM_DEF_LOCAL_NAME              "Samsung Galaxy Note 4"

#define BTE_BLE_STACK_CONF_FILE         "/etc/bluetooth/bt_stack.conf"

#define BTM_WBS_INCLUDED                TRUE
#define BTIF_HF_WBS_PREFERRED           TRUE
#define BLE_VND_INCLUDED                TRUE    /* Toggles support for vendor specific extensions */
#define BTM_SCO_INCLUDED                TRUE    /* TRUE includes SCO code */

/* useful for debugging */
#define BT_TRACE_VERBOSE                TRUE
#define BTM_PM_DEBUG                    TRUE   /* This is set to show debug trace messages for the power manager. */
#define BTA_AG_RESULT_DEBUG             TRUE
#define BTA_AG_DEBUG                    TRUE

#endif
