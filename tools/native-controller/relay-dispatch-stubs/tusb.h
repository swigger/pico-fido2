#pragma once
#include <stdint.h>
#include <stdbool.h>
typedef enum { HID_REPORT_TYPE_INVALID, HID_REPORT_TYPE_INPUT, HID_REPORT_TYPE_OUTPUT, HID_REPORT_TYPE_FEATURE } hid_report_type_t;
#define BOARD_TUD_RHPORT 0
#define HID_ASCII_TO_KEYCODE {0,0}
#define KEYBOARD_MODIFIER_LEFTSHIFT 2
#ifdef __cplusplus
extern "C" {
#endif
void tud_init(unsigned port);
bool tud_hid_ready(void);
bool tud_suspended(void);
void tud_remote_wakeup(void);
bool tud_hid_n_keyboard_report(uint8_t itf, uint8_t report, uint8_t modifier, const uint8_t *keys);
bool tud_hid_n_report(uint8_t itf, uint8_t report, const void *bytes, uint16_t length);
#ifdef __cplusplus
}
#endif
