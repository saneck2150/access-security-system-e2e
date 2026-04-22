#pragma once

// ============================================================
// hw_config.h — Hardware deployment configuration
// !!! EXAMPLE VALUES — edit before deployment !!!
// Values below are from the lab test setup and are NOT production credentials.
// Edit this file to adapt the firmware to a specific device.
// ============================================================

// ---- Network ----
#define HW_WIFI_SSID "TestHost"
#define HW_WIFI_PASS "11111111"
#define HW_SERVER_URL "http://10.124.3.72:8080/api/hw/uid"

// ---- HMAC authentication ----
// 64 hex chars = 32 bytes. Must match server's hw_shared_secret_hex.
#define HW_SECRET_HEX "a7aa5de55ad5ccd6b9d155ded41751cb06276819e8188c062e64350b5966fae3"

// ---- Device identity ----
#define HW_READER_ID 2
#define HW_DOOR_ID 6

// ---- GPIO pins ----
#define HW_PIN_RST 22
#define HW_PIN_SS 21
#define HW_PIN_LED_GREEN 2
#define HW_PIN_BUZZER 15

// ---- LEDC PWM (buzzer) ----
#define HW_LEDC_FREQ 2000     // Hz
#define HW_LEDC_RESOLUTION 8  // bits

// ---- Timing ----
#define HW_RESEND_DELAY_MS 1500   // Min interval between sends of same card (ms)
#define HW_WIFI_TIMEOUT_MS 20000  // WiFi connection timeout (ms)
#define HW_LOOP_DELAY_MS 30       // Main loop polling interval (ms)

// ---- Allow signal ----
#define HW_ALLOW_FREQ_HZ 2000  // Beep frequency (Hz)
#define HW_ALLOW_BEEP_MS 120   // Beep duration (ms)
#define HW_ALLOW_GAP_MS 60     // Delay after beep before LED off (ms)

// ---- Deny signal ----
#define HW_DENY_FREQ_HZ 500  // Beep frequency (Hz)
#define HW_DENY_BEEP_MS 140  // Beep duration (ms)
#define HW_DENY_GAP_MS 60    // Delay after beep before LED off (ms)
#define HW_DENY_PAUSE_MS 80  // Pause between repeat cycles (ms)
