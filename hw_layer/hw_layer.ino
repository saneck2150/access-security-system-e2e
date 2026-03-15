#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include "mbedtls/md.h"
#include "hw_config.h"

// ---- Hardware objects ----
MFRC522 rfid(HW_PIN_SS, HW_PIN_RST);

// ---- Persistent storage ----
Preferences prefs;
uint64_t hwSeq = 0;

String lastUid;
unsigned long lastSendMs = 0;

// ---- HMAC helpers ----

//! Converts hex character to nibble value.
static uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f') return (uint8_t)(10 + c - 'a');
  if (c >= 'A' && c <= 'F') return (uint8_t)(10 + c - 'A');
  return 0;
}

//! Decodes 64-char hex string to 32 bytes.
static void hexToBytes32(const char* hex, uint8_t out[32]) {
  for (int i = 0; i < 32; ++i) {
    out[i] = (hexNibble(hex[i * 2]) << 4) | hexNibble(hex[i * 2 + 1]);
  }
}

//! Computes HMAC-SHA256 and returns 64-char lowercase hex.
static String hmacSha256Hex(const uint8_t key[32], const String& msg) {
  unsigned char mac[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, key, 32,
                  (const unsigned char*)msg.c_str(), msg.length(),
                  mac);

  static const char* H = "0123456789abcdef";
  char hex[65];
  for (int i = 0; i < 32; ++i) {
    hex[i * 2]     = H[(mac[i] >> 4) & 0xF];
    hex[i * 2 + 1] = H[mac[i] & 0xF];
  }
  hex[64] = 0;
  return String(hex);
}

// ---- LED/Buzzer signals ----

static void ledsOff() { digitalWrite(HW_PIN_LED_GREEN, LOW); }

//! Starts LEDC tone at given frequency.
static void ledcToneStart(uint32_t freq) {
  ledcWriteTone(HW_PIN_BUZZER, freq);
}

//! Stops LEDC tone.
static void ledcToneStop() {
  ledcWriteTone(HW_PIN_BUZZER, 0);
}

//! Plays a beep using LEDC PWM.
static void beep(uint32_t freq, uint32_t duration_ms) {
  ledcToneStart(freq);
  delay(duration_ms);
  ledcToneStop();
}

static void signalAllow() {
  ledsOff();
  digitalWrite(HW_PIN_LED_GREEN, HIGH);
  beep(HW_ALLOW_FREQ_HZ, HW_ALLOW_BEEP_MS);
  delay(HW_ALLOW_GAP_MS);
  digitalWrite(HW_PIN_LED_GREEN, LOW);
}

static void signalDeny() {
  ledsOff();
  for (int i = 0; i < 2; ++i) {
    digitalWrite(HW_PIN_LED_GREEN, HIGH);
    beep(HW_DENY_FREQ_HZ, HW_DENY_BEEP_MS);
    delay(HW_DENY_GAP_MS);
    digitalWrite(HW_PIN_LED_GREEN, LOW);
    delay(HW_DENY_PAUSE_MS);
  }
}

static String uidToString(const MFRC522::Uid& uid) {
  String s;
  for (byte i = 0; i < uid.size; i++) {
    if (uid.uidByte[i] < 0x10) s += "0";
    s += String(uid.uidByte[i], HEX);
  }
  s.toUpperCase();
  return s;
}

static void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;

  Serial.print("Connecting to WiFi ");
  Serial.print(HW_WIFI_SSID);
  Serial.println("...");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  WiFi.begin(HW_WIFI_SSID, HW_WIFI_PASS);

  const unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - start) < HW_WIFI_TIMEOUT_MS) {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(" OK");
    Serial.print("IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println(" FAILED");
    Serial.print("WiFi.status() = ");
    Serial.println(WiFi.status());
  }
}

static bool parseAllowFromJson(const String& resp, bool& allowOut) {
  int i = resp.indexOf("\"allow\"");
  if (i < 0) return false;
  i = resp.indexOf(":", i);
  if (i < 0) return false;

  while (i < (int)resp.length() && (resp[i] == ':' || resp[i] == ' ')) i++;

  if (resp.startsWith("true", i))  { allowOut = true;  return true; }
  if (resp.startsWith("false", i)) { allowOut = false; return true; }
  return false;
}

static bool postUidToServer(const String& uid, bool& allowOut) {
  connectWiFi();
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return false;
  }

  // Increment and persist hw_seq (anti-replay)
  hwSeq++;
  prefs.putULong64("hw_seq", hwSeq);

  // Build JSON body with hw_seq
  String body =
    String("{\"uid\":\"") + uid +
    String("\",\"reader_id\":") + String(HW_READER_ID) +
    String(",\"door_id\":") + String(HW_DOOR_ID) +
    String(",\"hw_seq\":") + String((unsigned long long)hwSeq) +
    String("}");

  HTTPClient http;
  WiFiClient client;

  Serial.print("POST ");
  Serial.println(HW_SERVER_URL);
  Serial.print("Body: ");
  Serial.println(body);

  http.begin(client, HW_SERVER_URL);
  http.addHeader("Content-Type", "application/json");

  // Compute and add HMAC signature if secret is configured
  if (HW_SECRET_HEX[0] != '\0' && strlen(HW_SECRET_HEX) == 64) {
    uint8_t key[32];
    hexToBytes32(HW_SECRET_HEX, key);
    String signMsg = String("POST /api/hw/uid\n") + body;
    String sigHex = hmacSha256Hex(key, signMsg);
    http.addHeader("X-HW-Signature", sigHex);
    Serial.print("Sig: ");
    Serial.println(sigHex);
  }

  int code = http.POST(body);
  String resp = (code > 0) ? http.getString() : "";
  http.end();

  Serial.print("HTTP ");
  Serial.println(code);
  if (resp.length()) {
    Serial.print("Resp: ");
    Serial.println(resp);
  }

  if (!(code >= 200 && code < 300)) {
    return false;
  }

  if (!parseAllowFromJson(resp, allowOut)) {
    Serial.println("Bad response JSON (no allow field)");
    return false;
  }
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(HW_PIN_LED_GREEN, OUTPUT);
  ledsOff();

  // Setup LEDC for buzzer (ESP32 Arduino Core 3.x API)
  ledcAttach(HW_PIN_BUZZER, HW_LEDC_FREQ, HW_LEDC_RESOLUTION);

  // Load persistent hw_seq from NVS
  prefs.begin("access", false);
  hwSeq = prefs.getULong64("hw_seq", 0);
  Serial.print("hw_seq loaded: ");
  Serial.println((unsigned long long)hwSeq);

  SPI.begin();
  rfid.PCD_Init(HW_PIN_SS, HW_PIN_RST);

  Serial.println();
  Serial.println("RC522 ready (WiFi + HMAC mode).");
  Serial.println("Place card near the reader...");

  connectWiFi();
}

void loop() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    delay(HW_LOOP_DELAY_MS);
    return;
  }

  String uid = uidToString(rfid.uid);
  Serial.print("UID: ");
  Serial.println(uid);

  unsigned long now = millis();
  if (uid == lastUid && (now - lastSendMs) < HW_RESEND_DELAY_MS) {
    Serial.println("Skip (too soon)");
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    return;
  }

  lastUid = uid;
  lastSendMs = now;

  bool allow = false;
  bool ok = postUidToServer(uid, allow);
  if (ok && allow) {
    Serial.println("ALLOW");
    signalAllow();
  } else {
    Serial.println(ok ? "DENY" : "SEND FAILED");
    signalDeny();
  }

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}
