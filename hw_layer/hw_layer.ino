#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>

static const char* WIFI_SSID = "TestHost";
static const char* WIFI_PASS = "11111111";

static const char* SERVER_URL = "http://10.124.3.72:8080/api/hw/uid"; 
static const char* ADMIN_TOKEN = "admin"; 

static const uint32_t READER_ID = 2;
static const uint32_t DOOR_ID   = 6;

constexpr uint8_t RST_PIN = 22;
constexpr uint8_t SS_PIN  = 21;
MFRC522 rfid(SS_PIN, RST_PIN);

constexpr uint8_t LED_GREEN = 2;
constexpr uint8_t BUZZER    = 15;

String lastUid;
unsigned long lastSendMs = 0;
const unsigned long RESEND_DELAY_MS = 1500;

static void ledsOff() { digitalWrite(LED_GREEN, LOW); }

static void signalAllow() {
  ledsOff();
  digitalWrite(LED_GREEN, HIGH);
  tone(BUZZER, 2000, 120);
  delay(180);
  digitalWrite(LED_GREEN, LOW);
}

static void signalDeny() {
  ledsOff();
  for (int i = 0; i < 2; ++i) {
    digitalWrite(LED_GREEN, HIGH);
    tone(BUZZER, 500, 140);
    delay(200);
    digitalWrite(LED_GREEN, LOW);
    delay(80);
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
  Serial.print(WIFI_SSID);
  Serial.println("...");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  WiFi.begin(WIFI_SSID, WIFI_PASS);

  const unsigned long start = millis();
  const unsigned long timeout_ms = 20000;

  while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeout_ms) {
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

  String body =
    String("{\"uid\":\"") + uid +
    String("\",\"reader_id\":") + String(READER_ID) +
    String(",\"door_id\":") + String(DOOR_ID) +
    String(",\"ts_ms\":") + String(millis()) +
    String("}");

  HTTPClient http;
  WiFiClient client;

  Serial.print("POST ");
  Serial.println(SERVER_URL);
  Serial.print("Body: ");
  Serial.println(body);

  http.begin(client, SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  if (ADMIN_TOKEN && ADMIN_TOKEN[0] != '\0') {
    http.addHeader("X-Admin-Token", ADMIN_TOKEN);
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

  pinMode(LED_GREEN, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  ledsOff();

  SPI.begin();             
  rfid.PCD_Init(SS_PIN, RST_PIN);

  Serial.println();
  Serial.println("RC522 ready (WiFi mode).");
  Serial.println("Place card near the reader...");

  connectWiFi();
}

void loop() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    delay(30);
    return;
  }

  String uid = uidToString(rfid.uid);
  Serial.print("UID: ");
  Serial.println(uid);

  unsigned long now = millis();
  if (uid == lastUid && (now - lastSendMs) < RESEND_DELAY_MS) {
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