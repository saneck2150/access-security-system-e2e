#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

// Wokwi WiFi TEST 
static const char* WIFI_SSID = "Wokwi-GUEST";
static const char* WIFI_PASS = "";
static const int WIFI_CH = 6;

// webhook.site URL TEST
static const char* SERVER_URL = "https://webhook.site/f247765a-bb46-46fd-a45c-f834dfec993b";

// RC522 
constexpr uint8_t SS_PIN  = 5;  
constexpr uint8_t RST_PIN = 21;  
MFRC522 rfid(SS_PIN, RST_PIN);

// UTILS
constexpr uint8_t LED_GREEN = 2;  // allow
constexpr uint8_t LED_RED   = 4;  // deny
constexpr uint8_t BUZZER    = 15;

String lastUid;
unsigned long lastSendMs = 0;
const unsigned long RESEND_DELAY_MS = 1500;

static void ledsOff() {
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED, LOW);
}

static void signalAllow() {
  ledsOff();
  digitalWrite(LED_GREEN, HIGH);
  tone(BUZZER, 2000, 120);
  delay(180);
  digitalWrite(LED_GREEN, LOW);
}

static void signalDeny() {
  ledsOff();
  digitalWrite(LED_RED, HIGH);
  for (int i = 0; i < 2; i++) {
    tone(BUZZER, 500, 140);
    delay(220);
  }
  digitalWrite(LED_RED, LOW);
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
  Serial.print("...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS, WIFI_CH);

  while (WiFi.status() != WL_CONNECTED) {
    delay(200);
    Serial.print(".");
  }
  Serial.println(" OK");
  Serial.print("IP: ");
  Serial.println(WiFi.localIP());
}

static bool postUidToWebhook(const String& uid) {
  connectWiFi();
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return false;
  }

  String body =
    String("{\"uid\":\"") + uid +
    String("\",\"ts_ms\":") + String(millis()) +
    String("}");

  HTTPClient http;
  WiFiClientSecure client;
  client.setInsecure();

  Serial.print("POST ");
  Serial.println(SERVER_URL);
  Serial.print("Body: ");
  Serial.println(body);

  http.begin(client, SERVER_URL);
  http.addHeader("Content-Type", "application/json");

  int code = http.POST(body);
  String resp = (code > 0) ? http.getString() : "";

  http.end();

  if (code > 0) {
    Serial.print("HTTP ");
    Serial.println(code);
    if (resp.length()) {
      Serial.print("Resp: ");
      Serial.println(resp);
    }
    return (code >= 200 && code < 400);
  } else {
    Serial.print("HTTP failed: ");
    Serial.println(http.errorToString(code));
    return false;
  }
}


void setup() {
  Serial.begin(115200);
  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_RED, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  ledsOff();

  SPI.begin(18, 19, 23, SS_PIN);
  rfid.PCD_Init();                
  Serial.println("MFRC522 Ready");

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

  bool ok = postUidToWebhook(uid);
  if (ok) signalAllow();
  else    signalDeny();

  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
}