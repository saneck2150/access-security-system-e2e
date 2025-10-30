/*
#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include "arduino_cfg.ino"

WiFiClient client;
MFRC522 nfc(SS_PIN, RST_PIN);

String encrypt(String data) {
  // Простейший шифр для модели, замените своим
  String encrypted = "";
  for (char c : data) {
    encrypted += char(c + 3); // Сдвиг символов
  }
  return encrypted;
}

void setup() {
  Serial.begin(9600);
  SPI.begin();
  nfc.PCD_Init();

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
}

void loop() {
  if (!nfc.PICC_IsNewCardPresent() || !nfc.PICC_ReadCardSerial()) {
    delay(500);
    return;
  }

  String cardID = "";
  for (byte i = 0; i < nfc.uid.size; i++) {
    cardID += String(nfc.uid.uidByte[i], HEX);
  }

  String encryptedMessage = encrypt(cardID);
  Serial.println("Encrypted Message: " + encryptedMessage);

  if (client.connect(server_ip, server_port)) {
    client.println(encryptedMessage);
    client.stop();
  }

  delay(2000); // Задержка перед следующим чтением
}
*/

