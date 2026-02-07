#include <Arduino.h>

#define TXD2 17
#define RXD2 16

// CRC-16 CCITT-FALSE
uint16_t crc16_ccitt_false(const uint8_t* data, int len) {
  uint16_t crc = 0xFFFF;
  for (int i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; j++) {
      if (crc & 0x8000)
        crc = (crc << 1) ^ 0x1021;
      else
        crc <<= 1;
    }
  }
  return crc;
}

void setup() {
  Serial.begin(115200);
  Serial2.begin(921600, SERIAL_8N1, RXD2, TXD2);
}

uint16_t seq = 0;

void loop() {

  uint8_t payload[] = "HELLO";
  uint8_t len = 5;

  uint8_t buf[64];
  int p = 0;

  buf[p++] = 0xB2;       // magic
  buf[p++] = 0xDD;       // type

  buf[p++] = seq & 0xFF;        // seq L
  buf[p++] = seq >> 8;          // seq H

  buf[p++] = len;        // len

  memcpy(&buf[p], payload, len);
  p += len;

  // CRC over type+seq+len+payload (magic 제외)
  uint16_t crc = crc16_ccitt_false(&buf[1], 1 + 2 + 1 + len);

  buf[p++] = crc & 0xFF;       // CRC L
  buf[p++] = crc >> 8;         // CRC H

  Serial2.write(buf, p);

  seq++;

  delay(100);
}

