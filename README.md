# LinkScope BPU UART Analyzer

High-speed UART analyzer using ESP32-S3 + PC GUI.

Real-time capture, framing, statistics, and visualization for embedded debugging.

---

## Demo

![Demo](docs/demo.gif)

---

⚡ Quick Start (1 minute)

1. Flash firmware to ESP32-S3
2. Connect:
   - Target TX → GPIO18
   - Target GND → ESP32-S3 GND
3. Plug ESP32-S3 into USB
4. Run Windows EXE
5. Select COM port
6. Press Start


## Important (Windows): Close Serial Monitor / Other Serial Apps

Only one program can use a COM port at a time.

✅ Before running LinkScope, **close**:
- Arduino IDE Serial Monitor
- PlatformIO Serial Monitor
- PuTTY / TeraTerm
- any other serial terminal/logging tool

If the port is busy, LinkScope may fail to connect or exit immediately.

## Features

- Up to 921600 baud UART capture
- COBS framed binary protocol
- Real-time throughput graph
- RAW hex inspector
- Auto frame decoder
- Health / statistics monitoring
- Windows standalone EXE
- Works with STM32 / ESP32 / NRF / MCU UART TX

---

## System Architecture

[ Target MCU TX ] --> [ ESP32-S3 RX ] --> USB --> [ PC Analyzer ]

---

## Supported Devices

Any device with UART TX:

- STM32
- ESP32 / ESP8266
- NRF52 / NRF53
- RP2040
- Arduino
- Custom MCUs

---

## Getting Started (Beginner Guide)

This guide explains how to use LinkScope UART Analyzer step-by-step.

---

### 1. Flash Firmware to ESP32-S3

1. Open Arduino IDE
2. Open firmware file:

   firmware/esp32_s3/LinkScope_UART_Analyzer_v0.1.0_esp32_s3.ino

3. Select board:

   Tools → Board → ESP32 Arduino → ESP32S3 Dev Module

4. Select COM port
5. Click Upload

Wait until upload is finished.

---

### 2. Hardware Connection

Connect your target MCU to ESP32-S3:

Target MCU TX  --->  ESP32-S3 GPIO18 (RX)  
Target MCU GND --->  ESP32-S3 GND  

(Default RX pin: GPIO18)

Examples:

STM32 TX → GPIO18  
ESP32 TX → GPIO18  
Arduino TX → GPIO18  

No firmware change needed on target MCU.
Just connect TX line.

---

### 3. Run PC Analyzer (Windows)

1. Go to:

   releases/

2. Run:

   LinkScope_UART_Analyzer_v0.1.0_windows_x64.exe

No installation required.

---

### 4. Select Serial Port

1. Plug ESP32-S3 into PC
2. Check COM port in Windows Device Manager
3. In Analyzer:

   - Click Refresh
   - Select COM port
   - Set Baud Rate (default: 921600)
   - Click Connect

If connected, status will show "Connected".

---

### 5. Start Monitoring

After connection:

Press:

S → Start  
P → Stop  
C → Clear  

Or use GUI buttons.

UART data will appear in real-time.

---

### 6. Baud Rate Setting

Make sure target MCU baud matches analyzer.

Example (115200):

Type:

B115200

Press Enter, then press S.

---

### 7. Run from Python (Optional)

If you want to run from source:

```bash
pip install pyserial matplotlib
python host/LinkScope_UART_Analyzer_v0.1.0.py
```

---

### 8. Example Project

Example firmware:

examples/hello_demo_wroom_tx/

Use this to test basic UART transmission.

---

### 9. Troubleshooting

No data?

Check:

- TX/GND wiring
- Correct COM port
- Baud rate match
- ESP32-S3 firmware uploaded
- USB cable supports data

If still not working, open an Issue.

---

## Documentation

Beginner guide:

docs/usage.md

---

## Use Cases

- UART data loss debugging
- Throughput benchmarking
- Protocol reverse engineering
- Production testing
- Factory logging

---

## Build Windows EXE

```bash
pip install pyinstaller
pyinstaller --onefile host/LinkScope_UART_Analyzer_v0.1.0.py
```

---

## License

MIT License
