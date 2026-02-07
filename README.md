# LinkScope BPU UART Analyzer

High-speed UART analyzer using ESP32-S3 + PC GUI.

Real-time capture, framing, statistics, and visualization for embedded debugging.

---

## Demo

![Demo](docs/demo.gif)

---

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

- STM32
- ESP32 / ESP8266
- NRF52 / NRF53
- RP2040
- Arduino
- Custom MCUs

---

## Hardware Connection

Target TX -> GPIO18  
Target GND -> GND  

---

## Firmware

Location:

firmware/esp32_s3/

Baud rate: 921600

---

## PC Application

### Windows EXE

releases/LinkScope_UART_Analyzer_v0.1.0_windows_x64.exe

### Run from Source

pip install pyserial matplotlib  
python host/LinkScope_UART_Analyzer_v0.1.0.py

---

## Example

examples/hello_demo_wroom_tx/

---

## Commands

| Key | Function |
|-----|----------|
| S   | Start    |
| P   | Stop     |
| C   | Clear    |
| Bxxxx | Set baud |

Example:

B921600  
S

---

## Beginner Guide (Usage)

📘 Step-by-step guide:

➡️ [docs/usage.md](docs/usage.md)

---

## Build Windows EXE

pip install pyinstaller  
pyinstaller --onefile host/LinkScope_UART_Analyzer_v0.1.0.py

---

## License

MIT License
