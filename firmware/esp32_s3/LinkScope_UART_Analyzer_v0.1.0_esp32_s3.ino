#include <Arduino.h>
#include <stdarg.h>

// =====================
// Ports
// =====================
static HardwareSerial& UART = Serial1; // from Target TX -> our RX
static HardwareSerial& USB  = Serial;  // USB CDC -> PC (BINARY FRAMES)

// =====================
// UART config
// =====================
static uint32_t UART_BAUD = 921600;
static const int UART_RX_PIN = 18;   // Target TX -> S3 RX
static const int UART_TX_PIN = 17;   // optional

// =====================
// Analyzer protocol (S3->PC)
// =====================
// COBS framed, 0x00 delimited
// [ 'A' 'N' | TYPE | SEQ16 | TS_US32 | LEN16 | PAYLOAD... ]
static const uint8_t P0 = 'A';
static const uint8_t P1 = 'N';

enum : uint8_t {
  TYPE_RAW  = 0x01,   // payload: raw UART bytes
  TYPE_STAT = 0x02,   // payload: struct StatPayload
  TYPE_LOG  = 0x03    // payload: utf-8 text (no null required)
};

static uint16_t g_seq = 0;

// =====================
// Buffers / flushing
// =====================
static const size_t RAW_CHUNK_MAX = 512;     // flush chunk size
static const uint32_t IDLE_FLUSH_US = 2000;  // 2ms idle => flush

static uint8_t rawBuf[RAW_CHUNK_MAX];
static size_t  rawLen = 0;

static uint32_t lastByteUs = 0;

// =====================
// Stats
// =====================
struct StatPayload {
  uint32_t up_ms;
  uint32_t uart_baud;

  uint32_t rx_bytes_total;
  uint32_t rx_chunks_total;

  uint32_t rx_overflow;     // rawBuf overflow count
  uint32_t uart_hw_overrun; // UART driver fifo overrun (best-effort)

  uint32_t rx_bytes_per_s;  // last 1s
  uint32_t rx_chunks_per_s; // last 1s
  uint32_t max_chunk;       // max rawLen flushed in last window
};

static StatPayload st{};
static uint32_t win_ms = 0;
static uint32_t win_bytes = 0;
static uint32_t win_chunks = 0;
static uint32_t win_max_chunk = 0;

// capture state
static bool capturing = false;

// =====================
// CRC16? (optional)
// Not needed for USB CDC reliability; keep OFF for simplicity.
// =====================

// =====================
// COBS encode
// =====================
static size_t cobs_encode(const uint8_t* input, size_t length, uint8_t* output, size_t out_max){
  if(out_max == 0) return 0;
  size_t read_index=0, write_index=1, code_index=0;
  uint8_t code=1;

  while(read_index < length){
    if(write_index >= out_max) return 0;

    if(input[read_index] == 0){
      output[code_index] = code;
      code = 1;
      code_index = write_index++;
      read_index++;
    } else {
      output[write_index++] = input[read_index++];
      code++;
      if(code == 0xFF){
        output[code_index] = code;
        code = 1;
        code_index = write_index++;
      }
    }
  }

  if(code_index >= out_max) return 0;
  output[code_index] = code;
  return write_index;
}

static inline void w_u16(uint8_t* p, uint16_t v){ p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)((v>>8)&0xFF); }
static inline void w_u32(uint8_t* p, uint32_t v){ p[0]=v&0xFF; p[1]=(v>>8)&0xFF; p[2]=(v>>16)&0xFF; p[3]=(v>>24)&0xFF; }

// =====================
// Send one analyzer frame (COBS + 0x00)
// =====================
static void send_frame(uint8_t type, const uint8_t* payload, uint16_t len){
  // header 2 + 1 + 2 + 4 + 2 = 11 bytes
  const size_t HDR = 11;
  const size_t DEC_MAX = HDR + len;

  // worst-case COBS expansion: + (n/254)+2
  const size_t ENC_MAX = DEC_MAX + (DEC_MAX/254) + 8;
  static uint8_t dec[HDR + RAW_CHUNK_MAX + 64];
  static uint8_t enc[HDR + RAW_CHUNK_MAX + 64 + 32];

  if(DEC_MAX > sizeof(dec)) return;
  if(ENC_MAX > sizeof(enc)) return;

  uint8_t* d = dec;
  d[0]=P0; d[1]=P1;
  d[2]=type;

  uint16_t seq = g_seq++;
  w_u16(&d[3], seq);

  uint32_t ts = (uint32_t)micros();
  w_u32(&d[5], ts);

  w_u16(&d[9], len);

  for(uint16_t i=0;i<len;i++) d[HDR+i]=payload[i];

  size_t encLen = cobs_encode(dec, DEC_MAX, enc, sizeof(enc));
  if(encLen == 0) return;

  USB.write(enc, encLen);
  USB.write((uint8_t)0x00);
}

// =====================
// LOG helper (goes to UI)
// =====================
static void log_ui(const char* fmt, ...){
  char buf[256];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if(n <= 0) return;
  if(n >= (int)sizeof(buf)) n = (int)sizeof(buf)-1;
  send_frame(TYPE_LOG, (const uint8_t*)buf, (uint16_t)n);
}

// =====================
// Flush RAW chunk
// =====================
static void flush_raw(){
  if(rawLen == 0) return;

  send_frame(TYPE_RAW, rawBuf, (uint16_t)rawLen);

  st.rx_chunks_total++;
  win_chunks++;
  if(rawLen > win_max_chunk) win_max_chunk = (uint32_t)rawLen;

  rawLen = 0;
}

// =====================
// Pump UART
// =====================
static void pump_uart(){
  // best-effort: some cores expose overflow flags; if not, ignore.
  while(UART.available()){
    int v = UART.read();
    if(v < 0) break;

    uint8_t b = (uint8_t)v;

    st.rx_bytes_total++;
    win_bytes++;

    lastByteUs = (uint32_t)micros();

    if(rawLen < RAW_CHUNK_MAX){
      rawBuf[rawLen++] = b;
      if(rawLen == RAW_CHUNK_MAX){
        flush_raw(); // chunk full => flush
      }
    } else {
      // should not happen because we flush at ==max, but keep anyway
      st.rx_overflow++;
      rawLen = 0;
    }
  }

  // idle flush (end-of-burst)
  if(rawLen > 0){
    uint32_t nowUs = (uint32_t)micros();
    if((uint32_t)(nowUs - lastByteUs) >= IDLE_FLUSH_US){
      flush_raw();
    }
  }
}

// =====================
// PC command parsing (ASCII)
// =====================
static void handle_cmd(){
  static char line[64];
  static uint8_t li = 0;

  while(USB.available()){
    int c = USB.read();
    if(c < 0) break;

    if(c == '\n' || c == '\r'){
      line[li] = 0;
      li = 0;

      if(line[0] == 'S'){ // Start
        capturing = true;
        log_ui("[AN] START\n");
      } else if(line[0] == 'P'){ // Pause/Stop
        capturing = false;
        flush_raw();
        log_ui("[AN] STOP\n");
      } else if(line[0] == 'C'){ // Clear counters
        st = StatPayload{};
        win_bytes=win_chunks=win_max_chunk=0;
        log_ui("[AN] CLEAR\n");
      } else if(line[0] == 'B'){ // Baud: B921600
        uint32_t nb = (uint32_t)strtoul(&line[1], nullptr, 10);
        if(nb >= 1200 && nb <= 4000000){
          UART_BAUD = nb;
          UART.updateBaudRate(UART_BAUD);
          log_ui("[AN] BAUD=%lu\n", (unsigned long)UART_BAUD);
        }
      } else if(line[0] != 0){
        log_ui("[AN] Unknown cmd: %s\n", line);
      }
      continue;
    }

    if(li < sizeof(line)-1){
      line[li++] = (char)c;
    } else {
      li = 0;
    }
  }
}

// =====================
// Stats tick (1Hz + periodic send)
// =====================
static void stats_tick(){
  uint32_t now = millis();
  if(win_ms == 0) win_ms = now;

  if((int32_t)(now - win_ms) >= 1000){
    st.up_ms = now;
    st.uart_baud = UART_BAUD;

    st.rx_bytes_per_s  = win_bytes;
    st.rx_chunks_per_s = win_chunks;
    st.max_chunk = win_max_chunk;

    send_frame(TYPE_STAT, (const uint8_t*)&st, (uint16_t)sizeof(st));

    win_ms = now;
    win_bytes = 0;
    win_chunks = 0;
    win_max_chunk = 0;
  }
}

void setup(){
  USB.begin(115200);
  delay(150);

  UART.begin(UART_BAUD, SERIAL_8N1, UART_RX_PIN, UART_TX_PIN);
  delay(50);

  capturing = false;
  lastByteUs = (uint32_t)micros();

  log_ui("[AN] Boot. UART RX=GPIO%d baud=%lu\n", UART_RX_PIN, (unsigned long)UART_BAUD);
  log_ui("[AN] Commands: S(start) P(stop) C(clear) B<baud>\n");
}

void loop(){
  handle_cmd();

  if(capturing){
    pump_uart();
  }

  stats_tick();
  delay(1);
}
