# linkscope_bpu_uart_analyzer.py
# LinkScope BPU - UART Analyzer (White UI)
#
# Features:
# - Clean "white" ttk UI (no custom theme needed)
# - AN wrapper decoder (COBS + 0x00 delimiter)
# - RAW / LOG / TEXT / PARSED tabs
# - AUTO inner-frame decoder (magic-based + CRC brute force)
# - Record / Replay (.anlog)
# - Port selection UI (Refresh / Connect / Disconnect)
# - Safe UX: Start/Stop/Clear are disabled until Connected
#
# Requirements:
#   pip install pyserial matplotlib
#
# Run:
#   python linkscope_bpu_uart_analyzer.py
#   python linkscope_bpu_uart_analyzer.py COM11

import sys, time, struct, threading, collections, os, itertools
import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# =========================
# Protocol (AN wrapper)
# =========================
P0, P1 = ord('A'), ord('N')
TYPE_RAW  = 0x01
TYPE_STAT = 0x02
TYPE_LOG  = 0x03

# =========================
# CRC engine (many variants)
# =========================
def crc16_param(data: bytes, poly: int, init: int, refin: bool, refout: bool, xorout: int) -> int:
    def reflect8(x: int) -> int:
        r = 0
        for i in range(8):
            if x & (1 << i):
                r |= 1 << (7 - i)
        return r

    def reflect16(x: int) -> int:
        r = 0
        for i in range(16):
            if x & (1 << i):
                r |= 1 << (15 - i)
        return r

    crc = init & 0xFFFF
    for b in data:
        if refin:
            b = reflect8(b)
        crc ^= (b << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    if refout:
        crc = reflect16(crc)
    crc ^= (xorout & 0xFFFF)
    return crc & 0xFFFF

CRC_VARIANTS = [
    ("CCITT_FALSE", 0x1021, 0xFFFF, False, False, 0x0000),
    ("XMODEM",      0x1021, 0x0000, False, False, 0x0000),
    ("AUGCCITT",    0x1021, 0x1D0F, False, False, 0x0000),
    ("GENIBUS",     0x1021, 0xFFFF, False, False, 0xFFFF),
    ("X25",         0x1021, 0xFFFF, True,  True,  0xFFFF),
    ("KERMIT",      0x1021, 0x0000, True,  True,  0x0000),
    ("IBM_ARC",     0x8005, 0x0000, True,  True,  0x0000),
    ("MODBUS",      0x8005, 0xFFFF, True,  True,  0x0000),
]

CRC_FUNCS = []
for name, poly, init, refin, refout, xorout in CRC_VARIANTS:
    CRC_FUNCS.append(
        (name, lambda d, p=poly, i=init, rn=refin, ro=refout, xo=xorout: crc16_param(d, p, i, rn, ro, xo))
    )

# =========================
# COBS decode (AN framing)
# =========================
def cobs_decode(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        code = data[i]
        if code == 0:
            raise ValueError("COBS code=0")
        i += 1
        for _ in range(code - 1):
            if i >= n:
                raise ValueError("COBS overrun")
            out.append(data[i])
            i += 1
        if code < 0xFF and i < n:
            out.append(0)
    return bytes(out)

def parse_an_frame(dec: bytes):
    # Layout: [ 'A','N', type, seq16, ts32, len16, payload... ]
    if len(dec) < 11:
        return None
    if dec[0] != P0 or dec[1] != P1:
        return None
    typ = dec[2]
    seq = dec[3] | (dec[4] << 8)
    ts  = dec[5] | (dec[6] << 8) | (dec[7] << 16) | (dec[8] << 24)
    ln  = dec[9] | (dec[10] << 8)
    if len(dec) != 11 + ln:
        return None
    payload = dec[11:]
    return typ, seq, ts, payload

# =========================
# anlog (record / replay)
# =========================
# record format: t_ms(u32 LE) + len(u16 LE) + payload (RAW payload only)
def anlog_write(f, t_ms: int, payload: bytes):
    ln = len(payload)
    if ln > 0xFFFF:
        payload = payload[:0xFFFF]
        ln = 0xFFFF
    f.write(struct.pack("<IH", int(t_ms) & 0xFFFFFFFF, ln))
    if ln:
        f.write(payload)

def anlog_read_iter(path: str):
    with open(path, "rb") as f:
        while True:
            hdr = f.read(6)
            if not hdr or len(hdr) < 6:
                break
            t_ms, ln = struct.unpack("<IH", hdr)
            payload = f.read(ln) if ln else b""
            if len(payload) < ln:
                break
            yield t_ms, payload

# =========================
# Hex / ASCII helpers
# =========================
def hexdump_lines(data: bytes, base_off: int = 0, width: int = 16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base_off+i:04X}: {hexpart:<47}  {asciipart}")
    return lines

def ascii_runs(data: bytes, min_len: int = 6):
    runs = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(bytes(cur))
            cur.clear()
    if len(cur) >= min_len:
        runs.append(bytes(cur))
    return runs

def _u16_le(lo: int, hi: int) -> int:
    return (lo | (hi << 8)) & 0xFFFF

def _u16_be(hi: int, lo: int) -> int:
    return ((hi << 8) | lo) & 0xFFFF

def _read_int(buf: bytes, pos: int, size: int, endian: str = "LE"):
    if pos + size > len(buf):
        return None, pos
    if size == 1:
        return buf[pos], pos + 1
    if size == 2:
        if endian == "LE":
            return _u16_le(buf[pos], buf[pos+1]), pos + 2
        else:
            return _u16_be(buf[pos], buf[pos+1]), pos + 2
    return None, pos

# =========================
# AUTO inner frame decoder (bruteforce)
# =========================
DEFAULT_MAGICS = [0xB2]

def try_parse_magic_frame(buf: bytes, off: int, magic: int):
    n = len(buf)
    if off >= n or buf[off] != magic:
        return None

    MAX_LEN = 2048
    best = None

    crc_endians = ["LE", "BE"]
    field_orders = list(itertools.permutations(["type", "seq", "len"], 3))

    for order in field_orders:
        for seq_size in (1, 2):
            for len_size in (1, 2):
                pos = off + 1
                vals = {}
                loc = {}
                ok = True
                for name in order:
                    start = pos
                    if name == "type":
                        if pos + 1 > n:
                            ok = False
                            break
                        vals["type"] = buf[pos]
                        pos += 1
                    elif name == "seq":
                        v, pos2 = _read_int(buf, pos, seq_size, endian="LE")
                        if v is None:
                            ok = False
                            break
                        vals["seq"] = v
                        pos = pos2
                    elif name == "len":
                        v, pos2 = _read_int(buf, pos, len_size, endian="LE")
                        if v is None:
                            ok = False
                            break
                        vals["len"] = v
                        pos = pos2
                    loc[name] = (start, pos)

                if not ok:
                    continue

                ln = vals.get("len", 0)
                if ln < 0 or ln > MAX_LEN:
                    continue
                if pos + ln + 2 > n:
                    continue

                payload = buf[pos:pos+ln]
                crc_off = pos + ln
                got_le = _u16_le(buf[crc_off], buf[crc_off+1])
                got_be = _u16_be(buf[crc_off], buf[crc_off+1])

                header_bytes = buf[off+1:pos]
                total = (pos - off) + ln + 2

                covers = [
                    ("HDR+PAY", header_bytes + payload),
                    ("PAY", payload),
                    ("MAGIC+PAY", bytes([magic]) + payload),
                    ("MAGIC+HDR+PAY", bytes([magic]) + header_bytes + payload),
                ]

                if "len" in loc:
                    ls, le = loc["len"]
                    h0 = buf[off+1:ls]
                    h1 = buf[le:pos]
                    covers.append(("HDR(noLEN)+PAY", h0 + h1 + payload))
                    covers.append(("MAGIC+HDR(noLEN)+PAY", bytes([magic]) + h0 + h1 + payload))

                if "seq" in loc:
                    ss, se = loc["seq"]
                    h0 = buf[off+1:ss]
                    h1 = buf[se:pos]
                    covers.append(("HDR(noSEQ)+PAY", h0 + h1 + payload))
                    covers.append(("MAGIC+HDR(noSEQ)+PAY", bytes([magic]) + h0 + h1 + payload))

                for cover_name, cover in covers:
                    for crc_name, crc_fn in CRC_FUNCS:
                        calc = crc_fn(cover)
                        for crc_endian in crc_endians:
                            got = got_le if crc_endian == "LE" else got_be
                            crc_ok = (got == calc)

                            score = 0
                            score += min(total, 64)
                            if crc_ok:
                                score += 10000
                            if cover_name.startswith("HDR"):
                                score += 2
                            if order[0] == "type":
                                score += 1

                            cand = {
                                "magic": magic,
                                "off": off,
                                "type": vals["type"],
                                "seq": vals["seq"],
                                "len": ln,
                                "payload": payload,
                                "crc_got": got,
                                "crc_calc": calc,
                                "crc_ok": crc_ok,
                                "total": total,
                                "fmt": f"{order} seq{seq_size} len{len_size} crc={crc_name}/{crc_endian} cover={cover_name}",
                            }
                            if best is None or score > best["__score"]:
                                cand["__score"] = score
                                best = cand

    if best is None:
        return None
    best.pop("__score", None)
    return best

def scan_magic_frames(payload: bytes, magics=DEFAULT_MAGICS, max_frames: int = 64):
    out = []
    i = 0
    n = len(payload)
    while i < n and len(out) < max_frames:
        b = payload[i]
        if b in magics:
            best = try_parse_magic_frame(payload, i, b)
            if best:
                out.append(best)
                i += best["total"]
                continue
        i += 1
    return out

# =========================
# Port listing helpers
# =========================
def list_ports_pretty():
    items = []
    for p in serial.tools.list_ports.comports():
        dev = p.device
        desc = p.description or ""
        hwid = (p.hwid or "").replace(" ", "")
        label = f"{dev} - {desc} ({hwid})"
        items.append((label, dev))

    # Simple ranking: put common USB-UART/ESP ports on top
    def score(label: str) -> int:
        s = label.lower()
        k = [("cp210",5),("silicon",5),("ch340",4),("usb-serial",4),("usb serial",4),("uart",3),("esp",3),("ftdi",3)]
        sc = 0
        for kk,w in k:
            if kk in s:
                sc += w
        if "com" in s:
            sc += 1
        return sc

    items.sort(key=lambda x: score(x[0]), reverse=True)
    return items

# =========================
# UI App
# =========================
class App:
    def __init__(self, port: str | None, baud: int = 115200):
        self.port = port
        self.baud = baud

        self.ser = None
        self.running = True
        self.capturing = False

        # Stats tracking
        self.rx_bytes_total = 0
        self.rx_chunks_total = 0
        self.last_stat = {}
        self.seq_last = None
        self.seq_gap = 0

        # Throughput graph
        self.t_points = collections.deque(maxlen=600)
        self.bps_points = collections.deque(maxlen=600)
        self._last_plot_t = time.time()

        # RAW tail
        self.raw_tail = bytearray()

        # TEXT buffer
        self._text_buf = bytearray()
        self._t0 = time.time()

        # Parsed frames (AUTO)
        self.parsed_items = collections.deque(maxlen=1000)
        self.parsed_selected = None

        # Recording
        self.rec_on = False
        self.rec_path = None
        self.rec_f = None
        self.rec_bytes = 0
        self.rec_pkts = 0
        self._rec_lock = threading.Lock()

        # Replay
        self.replay_on = False
        self.replay_path = None
        self.replay_iter = None
        self.replay_start_wall = 0.0
        self.replay_start_t = 0
        self.replay_speed = 1.0

        # PERF: incremental scan + debounce
        self._b2_scan_buf = bytearray()
        self._b2_scan_buf_max = 8192
        self._b2_scan_pos = 0
        self._parse_every_n_chunks = 10
        self._live_chunk_counter = 0
        self._parsed_refresh_pending = False

        # UI
        self.root = tk.Tk()
        title_port = self.port if self.port else "(DISCONNECTED)"
        self.root.title(f"LinkScope BPU - UART Analyzer - {title_port}")
        self.root.minsize(1180, 720)

        self.font_mono = ("Consolas", 10)

        self._build_layout()
        self.refresh_ports_ui()

        # If CLI port exists, pre-select and auto-connect
        if self.port:
            self.select_port_in_ui(self.port)
            self.connect_serial()

        self.root.after(100, self.ui_tick)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(20, self.replay_tick)

        # Hotkeys
        self.root.bind("<Control-l>", lambda e: self.on_clear())
        self.root.bind("<Control-r>", lambda e: self.on_rec_toggle())
        self.root.bind("<Control-o>", lambda e: self.on_load())
        self.root.bind("<Control-s>", lambda e: self.on_save_snap())

    # -------------------------
    # Layout
    # -------------------------
    def _build_layout(self):
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill="both", expand=True)

        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=0)
        main.rowconfigure(1, weight=1)
        main.rowconfigure(2, weight=2)

        # Controls
        ctrl = ttk.LabelFrame(main, text="Controls", padding=8)
        ctrl.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=6, pady=6)
        for i in range(60):
            ctrl.columnconfigure(i, weight=0)
        ctrl.columnconfigure(59, weight=1)

        # Start/Stop/Clear
        self.btn_start = ttk.Button(ctrl, text="Start", command=self.on_start)
        self.btn_stop  = ttk.Button(ctrl, text="Stop", command=self.on_stop)
        self.btn_clear = ttk.Button(ctrl, text="Clear", command=self.on_clear)
        self.btn_start.grid(row=0, column=0, padx=4, pady=4, sticky="w")
        self.btn_stop.grid(row=0, column=1, padx=4, pady=4, sticky="w")
        self.btn_clear.grid(row=0, column=2, padx=12, pady=4, sticky="w")

        # Record/Replay controls
        self.btn_rec = ttk.Button(ctrl, text="REC ●", command=self.on_rec_toggle)
        self.btn_save = ttk.Button(ctrl, text="SAVE SNAP", command=self.on_save_snap)
        self.btn_load = ttk.Button(ctrl, text="LOAD", command=self.on_load)
        self.btn_replay = ttk.Button(ctrl, text="REPLAY", command=self.on_replay_toggle)
        self.btn_rec.grid(row=0, column=3, padx=4, pady=4, sticky="w")
        self.btn_save.grid(row=0, column=4, padx=4, pady=4, sticky="w")
        self.btn_load.grid(row=0, column=5, padx=12, pady=4, sticky="w")
        self.btn_replay.grid(row=0, column=6, padx=4, pady=4, sticky="w")

        # Replay speed
        ttk.Label(ctrl, text="Speed:").grid(row=0, column=7, padx=(12,4), pady=4, sticky="w")
        self.cmb_speed = ttk.Combobox(ctrl, values=["x1", "x2", "x10"], width=5, state="readonly")
        self.cmb_speed.set("x1")
        self.cmb_speed.grid(row=0, column=8, padx=4, pady=4, sticky="w")
        self.cmb_speed.bind("<<ComboboxSelected>>", self.on_speed_change)

        self.lbl_state = ttk.Label(ctrl, text="Idle")
        self.lbl_state.grid(row=0, column=9, padx=12, pady=4, sticky="w")

        # Port controls
        ttk.Label(ctrl, text="Port:").grid(row=1, column=0, padx=4, pady=(0,4), sticky="w")
        self.cmb_port = ttk.Combobox(ctrl, width=55, state="readonly")
        self.cmb_port.grid(row=1, column=1, columnspan=6, padx=4, pady=(0,4), sticky="w")

        ttk.Button(ctrl, text="Refresh", command=self.refresh_ports_ui).grid(row=1, column=7, padx=4, pady=(0,4), sticky="w")

        ttk.Label(ctrl, text="Baud:").grid(row=1, column=8, padx=(12,4), pady=(0,4), sticky="w")
        self.ent_baud = ttk.Entry(ctrl, width=10)
        self.ent_baud.insert(0, str(self.baud))
        self.ent_baud.grid(row=1, column=9, padx=4, pady=(0,4), sticky="w")

        self.btn_connect = ttk.Button(ctrl, text="Connect", command=self.connect_serial)
        self.btn_disconnect = ttk.Button(ctrl, text="Disconnect", command=self.disconnect_serial)
        self.btn_connect.grid(row=1, column=10, padx=4, pady=(0,4), sticky="w")
        self.btn_disconnect.grid(row=1, column=11, padx=4, pady=(0,4), sticky="w")

        self.lbl_port = ttk.Label(ctrl, text="Port: (none)  [Select a port, then Connect]")
        self.lbl_port.grid(row=2, column=0, columnspan=20, padx=4, pady=(0,4), sticky="w")

        self.rec_var = tk.StringVar(value="rec=OFF")
        ttk.Label(ctrl, textvariable=self.rec_var).grid(row=2, column=20, columnspan=40, padx=4, pady=(0,4), sticky="e")

        # Disable start/stop/clear until connected
        self._set_controls_connected(False)

        # Row 1: Throughput + Stats
        left1 = ttk.LabelFrame(main, text="Throughput", padding=8)
        left1.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        right1 = ttk.LabelFrame(main, text="Stats / Health", padding=8)
        right1.grid(row=1, column=1, sticky="nsew", padx=6, pady=6)
        left1.columnconfigure(0, weight=1)
        left1.rowconfigure(0, weight=1)
        right1.columnconfigure(0, weight=1)
        right1.rowconfigure(0, weight=1)

        fig = plt.Figure(figsize=(6, 3), dpi=100)
        self.ax = fig.add_subplot(111)
        self.ax.set_title("Throughput (bytes/s)")
        self.ax.set_xlabel("time (s)")
        self.ax.set_ylabel("bytes/s")
        self.line, = self.ax.plot([], [])
        self.ax.grid(True, alpha=0.3)

        self.canvas = FigureCanvasTkAgg(fig, master=left1)
        self.canvas.get_tk_widget().grid(row=0, column=0, sticky="nsew")

        self.stats_var = tk.StringVar(value="(no stats yet)")
        self.stats_lbl = ttk.Label(right1, textvariable=self.stats_var, justify="left", font=self.font_mono)
        self.stats_lbl.grid(row=0, column=0, sticky="nw")

        # Row 2: RAW + Notebook
        left2 = ttk.LabelFrame(main, text="RAW Inspector (tail hexdump)", padding=8)
        left2.grid(row=2, column=0, sticky="nsew", padx=6, pady=6)
        right2 = ttk.LabelFrame(main, text="LOG / Text", padding=8)
        right2.grid(row=2, column=1, sticky="nsew", padx=6, pady=6)
        left2.columnconfigure(0, weight=1)
        left2.rowconfigure(1, weight=1)
        right2.columnconfigure(0, weight=1)
        right2.rowconfigure(0, weight=1)

        # RAW options
        rawopt = ttk.Frame(left2)
        rawopt.grid(row=0, column=0, sticky="ew", pady=(0,6))
        self.var_raw_printable = tk.BooleanVar(value=True)
        ttk.Checkbutton(rawopt, text="Printable only", variable=self.var_raw_printable).pack(side="left")
        self.var_raw_ascii_mode = tk.StringVar(value="DOT")
        ttk.Label(rawopt, text="RAW → ASCII mode:").pack(side="left", padx=10)
        ttk.Radiobutton(rawopt, text="DOT", value="DOT", variable=self.var_raw_ascii_mode).pack(side="left")
        ttk.Radiobutton(rawopt, text="ESC", value="ESC", variable=self.var_raw_ascii_mode).pack(side="left")

        # RAW text box
        self.raw = tk.Text(left2, wrap="none", font=self.font_mono)
        self.raw.grid(row=1, column=0, sticky="nsew")
        raw_sy = ttk.Scrollbar(left2, orient="vertical", command=self.raw.yview)
        raw_sx = ttk.Scrollbar(left2, orient="horizontal", command=self.raw.xview)
        self.raw.configure(yscrollcommand=raw_sy.set, xscrollcommand=raw_sx.set)
        raw_sy.grid(row=1, column=1, sticky="ns")
        raw_sx.grid(row=2, column=0, sticky="ew")

        # Notebook
        self.nb = ttk.Notebook(right2)
        self.nb.grid(row=0, column=0, sticky="nsew")

        # LOG tab
        tab_log = ttk.Frame(self.nb)
        tab_log.columnconfigure(0, weight=1)
        tab_log.rowconfigure(0, weight=1)
        self.log = tk.Text(tab_log, wrap="none", font=self.font_mono)
        self.log.grid(row=0, column=0, sticky="nsew")
        log_sy = ttk.Scrollbar(tab_log, orient="vertical", command=self.log.yview)
        log_sx = ttk.Scrollbar(tab_log, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=log_sy.set, xscrollcommand=log_sx.set)
        log_sy.grid(row=0, column=1, sticky="ns")
        log_sx.grid(row=1, column=0, sticky="ew")

        # TEXT tab
        tab_text = ttk.Frame(self.nb)
        tab_text.columnconfigure(0, weight=1)
        tab_text.rowconfigure(1, weight=1)

        opt = ttk.Frame(tab_text)
        opt.grid(row=0, column=0, sticky="ew", pady=(0,6))
        self.var_text_printable = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text="Printable only", variable=self.var_text_printable).pack(side="left")
        self.var_text_ascii_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text="ASCII strings only", variable=self.var_text_ascii_only).pack(side="left", padx=10)

        self.text = tk.Text(tab_text, wrap="none", font=self.font_mono)
        self.text.grid(row=1, column=0, sticky="nsew")
        text_sy = ttk.Scrollbar(tab_text, orient="vertical", command=self.text.yview)
        text_sx = ttk.Scrollbar(tab_text, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=text_sy.set, xscrollcommand=text_sx.set)
        text_sy.grid(row=1, column=1, sticky="ns")
        text_sx.grid(row=2, column=0, sticky="ew")

        # PARSED tab
        tab_parsed = ttk.Frame(self.nb)
        tab_parsed.columnconfigure(0, weight=1)
        tab_parsed.rowconfigure(1, weight=1)
        tab_parsed.rowconfigure(2, weight=2)

        topbar = ttk.Frame(tab_parsed)
        topbar.grid(row=0, column=0, sticky="ew", pady=(0,6))
        ttk.Label(topbar, text=f"AUTO frame decoder (MAGICs={[hex(m) for m in DEFAULT_MAGICS]})").pack(side="left")

        self.var_parsed_crc_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            topbar,
            text="CRC OK only",
            variable=self.var_parsed_crc_only,
            command=self.schedule_parsed_refresh
        ).pack(side="left", padx=12)

        self.var_parsed_show_fmt = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            topbar,
            text="Show fmt",
            variable=self.var_parsed_show_fmt,
            command=self.schedule_parsed_refresh
        ).pack(side="left", padx=12)

        cols = ("t","off","magic","type","seq","len","crc","fmt")
        self.parsed_tree = ttk.Treeview(tab_parsed, columns=cols, show="headings", height=8)
        widths = {"t":90, "off":80, "magic":70, "type":70, "seq":80, "len":60, "crc":70, "fmt":520}
        for col in cols:
            self.parsed_tree.heading(col, text=col)
            self.parsed_tree.column(col, width=widths.get(col, 80), anchor="w", stretch=True)

        self.parsed_tree.grid(row=1, column=0, sticky="nsew")
        self.parsed_tree.bind("<<TreeviewSelect>>", self.on_parsed_select)

        detail = ttk.Frame(tab_parsed)
        detail.grid(row=2, column=0, sticky="nsew", pady=(6,0))
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(0, weight=1)

        self.parsed_detail = tk.Text(detail, wrap="none", font=self.font_mono)
        self.parsed_detail.grid(row=0, column=0, sticky="nsew")
        pd_sy = ttk.Scrollbar(detail, orient="vertical", command=self.parsed_detail.yview)
        pd_sx = ttk.Scrollbar(detail, orient="horizontal", command=self.parsed_detail.xview)
        self.parsed_detail.configure(yscrollcommand=pd_sy.set, xscrollcommand=pd_sx.set)
        pd_sy.grid(row=0, column=1, sticky="ns")
        pd_sx.grid(row=1, column=0, sticky="ew")

        self.nb.add(tab_log, text="LOG")
        self.nb.add(tab_text, text="TEXT")
        self.nb.add(tab_parsed, text="PARSED")

    def _set_controls_connected(self, connected: bool):
        state = "normal" if connected else "disabled"
        self.btn_start.config(state=state)
        self.btn_stop.config(state=state)
        self.btn_clear.config(state=state)

    # -------------------------
    # Port UI
    # -------------------------
    def refresh_ports_ui(self):
        self._port_items = list_ports_pretty()
        labels = [lab for (lab, dev) in self._port_items]
        self.cmb_port["values"] = labels

        # Auto selection:
        # 1) if CLI port exists, select it
        # 2) if only one port found, select it
        # 3) otherwise keep current selection if possible; else select top-ranked
        if self.port:
            self.select_port_in_ui(self.port)
        elif len(labels) == 1:
            self.cmb_port.set(labels[0])
        else:
            if not self.cmb_port.get() and labels:
                self.cmb_port.set(labels[0])

        self.append_log(f"[UI] Ports refreshed: {len(labels)} found")

    def select_port_in_ui(self, devname: str):
        devname_u = devname.upper()
        for lab, dev in getattr(self, "_port_items", []):
            if dev.upper() == devname_u:
                self.cmb_port.set(lab)
                return
        self.cmb_port.set(devname)

    def _get_selected_port_device(self):
        sel = self.cmb_port.get().strip()
        if not sel:
            return None
        for lab, dev in getattr(self, "_port_items", []):
            if sel == lab:
                return dev
        if sel.upper().startswith("COM") or sel.startswith("/dev/"):
            return sel
        return None

    def connect_serial(self):
        dev = self._get_selected_port_device()
        if not dev:
            messagebox.showwarning("Connect", "Select a serial port first.")
            return
        try:
            baud = int(self.ent_baud.get().strip())
        except Exception:
            messagebox.showwarning("Connect", "Invalid baud rate.")
            return

        # Close existing connection first
        self.disconnect_serial()

        try:
            self.ser = serial.Serial(dev, baudrate=baud, timeout=0.05)
        except Exception as e:
            self.ser = None
            messagebox.showerror("Connect failed", str(e))
            self.append_log(f"[SER] Connect failed: {e}")
            self._set_controls_connected(False)
            return

        self.port = dev
        self.baud = baud
        self.root.title(f"LinkScope BPU - UART Analyzer - {dev}")
        self.lbl_port.config(text=f"Port: {dev} @ {baud}")
        self.append_log(f"[SER] Connected: {dev} @ {baud}")
        self._set_controls_connected(True)

        # Start reader thread once
        if not hasattr(self, "th") or not self.th.is_alive():
            self.th = threading.Thread(target=self.reader_loop, daemon=True)
            self.th.start()

    def disconnect_serial(self):
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        self.port = None
        self.root.title("LinkScope BPU - UART Analyzer - (DISCONNECTED)")
        self.lbl_port.config(text="Port: (none)  [Select a port, then Connect]")
        self.append_log("[SER] Disconnected")
        self._set_controls_connected(False)
        self.capturing = False
        self.lbl_state.config(text="Idle")

    # -------------------------
    # Controls
    # -------------------------
    def append_log(self, s: str):
        self.log.insert("end", s)
        if not s.endswith("\n"):
            self.log.insert("end", "\n")
        self.log.see("end")

    def write_cmd(self, s: str):
        if not self.ser:
            return
        try:
            self.ser.write(s.encode("ascii"))
        except Exception:
            pass

    def on_start(self):
        if not self.ser:
            return
        self.write_cmd("S\n")
        self.capturing = True
        self.lbl_state.config(text="Capturing…")
        self.append_log("[AN] START")

    def on_stop(self):
        if not self.ser:
            return
        self.write_cmd("P\n")
        self.capturing = False
        self.lbl_state.config(text="Stopped")
        self.append_log("[AN] STOP")

    def on_clear(self):
        # Clear command is optional; send only if connected
        if self.ser:
            self.write_cmd("C\n")

        self.seq_last = None
        self.seq_gap = 0
        self.rx_bytes_total = 0
        self.rx_chunks_total = 0
        self.last_stat = {}

        self.raw.delete("1.0", "end")
        self.log.delete("1.0", "end")
        self.text.delete("1.0", "end")
        self.parsed_detail.delete("1.0", "end")

        self.raw_tail = bytearray()
        self._text_buf = bytearray()
        self._t0 = time.time()
        self.parsed_items.clear()

        self._b2_scan_buf = bytearray()
        self._b2_scan_pos = 0
        self._live_chunk_counter = 0

        self.refresh_parsed_list()
        self.append_log("[AN] CLEAR")

    def on_speed_change(self, _evt=None):
        s = self.cmb_speed.get().strip().lower()
        if s == "x2":
            self.replay_speed = 2.0
        elif s == "x10":
            self.replay_speed = 10.0
        else:
            self.replay_speed = 1.0
        if self.replay_on:
            self.lbl_state.config(text=f"Replay {self.cmb_speed.get()}")

    # -------------------------
    # Record
    # -------------------------
    def on_rec_toggle(self):
        if self.rec_on:
            self.stop_recording()
        else:
            self.start_recording()

    def start_recording(self):
        default = time.strftime("an_%Y%m%d_%H%M%S.anlog")
        path = filedialog.asksaveasfilename(
            title="Select record file",
            defaultextension=".anlog",
            initialfile=default,
            filetypes=[("Analyzer Log", "*.anlog"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            f = open(path, "wb")
        except Exception as e:
            messagebox.showerror("REC", f"Failed to open file:\n{e}")
            return

        with self._rec_lock:
            self.rec_on = True
            self.rec_path = path
            self.rec_f = f
            self.rec_bytes = 0
            self.rec_pkts = 0

        self.btn_rec.config(text="REC ■")
        self.append_log(f"[AN] REC ON: {os.path.basename(path)}")

    def stop_recording(self):
        with self._rec_lock:
            self.rec_on = False
            f = self.rec_f
            self.rec_f = None

        if f:
            try:
                f.flush()
                f.close()
            except Exception:
                pass

        self.btn_rec.config(text="REC ●")
        if self.rec_path:
            self.append_log(f"[AN] REC OFF: {os.path.basename(self.rec_path)}")
        self.rec_path = None

    def on_save_snap(self):
        default = time.strftime("snap_%Y%m%d_%H%M%S.anlog")
        path = filedialog.asksaveasfilename(
            title="Save snapshot (.anlog)",
            defaultextension=".anlog",
            initialfile=default,
            filetypes=[("Analyzer Log", "*.anlog"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "wb") as f:
                tail = bytes(self.raw_tail[-4096:])
                anlog_write(f, 0, tail)
        except Exception as e:
            messagebox.showerror("SAVE SNAP", f"Failed:\n{e}")
            return
        self.append_log(f"[AN] SNAP SAVED: {os.path.basename(path)}")

    # -------------------------
    # Load / Replay
    # -------------------------
    def on_load(self):
        path = filedialog.askopenfilename(
            title="Load .anlog",
            filetypes=[("Analyzer Log", "*.anlog"), ("All files", "*.*")]
        )
        if not path:
            return
        self.replay_path = path
        self.append_log(f"[AN] LOADED: {os.path.basename(path)} (ready)")
        if not self.ser:
            self.lbl_port.config(text=f"Port: (none)  [Loaded: {os.path.basename(path)}]")

    def on_replay_toggle(self):
        if self.replay_on:
            self.stop_replay()
        else:
            self.start_replay()

    def start_replay(self):
        if not self.replay_path:
            messagebox.showinfo("REPLAY", "Load a .anlog file first.")
            return
        try:
            self.replay_iter = iter(anlog_read_iter(self.replay_path))
            first = next(self.replay_iter, None)
            if not first:
                messagebox.showerror("REPLAY", "Empty or invalid .anlog.")
                self.replay_iter = None
                return
            self.replay_start_t = first[0]
            self.replay_start_wall = time.time()
            self.replay_on = True
            self.btn_replay.config(text="REPLAY ■")
            self.lbl_state.config(text=f"Replay {self.cmb_speed.get()}")
            self.append_log("[AN] REPLAY ON")
            self._apply_replay_record(first[0], first[1])
        except Exception as e:
            messagebox.showerror("REPLAY", f"Failed:\n{e}")
            self.replay_iter = None

    def stop_replay(self):
        self.replay_on = False
        self.btn_replay.config(text="REPLAY")
        self.lbl_state.config(text="Idle")
        self.append_log("[AN] REPLAY OFF")

    def replay_tick(self):
        if self.replay_on and self.replay_iter:
            now = time.time()
            elapsed_ms = (now - self.replay_start_wall) * 1000.0 * float(self.replay_speed)
            target_t = int(self.replay_start_t + elapsed_ms)

            while True:
                if not hasattr(self, "_replay_pending"):
                    self._replay_pending = None

                if self._replay_pending is None:
                    rec = next(self.replay_iter, None)
                    self._replay_pending = rec

                rec = self._replay_pending
                if rec is None:
                    self.stop_replay()
                    break

                t_ms, payload = rec
                if t_ms <= target_t:
                    self._apply_replay_record(t_ms, payload)
                    self._replay_pending = None
                    continue
                break

        self.root.after(20, self.replay_tick)

    def _apply_replay_record(self, t_ms: int, payload: bytes):
        self.rx_bytes_total += len(payload)
        self.rx_chunks_total += 1
        self.raw_tail.extend(payload)
        if len(self.raw_tail) > 4096:
            self.raw_tail = self.raw_tail[-4096:]

        self._append_text_bytes(payload)
        self._parse_and_store_auto(payload, ts_ms=t_ms, source="REPLAY")

        if self.rx_chunks_total % 2 == 0:
            self.root.after(0, self.update_raw_hexdump)
            self.root.after(0, self.schedule_parsed_refresh)

        self.t_points.append(time.time())
        self.bps_points.append(len(payload) * 10)

    # -------------------------
    # Close
    # -------------------------
    def on_close(self):
        self.running = False
        try:
            if self.ser:
                self.ser.close()
        except Exception:
            pass
        try:
            if self.rec_on:
                self.stop_recording()
        except Exception:
            pass
        self.root.destroy()

    # -------------------------
    # Stats panel
    # -------------------------
    def set_stats_text(self):
        st = self.last_stat
        if not st:
            self.stats_var.set("(no stats yet)")
        else:
            txt = (
                f"health={'OK' if (st.get('rx_overflow',0)==0 and st.get('uart_hw_overrun',0)==0 and self.seq_gap==0) else 'WARN'}\n"
                f"up_ms={st.get('up_ms')}  uart_baud={st.get('uart_baud')}\n"
                f"rx_bytes_total={st.get('rx_bytes_total')}  rx_chunks_total={st.get('rx_chunks_total')}\n"
                f"rx_overflow={st.get('rx_overflow',0)}  uart_hw_overrun={st.get('uart_hw_overrun',0)}  seq_gap={self.seq_gap}\n"
                f"rx_bytes/s={st.get('rx_bytes_per_s')}  rx_chunks/s={st.get('rx_chunks_per_s')}  max_chunk={st.get('max_chunk')}\n"
            )
            self.stats_var.set(txt)

        if self.rec_on and self.rec_path:
            self.rec_var.set(f"rec=ON  pkts={self.rec_pkts}  bytes={self.rec_bytes}  file={os.path.basename(self.rec_path)}")
        else:
            self.rec_var.set("rec=OFF")

    # -------------------------
    # Plot tick
    # -------------------------
    def ui_tick(self):
        now = time.time()
        if now - self._last_plot_t >= 0.2:
            self._last_plot_t = now
            if self.t_points:
                xs = list(self.t_points)
                ys = list(self.bps_points)
                x0 = xs[0]
                xs = [x - x0 for x in xs]
                self.line.set_data(xs, ys)
                self.ax.relim()
                self.ax.autoscale_view()
                self.canvas.draw_idle()

        self.set_stats_text()
        self.root.after(100, self.ui_tick)

    # -------------------------
    # RAW hexdump
    # -------------------------
    def update_raw_hexdump(self):
        tail = bytes(self.raw_tail[-512:])
        lines = hexdump_lines(tail, base_off=0)

        # ASCII preview mode: DOT vs ESC
        mode = self.var_raw_ascii_mode.get()
        if mode == "ESC":
            fixed = []
            for ln in lines:
                head, _asci = ln.rsplit("  ", 1)
                hexpart = head.split(": ", 1)[1]
                hexbytes = hexpart.split()
                bs = bytes(int(h, 16) for h in hexbytes if len(h) == 2)
                esc = []
                for b in bs:
                    if 32 <= b < 127:
                        esc.append(chr(b))
                    else:
                        esc.append(f"\\x{b:02X}")
                fixed.append(head + "  " + "".join(esc))
            lines = fixed

        self.raw.delete("1.0", "end")
        self.raw.insert("end", "\n".join(lines))
        self.raw.see("1.0")

    # -------------------------
    # TEXT preview
    # -------------------------
    def _append_text_bytes(self, payload: bytes):
        ascii_only = bool(self.var_text_ascii_only.get())
        printable_only = bool(self.var_text_printable.get())
        dt = time.time() - self._t0

        # Show only extracted ASCII strings (heuristic)
        if ascii_only:
            runs = ascii_runs(payload, min_len=6)
            if runs:
                for r in runs[:8]:
                    s = r.decode("ascii", errors="replace")
                    self._emit_text_line(f"[{dt:8.3f}] STR  {s}\n")
            return

        # Line-based decode (split by '\n')
        self._text_buf.extend(payload)
        if len(self._text_buf) > 8192:
            self._text_buf = self._text_buf[-8192:]

        while True:
            try:
                idx = self._text_buf.index(0x0A)  # '\n'
            except ValueError:
                break
            line = self._text_buf[:idx+1]
            del self._text_buf[:idx+1]

            if printable_only:
                filtered = bytearray()
                for b in line:
                    if b in (9, 10, 13) or (32 <= b < 127):
                        filtered.append(b)
                line = bytes(filtered)

            s = line.decode("utf-8", errors="replace")
            self._emit_text_line(f"[{dt:8.3f}] {s}")

    def _emit_text_line(self, s: str):
        def ui_add():
            self.text.insert("end", s if s.endswith("\n") else (s + "\n"))
            self.text.see("end")
        self.root.after(0, ui_add)

    # -------------------------
    # PARSED refresh debounce
    # -------------------------
    def schedule_parsed_refresh(self):
        if self._parsed_refresh_pending:
            return
        self._parsed_refresh_pending = True

        def _do():
            self._parsed_refresh_pending = False
            self.refresh_parsed_list()

        self.root.after(250, _do)

    # -------------------------
    # PARSED (AUTO decoder)
    # -------------------------
    def _parse_and_store_auto(self, payload: bytes, ts_ms: int, source: str):
        self._b2_scan_buf.extend(payload)
        if len(self._b2_scan_buf) > self._b2_scan_buf_max:
            cut = len(self._b2_scan_buf) - self._b2_scan_buf_max
            self._b2_scan_buf = self._b2_scan_buf[cut:]
            self._b2_scan_pos = max(0, self._b2_scan_pos - cut)

        data = bytes(self._b2_scan_buf)
        start = max(0, self._b2_scan_pos - 64)
        window = data[start:]

        frames = scan_magic_frames(window, magics=DEFAULT_MAGICS, max_frames=64)
        self._b2_scan_pos = len(data)
        if not frames:
            return

        wall = time.time() - self._t0
        for f in frames:
            f_off = f["off"] + start
            item = {
                "wall_s": wall,
                "ts_ms": ts_ms,
                "source": source,
                "off": f_off,
                "magic": f["magic"],
                "type": f["type"],
                "seq": f["seq"],
                "len": f["len"],
                "crc_ok": f["crc_ok"],
                "crc_got": f["crc_got"],
                "crc_calc": f["crc_calc"],
                "payload": f["payload"],
                "total": f["total"],
                "fmt": f["fmt"],
            }
            self.parsed_items.append(item)

    def refresh_parsed_list(self):
        crc_only = bool(self.var_parsed_crc_only.get())
        show_fmt = bool(self.var_parsed_show_fmt.get())
        self.parsed_tree.delete(*self.parsed_tree.get_children())

        items = list(self.parsed_items)
        items.reverse()

        shown = 0
        for it in items:
            if crc_only and not it["crc_ok"]:
                continue
            t = f"{it['wall_s']:.3f}"
            off = f"{it['off']}"
            magic = f"0x{it['magic']:02X}"
            typ = f"0x{it['type']:02X}"
            seq = f"{it['seq']}"
            ln  = f"{it['len']}"
            crc = "OK" if it["crc_ok"] else "FAIL"
            fmt = it["fmt"] if show_fmt else ""
            iid = f"row_{shown}"
            self.parsed_tree.insert("", "end", iid=iid, values=(t, off, magic, typ, seq, ln, crc, fmt))
            shown += 1
            if shown >= 60:
                break

    def on_parsed_select(self, _evt=None):
        sel = self.parsed_tree.selection()
        if not sel:
            return
        iid = sel[0]
        vals = self.parsed_tree.item(iid, "values")
        if not vals:
            return

        try:
            t_s = float(vals[0])
            off = int(vals[1])
            magic = int(vals[2], 16)
            typ = int(vals[3], 16)
            seq = int(vals[4])
            ln  = int(vals[5])
            crc_label = vals[6]
        except Exception:
            return

        items = list(self.parsed_items)
        items.reverse()
        target = None
        for it in items:
            if (abs(it["wall_s"] - t_s) < 0.02 and it["off"] == off and it["magic"] == magic
                and it["type"] == typ and it["seq"] == seq and it["len"] == ln):
                if (crc_label == "OK") == bool(it["crc_ok"]):
                    target = it
                    break
        if not target:
            return

        self.parsed_selected = target
        self._render_parsed_detail(target)

    def _render_parsed_detail(self, it: dict):
        self.parsed_detail.delete("1.0", "end")
        head = []
        head.append(f"AUTO FRAME @ t={it['wall_s']:.3f}s  source={it['source']}  ts_ms={it['ts_ms']}")
        head.append(f"magic=0x{it['magic']:02X}  offset={it['off']}  total={it['total']} bytes")
        head.append(f"type=0x{it['type']:02X}  seq={it['seq']}  len={it['len']}")
        head.append(f"crc_got=0x{it['crc_got']:04X}  crc_calc=0x{it['crc_calc']:04X}  crc_ok={it['crc_ok']}")
        head.append(f"fmt: {it['fmt']}")
        head.append("")
        head.append("payload hexdump:")
        hd = hexdump_lines(it["payload"], base_off=0)
        self.parsed_detail.insert("end", "\n".join(head + hd))
        self.parsed_detail.see("1.0")

    # -------------------------
    # Serial reader loop
    # -------------------------
    def reader_loop(self):
        buf = bytearray()
        while self.running:
            try:
                # If not connected, just wait
                if not self.ser:
                    time.sleep(0.05)
                    continue

                chunk = self.ser.read(4096)
                if not chunk:
                    continue
                buf.extend(chunk)

                # Frames are delimited by 0x00 (COBS)
                while True:
                    try:
                        k = buf.index(0)
                    except ValueError:
                        break

                    frame = bytes(buf[:k])
                    del buf[:k+1]
                    if not frame:
                        continue

                    try:
                        dec = cobs_decode(frame)
                    except Exception:
                        continue

                    parsed = parse_an_frame(dec)
                    if not parsed:
                        continue

                    typ, seq, ts, payload = parsed

                    # Sequence gap tracking
                    if self.seq_last is not None:
                        exp = (self.seq_last + 1) & 0xFFFF
                        if seq != exp:
                            self.seq_gap += 1
                    self.seq_last = seq

                    if typ == TYPE_RAW:
                        self.rx_bytes_total += len(payload)
                        self.rx_chunks_total += 1
                        self.raw_tail.extend(payload)
                        if len(self.raw_tail) > 4096:
                            self.raw_tail = self.raw_tail[-4096:]

                        self._append_text_bytes(payload)

                        # Parse periodically (performance)
                        self._live_chunk_counter += 1
                        if (self._live_chunk_counter % self._parse_every_n_chunks) == 0:
                            self._parse_and_store_auto(payload, ts_ms=ts, source="LIVE")
                            self.root.after(0, self.schedule_parsed_refresh)

                        if self.rx_chunks_total % 5 == 0:
                            self.root.after(0, self.update_raw_hexdump)

                        # Record RAW payload only
                        if self.rec_on:
                            with self._rec_lock:
                                f = self.rec_f
                                if f:
                                    try:
                                        anlog_write(f, ts, payload)
                                        self.rec_pkts += 1
                                        self.rec_bytes += len(payload)
                                    except Exception:
                                        pass

                    elif typ == TYPE_LOG:
                        s = payload.decode("utf-8", errors="replace")
                        self.root.after(0, self.append_log, s)

                    elif typ == TYPE_STAT:
                        # Expected layout: 9x u32 = 36 bytes
                        if len(payload) == 36:
                            fields = struct.unpack("<IIIIIIIII", payload)
                            keys = [
                                "up_ms","uart_baud",
                                "rx_bytes_total","rx_chunks_total",
                                "rx_overflow","uart_hw_overrun",
                                "rx_bytes_per_s","rx_chunks_per_s",
                                "max_chunk"
                            ]
                            self.last_stat = dict(zip(keys, fields))
                            self.root.after(0, self.update_raw_hexdump)

                            self.t_points.append(time.time())
                            self.bps_points.append(self.last_stat.get("rx_bytes_per_s", 0))

            except Exception:
                time.sleep(0.1)

    # -------------------------
    # Run
    # -------------------------
    def run(self):
        self.root.mainloop()

# =========================
# Main
# =========================
if __name__ == "__main__":
    port = sys.argv[1] if len(sys.argv) >= 2 else None
    app = App(port)
    app.run()


