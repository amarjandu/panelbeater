# Copyright (C) 2026 Amar Jandu
# SPDX-License-Identifier: GPL-2.0-or-later
"""ScanSnap iX1300 network transport ("VENS" dialect).

Reverse-engineered from a packet capture of ScanSnap Home <-> iX1300. The iX1300
is NOT the iX1500 platform: it speaks a related but distinct protocol.

Differences from the iX1500 ssNR path this file exists to handle:

  * Frames use the magic "VENS", not "ssNR". The envelope is otherwise
    identical: u32 BE total-length | magic | u32 BE opcode | u32 BE flags | body.
  * Everything runs over TCP 53218 (the SCSI passthrough port). Port 53219,
    the ssNR registration/host-list/profile port, is never used.
  * There is NO enrolment, NO host list, NO registration. `panelbeater enrol`
    does not apply to this model.
  * The host announces itself for button notices with a small VENS datagram to
    UDP 52217; the scanner then sends a VENS opcode-0x01 datagram to the host on
    UDP 55265 when the Scan button is pressed (three copies, like the iX1500).
  * GET_HW_STATUS returns the data in a SEPARATE frame after a 16-byte status
    frame; the hopper-empty bit is at offset 0x07 of the data block (not 0x03).
  * The scan setup is d8 / e9 / d4 -- no d5 wrappers -- and both e9 and d4 carry
    model-specific parameter blocks captured verbatim below.

All observed byte offsets match panelbeater's existing SCSI body layout exactly
(MAC at 0x00, CDB length at 0x10, transfer length at 0x14, CDB at 0x20), so the
SCSI framing here mirrors session.Session.scsi with the magic swapped.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from pathlib import Path

from . import output
from .config import Config
from .protocol import local_ip_and_mac
from .scanning import BATCH_END, as_jpeg, decode_sense

MAGIC = b"VENS"
PORT_CONTROL = 53218
PORT_REQUEST = 53219
PORT_ANNOUNCE = 52217
PORT_BUTTON_NOTIFY = 55265
OP_SCSI = 0x01
OP_REGISTER = 0x11
OP_BUTTON_NOTICE = 0x01

# e9 config and d4 parameter blocks, captured verbatim from an iX1300 scanning
# 300 dpi colour duplex. The geometry fields (012c012c = 300x300 dpi, and the
# page extents) live inside these; they are not fully decoded, so like the
# iX1500 path this transport is fixed at whatever the capture used.
E9_CONFIG = bytes.fromhex(
    "012c012c00002880000043500500000000000000000000000000000000000000"
)
D4_PARAMS = bytes.fromhex(
    "000301010000c1808080908080000000000000000000000000000000000000300010"
    "012c012c05820d000000288000004350040000000000000000000000010000000000"
    "000000000000000000000000"
)
assert len(E9_CONFIG) == 32 and len(D4_PARAMS) == 80


def signed(v: int) -> int:
    return v - (1 << 32) if v > 0x7FFFFFFF else v


def frame(opcode: int, payload: bytes = b"", flags: int = 0) -> bytes:
    body = MAGIC + struct.pack(">II", opcode, flags) + payload
    return struct.pack(">I", len(body) + 4) + body


def parse_frame(buf: bytes):
    if len(buf) < 16 or buf[4:8] != MAGIC:
        return None
    total = struct.unpack(">I", buf[0:4])[0]
    opcode, flags = struct.unpack(">II", buf[8:16])
    return opcode, flags, buf[16:total]


class Scanner:
    """A VENS control session on TCP 53218."""

    def __init__(self, host: str, timeout: float = 120.0):
        self.host = host
        self.timeout = timeout
        self.ip, self.mac, _ = local_ip_and_mac(host)
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, PORT_CONTROL), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.sock.recv(4096)  # the scanner greets first

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def scsi(self, cdb: bytes, read_len: int = 0, out: bytes = b"",
             collect: bool = False, quiet: float = 6.0):
        """Tunnel one SCSI CDB. Body layout identical to the ssNR transport."""
        if self.sock is None:
            raise OSError("not connected")
        body = bytearray(0x30)
        body[0:6] = self.mac
        struct.pack_into(">I", body, 0x10, len(cdb))
        struct.pack_into(">I", body, 0x14, read_len)
        if out:
            struct.pack_into(">I", body, 0x18, cdb[4])
        body[0x20:0x20 + len(cdb)] = cdb
        self.sock.sendall(frame(OP_SCSI, bytes(body) + out))

        data = b""
        buf = b""
        status = None
        self.sock.settimeout(quiet)
        try:
            while True:
                chunk = self.sock.recv(262144)
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 16:
                    total = struct.unpack(">I", buf[0:4])[0]
                    if total < 16 or len(buf) < total:
                        break
                    fr, buf = buf[:total], buf[total:]
                    if status is None:
                        status = struct.unpack(">I", fr[8:12])[0]
                    if len(fr) > 16 + 0x18:
                        data += fr[16 + 0x18:]
                if not collect and status is not None and not buf:
                    break
                # Image is complete at the JPEG EOI.
                if collect and data.endswith(b"\xff\xd9"):
                    break
                # In collect mode do NOT stop just because a status frame with
                # no data arrived: the iX1300 sends an empty ack first and then
                # streams the JPEG a moment later (the page is still feeding).
                # Keep reading until EOI, the socket closes, or `quiet` elapses.
        except socket.timeout:
            pass
        # Distinguish a real status 0 from a connection that closed with no
        # reply at all (status stays None) -- the latter shows as -1 so the logs
        # do not falsely read "status 0".
        return (signed(status) if status is not None else -1), data


def hw_status(sc: Scanner) -> bytes:
    """GET_HW_STATUS (0xC2) over an already-connected session."""
    st, data = sc.scsi(
        bytes([0xC2, 0, 0, 0, 0, 0, 0, 0x00, 0x30, 0]), 0x30, collect=False, quiet=4
    )
    return data


def hopper_has_paper(block: bytes) -> bool:
    # Paper-in-tray shows as bit 0x80 of status block byte 3 (confirmed by
    # watching the byte flip 0x80<->0x00 as paper was added/removed).
    return len(block) > 3 and bool(block[3] & 0x80)


def scanner_id(host: str) -> bytes:
    """The scanner's own 8-byte id, needed in the registration payload.

    It appears at offset 0x20 of the GET_HW_STATUS data block. Registration is
    refused unless this exact value is echoed back at payload offset 0x5c.
    """
    sc = Scanner(host)
    sc.connect()
    try:
        block = hw_status(sc)
    finally:
        sc.close()
    return block[0x20:0x28] if len(block) >= 0x28 else b"\x00" * 8


def registration_payload(host_ip: str, mac: bytes, sid: bytes,
                         trigger_port: int = PORT_BUTTON_NOTIFY, intent: int = 0) -> bytes:
    """The 112-byte VENS opcode-0x11 registration body.

    Same field layout as the iX1500 ssNR registration (MAC at 0x00, intent at
    0x14, host IP at 0x1c, notify port at 0x20, timestamp at 0x54) but shorter,
    and carrying the SCANNER's id at 0x5c rather than a host id. The timestamp
    is validated by the scanner, so it must be a real current local time.
    """
    p = bytearray(112)
    p[0:6] = mac
    p[0x10:0x14] = bytes([0x00, 0x10, 0x1E, 0x00])
    struct.pack_into(">I", p, 0x14, intent)
    p[0x1C:0x20] = socket.inet_aton(host_ip)
    struct.pack_into(">I", p, 0x20, trigger_port)
    t = time.localtime()
    struct.pack_into(">H", p, 0x54, t.tm_year)
    p[0x56], p[0x57], p[0x58] = t.tm_mon, t.tm_mday, t.tm_hour
    p[0x59], p[0x5A] = t.tm_min, t.tm_sec
    p[0x5C:0x64] = sid
    p[0x64:0x68] = bytes([0x00, 0x00, 0x62, 0x70])
    return bytes(p)


def _req53219(host: str, opcode: int, body: bytes) -> int:
    """Send one VENS request on 53219, return the reply status (0 = ok)."""
    frame = MAGIC + struct.pack(">II", opcode, 0) + body
    pkt = struct.pack(">I", len(frame) + 4) + frame
    with socket.create_connection((host, PORT_REQUEST), timeout=5) as s:
        s.settimeout(5)
        s.recv(4096)  # greeting
        s.sendall(pkt)
        buf = b""
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                buf += c
                s.settimeout(1.0)
        except socket.timeout:
            pass
    off = 16 if buf[:4] == b"\x00\x00\x00\x10" else 0
    if len(buf) < off + 12:
        return -1
    return signed(struct.unpack(">I", buf[off + 8:off + 12])[0])


def register(host: str, ip: str, mac: bytes, sid: bytes, retries: int = 6, log=print) -> int:
    """Register this host, using ScanSnap Home's full sequence.

    A bare opcode-0x11 register is unreliable -- the scanner often refuses it
    with -1. The vendor software wraps it: INFO (0x13), op30, REGISTER (0x11),
    op30, op62 x2. Replicating that makes registration stick. Returns the
    REGISTER status (0 = success). Retries a few times on -1 (transient
    contention with another host holding the single registration slot).
    """
    info_body = mac + bytes(14)
    op30_body = mac + bytes(10)
    op62_sub1 = mac + bytes.fromhex("0000000000000000000000000001ffffffff0000000000000000")
    op62_sub2 = mac + bytes.fromhex("0000000000000000000000000002000000000000000000000000")
    reg_body = registration_payload(ip, mac, sid)

    st = -1
    for attempt in range(retries):
        _req53219(host, 0x13, info_body)          # INFO
        _req53219(host, 0x30, op30_body)          # op30
        st = _req53219(host, OP_REGISTER, reg_body)  # REGISTER
        if st == 0:
            _req53219(host, 0x30, op30_body)      # op30
            _req53219(host, 0x62, op62_sub1)      # op62 (sub 1)
            _req53219(host, 0x62, op62_sub2)      # op62 (sub 2)
            return 0
        if attempt < retries - 1:
            time.sleep(2.0)
    return st


def announce(sock: socket.socket, host: str, ip: str, mac: bytes) -> None:
    """Tell the scanner where to send button notices (UDP 52217).

    This is the iX1300's stand-in for registration: a small VENS datagram
    carrying the host IP and MAC. Without it the scanner has nowhere to send the
    Scan-button notice.
    """
    p = bytearray(32)
    p[0:4] = MAGIC
    struct.pack_into(">I", p, 4, 0x01)
    p[8:12] = socket.inet_aton(ip)
    p[12:18] = mac
    # Trailing constant seen in the capture (includes the notify port hint).
    p[22:26] = bytes([0xD7, 0xE0, 0x10, 0x00])
    try:
        sock.sendto(bytes(p), (host, PORT_ANNOUNCE))
    except OSError:
        pass


def scan_batch(sc: Scanner, out_prefix: str, max_sheets: int = 100, log=print) -> int:
    """Pull every sheet in the hopper. Returns sides written."""
    setup = [
        ("d8 begin", [0xD8, 0, 0, 0, 0, 0], 0, b""),
        ("e9 config", [0xE9, 0, 0, 0, 0, 0, 0, 0x20, 0, 0], 0, E9_CONFIG),
        ("d4 params", [0xD4, 0, 0, 0, 0x50, 0], 0, D4_PARAMS),
    ]
    for label, cdb, rl, out in setup:
        st, _ = sc.scsi(bytes(cdb), rl, out)
        log(f"  {label:<10} {st}")
        if st != 0:
            log(f"  aborting: {label} failed")
            return 0

    # Match the capture: a status read + sense immediately after d4, with no
    # idle gap. Pausing here instead lets the scanner close the control
    # connection (observed as a broken pipe on the first e0).
    sc.scsi(bytes([0xC2, 0, 0, 0, 0, 0, 0, 0x00, 0x30, 0]), 0x30)
    sc.scsi(bytes([0x03, 0, 0, 0, 0x12, 0]), 0x12)

    pages = 0
    stopped = f"reached the {max_sheets}-sheet limit"
    done = False
    try:
        for sheet in range(1, max_sheets + 1):
            st, _ = sc.scsi(bytes([0xE0, 0, 0, 0, 0, 0]))
            log(f"  sheet {sheet} e0 START {st}")
            if st != 0:
                stopped = f"e0 refused for sheet {sheet} (status {st})"
                break
            got = 0
            for side, tag, last in ((0x00, "front", 0), (0x80, "back", 1)):
                _st, raw = sc.scsi(
                    bytes([0x28, 0, 0, 0x02, 0, side, 0x30, 0, 0, 0, last, 0]),
                    0x300000, collect=True, quiet=20,
                )
                jpg = as_jpeg(raw)
                if jpg and len(jpg) > 10000:
                    pages += 1
                    path = f"{out_prefix}-{pages:04d}.jpg"
                    with open(path, "wb") as fh:
                        fh.write(jpg)
                    log(f"  sheet {sheet} {tag:<6} {len(jpg):>9,} bytes -> {path}")
                    got += 1
                else:
                    log(f"  sheet {sheet} {tag:<6} no image (read status {_st}, "
                        f"{len(raw)} bytes, head={raw[:16].hex()})")

                _, sense = sc.scsi(bytes([0x03, 0, 0, 0, 0x12, 0]), 0x12)
                d = decode_sense(sense)
                if d:
                    key, asc, ascq, eom, ili = d
                    end = BATCH_END.get((key, asc, ascq))
                    if end:
                        stopped, done = end[0], True
                    elif key != 0:
                        stopped = f"sense key {key:#x} asc {asc:#04x} ascq {ascq:#04x}"
                        done = True
                    if done:
                        log(f"  sheet {sheet} {tag:<6} -> {stopped}")
                        break
                sc.scsi(bytes([0x28, 0, 0x80, 0, 0, side, 0, 0, 0x20, 0, 0, 0]), 0x20)
            if done:
                break
            if not got:
                stopped = "no image data"
                break
            block = hw_status(sc)
            if not hopper_has_paper(block):
                stopped = "hopper empty"
                break
        log(f"  batch ended: {stopped}")
    finally:
        # The capture ends the batch with e0 (a start with no paper behind it),
        # not d6. Sending d6 here is what the iX1500 needs; the iX1300 did not.
        try:
            st, _ = sc.scsi(bytes([0xE0, 0, 0, 0, 0, 0]))
            log(f"  e0 end     {st}")
        except OSError as exc:
            log(f"  e0 end     could not send: {exc}")
    return pages


def scan_once(cfg: Config, host: str, out_prefix: str, log=print) -> int:
    # Register first (VENS op 0x11 on 53219). Without a successful registration
    # the scanner accepts status reads but closes any scan command. Registration
    # also needs the scanner's own id, read from GET_HW_STATUS.
    ip, mac, ifn = local_ip_and_mac(host)
    sid = scanner_id(host)
    log(f"  identity: ip={ip} mac={mac.hex(':')} if={ifn} sid={sid.hex()}")
    st = register(host, ip, mac, sid, log=log)
    log(f"  register: status {st}")
    if st != 0:
        log("  registration failed; the scanner will refuse to scan")
        return 0

    sc = Scanner(host)
    sc.connect()
    try:
        block = hw_status(sc)
        log(f"  hw_status block: {block.hex()}")
        return scan_batch(sc, out_prefix, int(cfg.num("max_sheets", 100)), log=log)
    finally:
        sc.close()


def stamp() -> str:
    return time.strftime("%H:%M:%S")


def serve(cfg: Config, host: str, log=print) -> int:
    """Register as a keep-alive, then scan when the Scan button is pressed."""
    import tempfile

    ip, mac, _ = local_ip_and_mac(host)
    interval = cfg.num("interval", 15.0)
    busy = threading.Lock()
    last_done = [0.0]

    try:
        sid = scanner_id(host)
    except OSError as exc:
        log(f"cannot reach scanner: {exc}")
        return 1

    def do_scan(source: str) -> None:
        if not busy.acquire(blocking=False):
            return
        try:
            if time.monotonic() - last_done[0] < 5.0:
                return
            log(f"[{stamp()}] SCAN BUTTON PRESSED via {source}")
            work = Path(tempfile.mkdtemp(prefix="panelbeater-"))
            try:
                n = scan_once(cfg, host, str(work / "page"), log=log)
            except OSError as exc:
                log(f"  scan failed: {exc}")
                n = 0
            if n:
                pages = sorted(str(p) for p in work.glob("page-*.jpg"))
                threading.Thread(
                    target=lambda: output.finish(
                        pages, time.strftime("%Y%m%d-%H%M%S"), cfg, log=log)
                ).start()
        finally:
            last_done[0] = time.monotonic()
            busy.release()

    # Button-notice listener (scanner -> host UDP 55265, VENS op 0x01).
    notify = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    notify.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    notify.bind(("", PORT_BUTTON_NOTIFY))

    def listener():
        seen = 0.0
        while True:
            try:
                data, addr = notify.recvfrom(4096)
            except OSError:
                return
            if addr[0] != host:
                continue
            parsed = parse_frame(data)
            op = parsed[0] if parsed else -1
            now = time.monotonic()
            if now - seen < 3.0:  # notices arrive in triplicate
                continue
            seen = now
            log(f"[{stamp()}] notice from {addr[0]} op=0x{op:02x}")
            if op == OP_BUTTON_NOTICE:
                do_scan("UDP notice")

    threading.Thread(target=listener, daemon=True).start()
    log(f"[{stamp()}] iX1300 mode: registering with {host} every {interval:.0f}s, "
        f"listening on UDP {PORT_BUTTON_NOTIFY}")
    try:
        while True:
            st = register(host, ip, mac, sid, log=log)
            if st != 0:
                log(f"[{stamp()}] registration refused (status {st})")
            time.sleep(interval)
    except KeyboardInterrupt:
        log("")
    return 0
