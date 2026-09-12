# ScanSnap iX1300 network protocol ("VENS") — reverse-engineering notes

Derived from a 55 s packet capture of ScanSnap Home (host) talking
to an iX1300 , covering connect, idle polling, and one duplex scan.

## Summary

The iX1300 is **not** the iX1500 platform. It speaks a related but distinct
protocol. The frame envelope is identical to the iX1500's `ssNR`, but:

| Aspect            | iX1500 (`ssNR`)                     | iX1300 (`VENS`)                 |
|-------------------|-------------------------------------|---------------------------------|
| Frame magic       | `ssNR`                              | `VENS`                          |
| Registration/host list | ssNR JSON on TCP 53219         | **none** — no 53219 at all      |
| Enrolment         | required                            | **not a concept**               |
| SCSI passthrough  | ssNR op 0x01 on TCP 53218           | VENS op 0x01 on TCP 53218       |
| Button notice     | UDP 55265, ssNR op 0x01             | UDP 55265, VENS op 0x01         |
| Host announce     | via registration                    | VENS datagram to UDP 52217      |
| GET_HW_STATUS     | single frame, data at 0x18          | status frame + data frame       |
| Hopper-empty bit  | data block byte 3, mask 0x80        | data block **byte 7**, mask 0x80|

## Frame format (both directions)

    u32 BE total_length (whole frame) | "VENS" | u32 BE opcode | u32 BE flags | body

Opcode 0x01 = SCSI passthrough (requests) and the button notice. Replies use
opcode 0 with the SCSI status in the opcode/flags area; a 16-byte opcode-0 frame
is the greeting the scanner sends on connect (must be read before sending).

## SCSI passthrough body (TCP 53218)

Byte-for-byte the same as panelbeater's `session.Session.scsi`:

    0x00  host MAC (6 bytes)
    0x10  u32 BE CDB length
    0x14  u32 BE transfer (read/alloc) length
    0x18  u32 BE = CDB[4] when a data-out payload follows
    0x20  CDB
    ...   data-out payload (e.g. d4/e9 parameter blocks), appended after body

## Scan sequence (one duplex sheet)

    d8 00 00 00 00 00                      begin           (no payload)
    e9 00 00 00 00 00 00 20 00 00          config          (+32-byte E9_CONFIG)
    d4 00 00 00 50 00                      params          (+80-byte D4_PARAMS)
    e0 00 00 00 00 00                      start sheet
    28 00 00 02 00 00 30 00 00 00 00 00    READ front (side 0x00) -> JPEG
    03 00 00 00 12 00                      REQUEST SENSE
    28 00 00 02 00 80 30 00 00 00 01 00    READ back  (side 0x80, last=1) -> JPEG
    03 00 00 00 12 00                      REQUEST SENSE
    28 00 80 00 00 80 00 00 20 00 00 00    READ 0x20 tail
    c2 ...                                 GET_HW_STATUS (hopper check)
    e0 / d6                                end / finish

JPEG arrives inside the 0x28 READ reply, SOI a few bytes into the frame payload
(panelbeater's `as_jpeg` finds it by scanning for FF D8 FF, so the offset does
not matter). ~1.5 MB per side at 300 dpi colour.

### E9_CONFIG (32 bytes)
    012c012c 00002880 00004350 05000000 00000000 00000000 00000000 00000000

### D4_PARAMS (80 bytes)
    00030101 0000c180 80809080 80000000 00000000 00000000 00000000 00000030
    0010012c 012c0582 0d000000 28800000 43500400 00000000 00000000 00010000
    00000000 00000000 00000000 00000000

(`012c` = 300 dpi; the page-extent fields are not fully decoded.)

## Button notice

On a Scan-button press the scanner sends, three times:

    from 10.x.x.x:40198  to  host:55265
    VENS op 0x01, payload begins 02 00 00 00 ...

## Host announce (stand-in for registration)

The host periodically sends a 32-byte VENS datagram to the scanner UDP 52217 so
the scanner knows where to deliver button notices. Observed from host port 55264:

    "VENS" | u32 BE 0x01 | host IPv4 | host MAC | 00000000 | D7 E0 10 00 | pad

The scanner acks with a 12-byte `VENS 80010000 00000000` on the same 5-tuple.

## GET_HW_STATUS reply

Two frames: a 16-byte opcode-0 status frame (status 0 = OK), then an opcode-0
data frame. Reading the data block from payload offset 0x18 (as panelbeater
already does) yields the 0x30-byte status block. Hopper-empty is **bit 0x80 of
block byte 0x07** (paper present when clear). The button press is delivered by
the UDP notice above, not by a status bit, so the daemon relies on the notice.

## Registration / enrolment (TCP 53219, VENS op 0x11) — THE GATE

Confirmed against a live scanner. The scanner accepts status reads from anyone,
but **closes any scan command (d8, TEST UNIT READY, etc.) unless the host has
registered.** Registration is a VENS opcode-0x11 request on TCP **53219** (no
JSON, no host-list — unlike the iX1500). 112-byte payload:

    0x00  host MAC
    0x10  00 10 1e 00                     constant
    0x14  u32 BE intent (0)
    0x1d  host IPv4                        (NOTE: 0x1d, not 0x1c)
    0x21  u32 BE notify port (0xd7e1 = 55265)
    0x54  u16 BE year, then mon,day,hour,min,sec   (validated -- use real time)
    0x5c  the scanner's own 8-byte id      (from GET_HW_STATUS block offset 0x20)
    0x64  00 00 62 70                      constant

Reply opcode 0 = success. Pairing order in the capture: INFO (0x13) then
REGISTER (0x11); "remove printer" is UNREGISTER (0x12). Once registered, the
scan sequence on 53218 delivers the JPEG (verified: 2592x3424, 300 dpi, comment
"PFU ScanSnap #iX1300"). Registration also tells the scanner where to send the
button notice (host port from 0x21), so it doubles as the keep-alive.

The ONLY reason panelbeater's original register failed: it used the ssNR magic.
The field layout is otherwise the iX1500's, shifted by one byte at the IP/port.

## Status of the panelbeater patch (panelbeater/ix1300.py)

Implemented from these notes and UNTESTED against hardware:
- VENS framing, greeting-first TCP, SCSI passthrough.
- `scan` (one-shot) and `serve` (announce + notice listener).
- No registration/enrolment.

Enable with `transport = ix1300`. Test order: `scan` with paper loaded first
(exercises the whole SCSI path), then `serve` for the button. Likely tuning
points if something misbehaves: the D4/E9 blocks, the READ tail command, and the
announce packet's trailing constant.
