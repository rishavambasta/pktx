# pktx - Network Equipment Packet Generator & Tester in C

`pktx` is a modular, high-performance C tool designed for testing network equipment. It provides capabilities for constructing, parsing, editing, stream-saving, and transmitting Layer 2 (Ethernet II) and Layer 3 (IPv4) packets.

---

## Key Features

1. **Protocol Header Construction & Field Validation**:
   - **L2 Ethernet II**: Destination MAC, Source MAC, EtherType (default: `0x0800` IPv4).
   - **L3 IPv4**: Source IP, Destination IP, Version, IHL, TOS/DSCP, Identification, Flags (DF, MF), Fragment Offset, TTL, Protocol (UDP, TCP, ICMP, Raw), Header Checksum (auto RFC 1071 calculation or custom override).
   - **Validation & Default Suggestions**: Every field is validated with suggested defaults for rapid testing.

2. **Payload Patterns**:
   - **All 0s (`0x00...00`)**
   - **All 1s (`0xFF...FF`)**
   - **Pseudo-Random Pattern**

3. **Ethernet II Standard Frame Sizing**:
   - Dynamic size control bounded between **64 and 1514 bytes** per Ethernet II specifications. Automatic zero-padding for sub-min payload frames.

4. **Stream File (`.strm`) Format**:
   - Save created or edited packet streams into binary `.strm` stream files.
   - Re-load `.strm` files anytime for immediate or deferred packet playback and transmission.

5. **Wireshark PCAP / PCAPNG Parser**:
   - Native pure-C parser for `.pcap` and `.pcapng` files (Section Header, Interface Description, Enhanced & Simple Packet Blocks).
   - Extract captured Ethernet & IPv4 frames, inspect headers, edit fields, convert to `.strm`, or re-transmit.

6. **Flexible Packet Transmission**:
   - Transmission via Linux `AF_PACKET` raw sockets.
   - Configurable repetition count ($1 \dots N$ or continuous).
   - Configurable Inter-Packet Gap (IPG) or custom delay in milliseconds.
   - **Dry-Run Simulation Mode**: Enables safe testing without root raw socket permissions or physical wire transmission.

---

## Directory Structure

```
pktx/
├── include/          # Header files
│   ├── pktx.h        # Global definitions & bounds
│   ├── ethernet.h    # L2 Ethernet II structs & parsing/building
│   ├── ipv4.h        # L3 IPv4 header structs & checksum engine
│   ├── payload.h     # Payload pattern generators
│   ├── strm.h        # Binary .strm format specification & file I/O
│   ├── pcapng.h      # Pcap & Pcapng block reader
│   ├── transmitter.h # Raw socket packet TX & dry-run simulation
│   ├── cli.h         # Interactive wizard & command line parser
│   └── utils.h       # MAC/IP parsers, hex dump, checksum utils
├── src/              # Implementation files
│   ├── ethernet.c
│   ├── ipv4.c
│   ├── payload.c
│   ├── strm.c
│   ├── pcapng.c
│   ├── transmitter.c
│   ├── cli.c
│   ├── utils.c
│   └── main.c
├── tests/            # Test suite
│   └── test_pktx.c
├── samples/          # Sample capture and stream files
│   ├── sample.pcapng
│   └── converted.strm
└── Makefile          # Build configuration
```

---

## Build & Test Instructions

### Building the Project
```bash
make
```
This produces two binaries:
- `pktx`: The primary CLI and interactive tool.
- `pktx_test`: The unit test suite.

### Running Unit Tests
```bash
make test
```

---

## Usage Guide

### 1. Interactive Menu Mode (Default)
Run `./pktx` without arguments to launch the interactive terminal wizard:
```bash
./pktx
```
The wizard guides you through:
1. Selecting L2 (Ethernet) or L3 (IPv4).
2. Entering header fields with default values.
3. Choosing payload type (All 0s, All 1s, Pseudo-random).
4. Setting packet size (64 - 1514 bytes).
5. Saving packet configuration into `.strm` stream format.
6. Transmitting packets with repetition count and delay (IPG in ms).

### 2. Command-Line (CLI) Flag Mode

- **Construct & Transmit L2 Ethernet Frame**:
  ```bash
  ./pktx --l2 --src-mac 00:11:22:33:44:55 --dst-mac FF:FF:FF:FF:FF:FF --size 128 --payload ones --save frame_l2.strm --tx eth0 --count 10 --delay 100
  ```

- **Construct & Transmit L3 IPv4 Packet**:
  ```bash
  ./pktx --l3 --src-ip 192.168.1.100 --dst-ip 192.168.1.1 --proto 17 --size 256 --payload rand --save pkt_l3.strm --tx eth0 --count 50 --delay 10
  ```

- **Load & Re-transmit `.strm` File**:
  ```bash
  ./pktx --load pkt_l3.strm --tx eth0 --count 100 --delay 5
  ```

- **Parse Wireshark `.pcapng` File & Save to `.strm`**:
  ```bash
  ./pktx --pcap samples/sample.pcapng --save samples/converted.strm --tx lo --dry-run
  ```

- **Dry-Run Simulation Mode**:
  Add `--dry-run` or `-n` to any transmit command to simulate packet send without root socket access:
  ```bash
  ./pktx --l3 --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --tx lo --dry-run
  ```

---

## Binary `.strm` Format Specification

The `.strm` file structure consists of a global binary file header followed by packet stream entries:

1. **File Header (16 bytes)**:
   - `magic` (4 bytes): `0x504B5458` (`"PKTX"`)
   - `version` (2 bytes): `1`
   - `protocol_level` (2 bytes): `2` (L2) or `3` (L3)
   - `num_packets` (4 bytes): Count of packet entries
   - `reserved` (4 bytes): Padding

2. **Packet Entry Header (12 bytes per packet)**:
   - `pkt_len` (4 bytes): Frame length in bytes ($64 \le \text{pkt\_len} \le 1514$)
   - `delay_ms` (4 bytes): Inter-packet gap in milliseconds
   - `repetitions` (4 bytes): Transmit repeat count

3. **Packet Bytes**:
   - `raw_data`: Exactly `pkt_len` bytes of frame data.
