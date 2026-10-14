# SOME/IP Monitor — SBC Agent + PC GUI

Starter project for monitoring SOME/IP and SOME/IP-SD traffic from an SBC and viewing it on a PC.

## Components

- `sbc_agent/`: C++17 UDP telemetry/control agent with packet-capture abstraction.
- `pc_monitor/`: Python/PySide6 GUI.
- Packet capture currently uses **libpcap**. QNX SDP 8.0 has pcap-related packages, but you must verify that the pcap headers/library are installed in your host SDP and that the package is included in the target image. If not, implement the `CaptureBackend` using QNX io-sock BPF (`/dev/bpf`) as a separate backend.
- The SOME/IP parser handles Ethernet + IPv4 + UDP/TCP packets and decodes basic SOME/IP-SD entries (OfferService, FindService, SubscribeEventgroup, SubscribeEventgroupAck). This is an MVP, not a complete AUTOSAR-compliant dissector.

## Network ports

- PC -> SBC control: UDP 47000
- SBC -> PC telemetry: UDP 47001
- SOME/IP-SD default destination port: 30490 (configurable through source code for now)

The PC IP is configured when starting the agent.

## Linux build (host or SBC)

Dependencies:
- C++17 compiler
- CMake 3.16+
- libpcap development headers/library

```bash
cd sbc_agent
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo ./build/someip_agent --iface eth0 --pc-ip 192.168.1.5
```

Use `--iface` for your interface (e.g. `eth0`, `enp1s0`). Capture generally requires root or appropriate packet-capture capabilities.

## QNX SDP 8.0 notes

1. Verify the pcap headers and library in your installed SDP and target image.
2. Build with the QNX aarch64 toolchain configured in your environment. For example, if that variant exists:
   ```bash
   q++ -Vgcc_ntoaarch64le_cxx ...
   ```
   Prefer a CMake toolchain file configured for your actual SDP installation.
3. Ensure the target has the relevant io-sock networking stack, interface driver, and permissions for packet capture.
4. If pcap is unavailable, do not assume Linux `AF_PACKET` works on QNX. Add a QNX-specific BPF backend using the documented `/dev/bpf` interface and ioctls.
5. Do not claim QNX compilation success until you build and run it on your installed SDP/target.

## Run the GUI

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install PySide6
python3 pc_monitor/main.py
```

In the GUI, set the PC IP that the SBC can reach, then click **Start agent listener**. Start the SBC agent with the same PC IP. Send `START` or `STOP` commands from the GUI.

## Control protocol

Commands are plain UTF-8 UDP datagrams:
- `START`
- `STOP`
- `GET_STATUS`
- `GET_SERVICES`
- `SET_FILTER <pcap-filter-expression>`

The GUI sends commands to the SBC control port. Telemetry datagrams are JSON objects:
- `{"type":"status", ...}`
- `{"type":"packet", ...}`
- `{"type":"service", ...}`
- `{"type":"sd", ...}`

## Limitations / next steps

- Capture is local to the SBC interface. A PC connected to an ordinary switch will not necessarily see unicast packets between two other devices.
- Current service tracking is an MVP; TTL expiry is applied when processing SD packets, not by a periodic expiry timer.
- TCP payload reassembly is not implemented. TCP packets are decoded only when a complete SOME/IP message is present in one captured segment.
- IPv6, VLAN-tagged Ethernet, SOME/IP-TP segmentation, malformed-packet hardening, and full AUTOSAR SD option parsing need further implementation.
- This project is a starting implementation and should be tested with real traffic before being used for debugging or production.
