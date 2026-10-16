# SOME/IP & SOME/IP-SD Test Checklist & Automated Test Suite

## 1. Automated Test Suite

### C++ Dissector Tests
Located in `sbc_agent/tests/test_dissector.cpp`:
- Tests SOME/IP standard Request message parsing (header fields, client/session, payload hex).
- Tests SOME/IP-TP (Transport Protocol) message parsing (TP header, offset in bytes, more segments flag).
- Tests SOME/IP-SD OfferService with IPv4 Endpoint Option (SD flags, entry fields, TTL, option resolution and linking).
- Tests 802.1Q VLAN tagged Ethernet frame unwrapping.

To run:
```bash
# Build via CMake or direct compiler:
cd sbc_agent
g++ -std=c++17 -Wall -Wextra -I include src/someip/someip_dissector.cpp tests/test_dissector.cpp -o test_dissector
./test_dissector
```

### Python Decoder Tests
Located in `tests/test_someip_decoder.py`:
- Tests `decode_someip()` for Requests, Notifications, and SOME/IP-TP.
- Tests `decode_sd()` for OfferService, SubscribeEventgroup, and Acks.
- Tests `format_hex_dump()` Wireshark-style representation.
- Tests `interpret_payload()` across multiple data types and telemetry sensor pattern (`>If`).

To run:
```bash
python -m unittest tests/test_someip_decoder.py
```

---

## 2. Manual Live Testing Checklist

1. Start the GUI:
   ```bash
   python pc_monitor/main.py
   ```
2. Click **Start listener** on the PC.
3. Start the SBC Agent on target (Linux or QNX):
   - Linux:
     ```bash
     sudo ./someip_agent --iface eth0 --pc-ip <PC_IP>
     ```
   - QNX:
     ```bash
     ./someip_agent --iface dmfe0 --pc-ip <PC_IP> --backend bpf
     ```
4. Verify initial connection in the **Agent Logs** and **Status Bar**.
5. Generate SOME/IP traffic (e.g. run `python comsumer.py`).
6. In GUI:
   - Click on any packet row to inspect the collapsible **Packet Dissection Details** tree.
   - Verify Service ID, Method/Event flag, Client ID, Session ID, and Message Type.
   - Verify the **Raw Payload Hex & Interpretations** pane.
7. Send SOME/IP-SD OfferService or start a service provider:
   - Check the **Discovered Services (Catalog)** tab.
   - Confirm Provider Endpoint IP:Port, Protocol, and TTL countdown.
8. Filter test:
   - Filter by Service ID (e.g. `0x1234`) or search keyword in the toolbar.
   - Filter by Message Type dropdown (e.g. `NOTIFICATION`, `REQUEST`, `SOME/IP-SD Only`).
9. Click **Export JSON** to verify captured packets can be saved for offline analysis.
