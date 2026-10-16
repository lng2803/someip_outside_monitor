#include "someip/someip_dissector.h"
#include "someip/someip_types.h"

#include <cassert>
#include <iostream>
#include <vector>

void test_someip_request() {
    std::cout << "Running test_someip_request...\n";
    // SOME/IP Request: Service=0x1234, Method=0x0001, Length=16 (8 hdr + 8 payload),
    // Client=0x0001, Session=0x0042, Proto=1, Iface=1, Type=0x00 (REQUEST), Code=0x00 (E_OK)
    // Payload = 8 bytes
    std::vector<uint8_t> pdu = {
        0x12, 0x34, 0x00, 0x01, // Service ID 0x1234, Method ID 0x0001
        0x00, 0x00, 0x00, 0x10, // Length = 16 (0x10)
        0x00, 0x01, 0x00, 0x42, // Client ID 0x0001, Session ID 0x0042
        0x01, 0x01, 0x00, 0x00, // Proto 1, Iface 1, Type REQUEST (0x00), Code E_OK (0x00)
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE  // 8 bytes payload
    };

    someip::SomeIpDissector dissector;
    someip::DissectedMessage msg;
    bool ok = dissector.dissect_someip_pdu(pdu.data(), pdu.size(), msg);
    assert(ok);
    assert(msg.header.service_id == 0x1234);
    assert(msg.header.method_id == 0x0001);
    assert(!msg.header.is_event);
    assert(msg.header.length == 16);
    assert(msg.header.client_id == 0x0001);
    assert(msg.header.session_id == 0x0042);
    assert(msg.header.protocol_version == 1);
    assert(msg.header.interface_version == 1);
    assert(msg.header.message_type == someip::MessageType::REQUEST);
    assert(msg.header.return_code == someip::ReturnCode::E_OK);
    assert(!msg.header.is_tp);
    assert(msg.payload_len == 8);
    assert(msg.payload_hex_preview == "deadbeefcafebabe");
    assert(!msg.is_sd);

    std::string json = dissector.to_json(msg);
    assert(json.find("\"protocol\":\"SOME/IP\"") != std::string::npos);
    assert(json.find("\"msg_type_name\":\"REQUEST\"") != std::string::npos);
    assert(json.find("\"service\":\"0x1234\"") != std::string::npos);
    std::cout << "test_someip_request passed!\n";
}

void test_someip_tp_notification() {
    std::cout << "Running test_someip_tp_notification...\n";
    // Event ID 0x8123 (bit 15 set), Type=0x22 (TP_NOTIFICATION)
    // Length = 16 (8 standard + 4 TP header + 4 payload)
    std::vector<uint8_t> pdu = {
        0x12, 0x34, 0x81, 0x23, // Service 0x1234, Event 0x8123
        0x00, 0x00, 0x00, 0x10, // Length = 16
        0x00, 0x01, 0x00, 0x05, // Client 0x0001, Session 0x0005
        0x01, 0x01, 0x22, 0x00, // Proto 1, Iface 1, Type TP_NOTIFICATION (0x22), Code E_OK
        0x00, 0x00, 0x01, 0x01, // TP Header: Offset=16 (0x10 bytes), More=1
        0x11, 0x22, 0x33, 0x44  // 4 bytes payload
    };

    someip::SomeIpDissector dissector;
    someip::DissectedMessage msg;
    bool ok = dissector.dissect_someip_pdu(pdu.data(), pdu.size(), msg);
    assert(ok);
    assert(msg.header.service_id == 0x1234);
    assert(msg.header.method_id == 0x8123);
    assert(msg.header.is_event);
    assert(msg.header.is_tp);
    assert(msg.header.tp_offset == 0x00000100);
    assert(msg.header.tp_more_segments);
    assert(msg.payload_len == 4);
    assert(msg.payload_hex_preview == "11223344");

    std::string json = dissector.to_json(msg);
    assert(json.find("\"is_tp\":true") != std::string::npos);
    assert(json.find("\"tp_more\":true") != std::string::npos);
    std::cout << "test_someip_tp_notification passed!\n";
}

void test_someip_sd_offer_with_options() {
    std::cout << "Running test_someip_sd_offer_with_options...\n";
    // SOME/IP-SD: Service=0xFFFF, Method=0x8100, Type=0x02 (NOTIFICATION)
    // SD Payload starts after 16-byte header:
    // Flags: 0xC0 (Reboot=1, Unicast=1), Reserved: 0x000000
    // Entries Length: 16 (0x00000010)
    // Entry 0: Type=0x01 (OfferService), Opt1_Idx=0, Opt2_Idx=0, Opts=(1 opt in run 1: 0x10),
    //          Service=0x1234, Instance=0x5678, Major=1, TTL=10 (0x00000A), Minor=42 (0x0000002A)
    // Options Length: 12 (0x0000000C)
    // Option 0: Length=9 (0x0009), Type=0x04 (IPv4 Endpoint), Discardable=0x00,
    //           IP=192.168.1.10 (0xC0, 0xA8, 0x01, 0x0A), Reserved=0x00, Proto=UDP (0x11), Port=3002 (0x0BBA)
    std::vector<uint8_t> pdu = {
        // SOME/IP Header (16 bytes)
        0xFF, 0xFF, 0x81, 0x00,
        0x00, 0x00, 0x00, 0x30, // Length = 48 bytes (8 hdr + 40 SD payload)
        0x00, 0x00, 0x00, 0x01,
        0x01, 0x01, 0x02, 0x00,
        // SD Flags (4 bytes)
        0xC0, 0x00, 0x00, 0x00,
        // Entries Length (4 bytes)
        0x00, 0x00, 0x00, 0x10,
        // Entry 0 (16 bytes)
        0x01, 0x00, 0x00, 0x10, // OfferService, Opt1_Idx=0, 1 Option
        0x12, 0x34, 0x56, 0x78, // Service 0x1234, Instance 0x5678
        0x01, 0x00, 0x00, 0x0A, // Major 1, TTL 10 seconds
        0x00, 0x00, 0x00, 0x2A, // Minor 42
        // Options Length (4 bytes)
        0x00, 0x00, 0x00, 0x0C,
        // Option 0 (12 bytes)
        0x00, 0x09, 0x04, 0x00, // Length 9, IPv4 Endpoint, Discardable 0
        192, 168, 1, 10,        // IP
        0x00, 0x11, 0x0B, 0xBA  // Reserved 0, Proto UDP (17), Port 3002
    };

    someip::SomeIpDissector dissector;
    someip::DissectedMessage msg;
    bool ok = dissector.dissect_someip_pdu(pdu.data(), pdu.size(), msg);
    assert(ok);
    assert(msg.is_sd);
    assert(msg.sd.reboot_flag);
    assert(msg.sd.unicast_flag);
    assert(msg.sd.entries.size() == 1);

    const auto& entry = msg.sd.entries[0];
    assert(entry.type == someip::SdEntryType::OFFER_SERVICE);
    assert(entry.service_id == 0x1234);
    assert(entry.instance_id == 0x5678);
    assert(entry.major_version == 1);
    assert(entry.minor_version == 42);
    assert(entry.ttl == 10);
    assert(entry.type_name == "OfferService");

    // Option verification
    assert(msg.sd.options.size() == 1);
    const auto& opt = msg.sd.options[0];
    assert(opt.type == someip::SdOptionType::IPV4_ENDPOINT);
    assert(opt.ip == "192.168.1.10");
    assert(opt.proto == "UDP");
    assert(opt.port == 3002);

    // Option reference resolution
    assert(entry.endpoint_options.size() == 1);
    assert(entry.endpoint_options[0].ip == "192.168.1.10");
    assert(entry.endpoint_options[0].port == 3002);

    std::string json = dissector.to_json(msg);
    assert(json.find("\"type\":\"sd_packet\"") != std::string::npos);
    assert(json.find("\"type_name\":\"OfferService\"") != std::string::npos);
    assert(json.find("\"endpoints\":[{\"ip\":\"192.168.1.10\",\"port\":3002") != std::string::npos);

    std::cout << "test_someip_sd_offer_with_options passed!\n";
}

void test_ethernet_vlan_frame() {
    std::cout << "Running test_ethernet_vlan_frame...\n";
    // Ethernet + 802.1Q VLAN (VLAN ID 100) + IPv4 + UDP + SOME/IP Request
    std::vector<uint8_t> frame = {
        // Ethernet Header: Dst MAC (6), Src MAC (6), 802.1Q tag (4)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0x81, 0x00, 0x00, 0x64, // EtherType 0x8100, VLAN ID 100
        0x08, 0x00,             // EtherType 0x0800 (IPv4)
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x34, // Ver 4, IHL 5 (20 bytes), Total len 52
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // TTL 64, Proto 17 (UDP)
        192, 168, 1, 10,        // Src IP
        192, 168, 1, 20,        // Dst IP
        // UDP Header (8 bytes)
        0x0B, 0xBA, 0x0B, 0xBB, // Src Port 3002, Dst Port 3003
        0x00, 0x20, 0x00, 0x00, // UDP Len 32 (8 hdr + 24 SOME/IP)
        // SOME/IP Message (24 bytes)
        0x12, 0x34, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x01, 0x00, 0x01,
        0x01, 0x01, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    someip::SomeIpDissector dissector;
    auto msgs = dissector.dissect_frame(frame.data(), frame.size());
    assert(msgs.size() == 1);
    assert(msgs[0].src_ip == "192.168.1.10");
    assert(msgs[0].src_port == 3002);
    assert(msgs[0].dst_ip == "192.168.1.20");
    assert(msgs[0].dst_port == 3003);
    assert(msgs[0].transport == "UDP");
    assert(msgs[0].header.service_id == 0x1234);
    assert(msgs[0].header.method_id == 0x0002);
    assert(msgs[0].payload_len == 8);

    std::cout << "test_ethernet_vlan_frame passed!\n";
}

int main() {
    std::cout << "=== SOME/IP Dissector Unit Tests ===\n";
    test_someip_request();
    test_someip_tp_notification();
    test_someip_sd_offer_with_options();
    test_ethernet_vlan_frame();
    std::cout << "All C++ dissector tests passed successfully!\n";
    return 0;
}
