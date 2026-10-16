#ifndef SOMEIP_DISSECTOR_H
#define SOMEIP_DISSECTOR_H

#include "someip_types.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace someip {

class SomeIpDissector {
public:
    explicit SomeIpDissector(size_t max_payload_preview = 256);

    // Dissects an Ethernet frame (with or without 802.1Q VLAN tag).
    // Returns a vector of dissected SOME/IP messages (since a single frame
    // or L4 payload can contain multiple SOME/IP PDUs).
    std::vector<DissectedMessage> dissect_frame(const uint8_t* frame, size_t len);

    // Dissects SOME/IP messages directly from L4 payload (UDP/TCP data)
    std::vector<DissectedMessage> dissect_l4_payload(
        const uint8_t* payload, size_t len,
        const std::string& transport,
        const std::string& src_ip, uint16_t src_port,
        const std::string& dst_ip, uint16_t dst_port
    );

    // Dissects a single SOME/IP message at payload pointer
    bool dissect_someip_pdu(
        const uint8_t* pdu, size_t pdu_len,
        DissectedMessage& out_msg
    );

    // Dissects SOME/IP-SD payload starting at SD flags (after 16-byte SOME/IP header)
    bool dissect_sd(
        const uint8_t* sd_payload, size_t sd_len,
        SomeIpSdMessage& out_sd
    );

    // Converts a DissectedMessage to JSON representation
    std::string to_json(const DissectedMessage& msg) const;

    // Helper: escape JSON string
    static std::string json_escape(const std::string& in);

    // Helper: format bytes to hex string
    static std::string bytes_to_hex(const uint8_t* data, size_t len);

private:
    size_t max_payload_preview_;

    static uint16_t read_be16(const uint8_t* p) {
        return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
    }
    static uint32_t read_be24(const uint8_t* p) {
        return (static_cast<uint32_t>(p[0]) << 16) |
               (static_cast<uint32_t>(p[1]) << 8) | p[2];
    }
    static uint32_t read_be32(const uint8_t* p) {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) | p[3];
    }
};

} // namespace someip

#endif // SOMEIP_DISSECTOR_H
