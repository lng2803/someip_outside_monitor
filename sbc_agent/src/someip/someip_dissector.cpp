#include "someip/someip_dissector.h"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace someip {

SomeIpDissector::SomeIpDissector(size_t max_payload_preview)
    : max_payload_preview_(max_payload_preview) {}

std::string SomeIpDissector::json_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        if (c == '"') {
            out += "\\\"";
        } else if (c == '\\') {
            out += "\\\\";
        } else if (c == '\b') {
            out += "\\b";
        } else if (c == '\f') {
            out += "\\f";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else if (c == '\t') {
            out += "\\t";
        } else if (c >= 0x20) {
            out += static_cast<char>(c);
        } else {
            std::ostringstream ss;
            ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            out += ss.str();
        }
    }
    return out;
}

std::string SomeIpDissector::bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

std::vector<DissectedMessage> SomeIpDissector::dissect_frame(const uint8_t* frame, size_t len) {
    std::vector<DissectedMessage> results;
    if (!frame || len < 14) return results;

    // Ethernet II header
    size_t l3_offset = 14;
    uint16_t ethertype = read_be16(frame + 12);

    // 802.1Q VLAN handling
    if (ethertype == 0x8100) {
        if (len < 18) return results;
        ethertype = read_be16(frame + 16);
        l3_offset = 18;
    }

    // Only IPv4 (0x0800) handled for now
    if (ethertype != 0x0800 || len < l3_offset + 20) return results;

    const uint8_t* ip_hdr = frame + l3_offset;
    const uint8_t ver_ihl = ip_hdr[0];
    const uint8_t ver = (ver_ihl >> 4) & 0x0F;
    if (ver != 4) return results;

    const size_t ihl = (ver_ihl & 0x0F) * 4;
    if (ihl < 20 || len < l3_offset + ihl) return results;

    const uint8_t proto = ip_hdr[9];
    if (proto != 17 && proto != 6) return results; // Only UDP (17) or TCP (6)

    // Format IP addresses
    std::ostringstream src_ip_ss, dst_ip_ss;
    src_ip_ss << static_cast<unsigned>(ip_hdr[12]) << "."
              << static_cast<unsigned>(ip_hdr[13]) << "."
              << static_cast<unsigned>(ip_hdr[14]) << "."
              << static_cast<unsigned>(ip_hdr[15]);
    dst_ip_ss << static_cast<unsigned>(ip_hdr[16]) << "."
              << static_cast<unsigned>(ip_hdr[17]) << "."
              << static_cast<unsigned>(ip_hdr[18]) << "."
              << static_cast<unsigned>(ip_hdr[19]);

    const std::string src_ip = src_ip_ss.str();
    const std::string dst_ip = dst_ip_ss.str();

    const size_t l4_offset = l3_offset + ihl;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    size_t app_offset = 0;
    size_t app_len = 0;
    std::string transport;

    if (proto == 17) {
        // UDP
        transport = "UDP";
        if (len < l4_offset + 8) return results;
        src_port = read_be16(frame + l4_offset);
        dst_port = read_be16(frame + l4_offset + 2);
        uint16_t udp_len = read_be16(frame + l4_offset + 4);
        app_offset = l4_offset + 8;
        if (len < app_offset) return results;
        app_len = len - app_offset;
        if (udp_len >= 8 && static_cast<size_t>(udp_len - 8) < app_len) {
            app_len = udp_len - 8;
        }
    } else {
        // TCP
        transport = "TCP";
        if (len < l4_offset + 20) return results;
        src_port = read_be16(frame + l4_offset);
        dst_port = read_be16(frame + l4_offset + 2);
        size_t tcp_hdr_len = ((frame[l4_offset + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20 || len < l4_offset + tcp_hdr_len) return results;
        app_offset = l4_offset + tcp_hdr_len;
        app_len = len - app_offset;
    }

    if (app_len == 0) return results;

    // Filter out agent's own control (47000) and telemetry (47001) ports to avoid self-capture loops
    if (src_port == 47000 || dst_port == 47000 || src_port == 47001 || dst_port == 47001) {
        return results;
    }

    return dissect_l4_payload(frame + app_offset, app_len, transport, src_ip, src_port, dst_ip, dst_port);
}

std::vector<DissectedMessage> SomeIpDissector::dissect_l4_payload(
    const uint8_t* payload, size_t len,
    const std::string& transport,
    const std::string& src_ip, uint16_t src_port,
    const std::string& dst_ip, uint16_t dst_port) {

    std::vector<DissectedMessage> results;
    if (!payload || len < 16) return results;

    size_t offset = 0;
    while (offset + 16 <= len) {
        const uint8_t* pdu = payload + offset;
        const size_t remaining = len - offset;

        DissectedMessage msg;
        msg.transport = transport;
        msg.src_ip = src_ip;
        msg.src_port = src_port;
        msg.dst_ip = dst_ip;
        msg.dst_port = dst_port;
        msg.payload_offset = offset;

        if (!dissect_someip_pdu(pdu, remaining, msg)) {
            // Not a valid SOME/IP PDU at this offset
            break;
        }

        const size_t pdu_total_size = msg.header.total_size();
        if (pdu_total_size == 0 || pdu_total_size > remaining) {
            // Incomplete message or exceeds buffer length
            break;
        }

        results.push_back(std::move(msg));
        offset += pdu_total_size;
    }

    return results;
}

bool SomeIpDissector::dissect_someip_pdu(
    const uint8_t* pdu, size_t pdu_len,
    DissectedMessage& out_msg) {

    if (!pdu || pdu_len < 16) return false;

    // Header fields
    SomeIpHeader& hdr = out_msg.header;
    hdr.service_id = read_be16(pdu + 0);
    hdr.method_id = read_be16(pdu + 2);
    hdr.is_event = (hdr.method_id & 0x8000) != 0;
    hdr.length = read_be32(pdu + 4);

    // Sanity check: SOME/IP length covers 8 bytes of header (Request ID, Proto, Iface, Type, Code) + payload
    if (hdr.length < 8) {
        return false;
    }

    size_t full_pdu_size = static_cast<size_t>(hdr.length) + 8;
    // For UDP: In SOME/IP over UDP, the message MUST fit within the UDP datagram payload
    if (out_msg.transport == "UDP" && full_pdu_size > pdu_len) {
        return false;
    }
    // Sanity limit: max 16MB for SOME/IP message to discard non-SOME/IP garbage
    if (full_pdu_size > 16777216) {
        return false;
    }

    hdr.client_id = read_be16(pdu + 8);
    hdr.session_id = read_be16(pdu + 10);
    hdr.protocol_version = pdu[12];

    // In AUTOSAR SOME/IP, Protocol Version MUST be 0x01
    if (hdr.protocol_version != 0x01) {
        return false;
    }

    hdr.interface_version = pdu[13];

    // Message Type validation
    uint8_t raw_msg_type = pdu[14];
    if (!is_valid_message_type(raw_msg_type)) {
        return false;
    }
    hdr.message_type = static_cast<MessageType>(raw_msg_type);

    // Return Code validation
    uint8_t raw_return_code = pdu[15];
    if (!is_valid_return_code(raw_msg_type, raw_return_code)) {
        return false;
    }
    hdr.return_code = static_cast<ReturnCode>(raw_return_code);

    // Check TP (Transport Protocol) flag (bit 5 = 0x20)
    hdr.is_tp = (raw_msg_type & 0x20) != 0;

    size_t header_size = 16;
    if (hdr.is_tp) {
        if (pdu_len < 20) return false;
        uint32_t tp_word = read_be32(pdu + 16);
        hdr.tp_offset = (tp_word & 0xFFFFFFF0);
        hdr.tp_more_segments = (tp_word & 0x01) != 0;
        header_size = 20;
    }

    size_t actual_pdu_bytes = std::min(pdu_len, full_pdu_size);

    if (actual_pdu_bytes > header_size) {
        out_msg.payload_len = actual_pdu_bytes - header_size;
        const uint8_t* payload_ptr = pdu + header_size;

        // Check if this is SOME/IP-SD: Service 0xFFFF, Method 0x8100
        if (hdr.service_id == 0xFFFF && hdr.method_id == 0x8100) {
            // Validate SD specifics: notification/request, return code 0, client ID 0
            if (raw_msg_type != 0x02 && raw_msg_type != 0x00) return false;
            if (raw_return_code != 0x00) return false;
            if (hdr.client_id != 0x0000) return false;

            out_msg.is_sd = true;
            if (!dissect_sd(payload_ptr, out_msg.payload_len, out_msg.sd)) {
                return false;
            }
        }

        // Preview hex
        size_t preview_len = std::min(out_msg.payload_len, max_payload_preview_);
        out_msg.payload_hex_preview = bytes_to_hex(payload_ptr, preview_len);
    } else {
        out_msg.payload_len = 0;
        out_msg.payload_hex_preview.clear();
    }

    return true;
}

bool SomeIpDissector::dissect_sd(
    const uint8_t* sd_payload, size_t sd_len,
    SomeIpSdMessage& out_sd) {

    // SD payload:
    // flags(1), reserved(3), entries_len(4), entries..., options_len(4), options...
    if (!sd_payload || sd_len < 12) return false;

    out_sd.raw_flags = sd_payload[0];
    out_sd.reboot_flag = (out_sd.raw_flags & 0x80) != 0;
    out_sd.unicast_flag = (out_sd.raw_flags & 0x40) != 0;
    out_sd.explicit_initial_data_control = (out_sd.raw_flags & 0x20) != 0;

    const uint32_t entries_len = read_be32(sd_payload + 4);
    size_t entries_start = 8;
    if (entries_start + entries_len > sd_len) {
        return false;
    }
    size_t entries_end = entries_start + entries_len;

    // First parse options array if present
    size_t options_len_pos = entries_end;
    std::vector<SdOption> all_options;

    if (options_len_pos + 4 <= sd_len) {
        uint32_t options_len = read_be32(sd_payload + options_len_pos);
        size_t opt_start = options_len_pos + 4;
        size_t opt_end = std::min(sd_len, opt_start + options_len);

        size_t opt_ptr = opt_start;
        while (opt_ptr + 4 <= opt_end) {
            uint16_t opt_data_len = read_be16(sd_payload + opt_ptr);
            // In AUTOSAR SD, length excludes the 2-byte Length and 1-byte Type, so record length is opt_data_len + 3.
            size_t record_len = static_cast<size_t>(opt_data_len) + 3;
            if (opt_data_len == 10) {
                // Some stacks count Type in the length
                record_len = 12;
            }
            if (record_len < 4 || opt_ptr + record_len > opt_end) {
                break;
            }

            SdOption opt;
            uint8_t raw_type = sd_payload[opt_ptr + 2];
            opt.type = static_cast<SdOptionType>(raw_type);
            opt.discardable = sd_payload[opt_ptr + 3];

            if (opt.type == SdOptionType::IPV4_ENDPOINT ||
                opt.type == SdOptionType::IPV4_MULTICAST ||
                opt.type == SdOptionType::IPV4_SD_ENDPOINT) {
                if (record_len >= 12) {
                    const uint8_t* p = sd_payload + opt_ptr + 4;
                    std::ostringstream ip_ss;
                    ip_ss << static_cast<unsigned>(p[0]) << "."
                          << static_cast<unsigned>(p[1]) << "."
                          << static_cast<unsigned>(p[2]) << "."
                          << static_cast<unsigned>(p[3]);
                    opt.ip = ip_ss.str();
                    uint8_t proto_num = p[5];
                    opt.proto = (proto_num == 6) ? "TCP" : (proto_num == 17) ? "UDP" : std::to_string(proto_num);
                    opt.port = read_be16(p + 6);
                }
            } else if (opt.type == SdOptionType::IPV6_ENDPOINT ||
                       opt.type == SdOptionType::IPV6_MULTICAST ||
                       opt.type == SdOptionType::IPV6_SD_ENDPOINT) {
                if (record_len >= 24) {
                    const uint8_t* p = sd_payload + opt_ptr + 4;
                    std::ostringstream ip_ss;
                    ip_ss << std::hex << std::setfill('0');
                    for (int i = 0; i < 16; i += 2) {
                        if (i > 0) ip_ss << ":";
                        ip_ss << std::setw(2) << static_cast<unsigned>(p[i])
                              << std::setw(2) << static_cast<unsigned>(p[i+1]);
                    }
                    opt.ip = ip_ss.str();
                    uint8_t proto_num = p[17];
                    opt.proto = (proto_num == 6) ? "TCP" : (proto_num == 17) ? "UDP" : std::to_string(proto_num);
                    opt.port = read_be16(p + 18);
                }
            } else if (opt.type == SdOptionType::CONFIGURATION) {
                if (record_len > 4) {
                    const char* str_ptr = reinterpret_cast<const char*>(sd_payload + opt_ptr + 4);
                    size_t str_len = record_len - 4;
                    // Might contain null terminators or length prefix
                    opt.config_string = std::string(str_ptr, str_len);
                }
            }

            all_options.push_back(std::move(opt));
            opt_ptr += record_len;
        }
    }

    out_sd.options = all_options;

    // Parse Entries
    size_t e_ptr = entries_start;
    while (e_ptr + 16 <= entries_end) {
        SdEntry entry;
        entry.type = static_cast<SdEntryType>(sd_payload[e_ptr + 0]);
        entry.opt1_index = sd_payload[e_ptr + 1];
        entry.opt2_index = sd_payload[e_ptr + 2];
        uint8_t num_opts = sd_payload[e_ptr + 3];
        entry.opt1_count = (num_opts >> 4) & 0x0F;
        entry.opt2_count = num_opts & 0x0F;

        entry.service_id = read_be16(sd_payload + e_ptr + 4);
        entry.instance_id = read_be16(sd_payload + e_ptr + 6);
        entry.major_version = sd_payload[e_ptr + 8];
        entry.ttl = read_be24(sd_payload + e_ptr + 9);
        entry.type_name = to_string(entry.type, entry.ttl);

        if (entry.type == SdEntryType::FIND_SERVICE || entry.type == SdEntryType::OFFER_SERVICE) {
            // Service entry
            entry.minor_version = read_be32(sd_payload + e_ptr + 12);
        } else if (entry.type == SdEntryType::SUBSCRIBE_EVENTGROUP ||
                   entry.type == SdEntryType::SUBSCRIBE_EVENTGROUP_ACK) {
            // Eventgroup entry
            entry.counter = (sd_payload[e_ptr + 12] & 0x0F);
            entry.initial_data_requested = (sd_payload[e_ptr + 12] & 0x10) != 0;
            entry.eventgroup_id = read_be16(sd_payload + e_ptr + 14);
        }

        // Resolve referenced endpoint options for this entry
        auto resolve_opts = [&](uint8_t start_idx, uint8_t count) {
            for (size_t i = 0; i < count; ++i) {
                size_t idx = start_idx + i;
                if (idx < all_options.size()) {
                    entry.endpoint_options.push_back(all_options[idx]);
                }
            }
        };

        if (entry.opt1_count > 0) resolve_opts(entry.opt1_index, entry.opt1_count);
        if (entry.opt2_count > 0) resolve_opts(entry.opt2_index, entry.opt2_count);

        out_sd.entries.push_back(std::move(entry));
        e_ptr += 16;
    }

    return true;
}

std::string SomeIpDissector::to_json(const DissectedMessage& msg) const {
    std::ostringstream ss;
    ss << "{";

    if (msg.is_sd) {
        ss << "\"type\":\"sd_packet\",";
    } else {
        ss << "\"type\":\"packet\",";
    }

    ss << "\"protocol\":\"" << (msg.is_sd ? "SOME/IP-SD" : "SOME/IP") << "\","
       << "\"transport\":\"" << msg.transport << "\","
       << "\"src_ip\":\"" << msg.src_ip << "\","
       << "\"src_port\":" << msg.src_port << ","
       << "\"dst_ip\":\"" << msg.dst_ip << "\","
       << "\"dst_port\":" << msg.dst_port << ",";

    // SOME/IP Header fields
    const auto& h = msg.header;
    ss << "\"service\":\"" << hex4(h.service_id) << "\","
       << "\"service_id\":" << h.service_id << ","
       << "\"method\":\"" << hex4(h.method_id) << "\","
       << "\"method_id\":" << h.method_id << ","
       << "\"is_event\":" << (h.is_event ? "true" : "false") << ","
       << "\"length\":" << (h.length + 8) << ","
       << "\"client_id\":\"" << hex4(h.client_id) << "\","
       << "\"session_id\":\"" << hex4(h.session_id) << "\","
       << "\"proto_ver\":" << static_cast<unsigned>(h.protocol_version) << ","
       << "\"iface_ver\":" << static_cast<unsigned>(h.interface_version) << ","
       << "\"msg_type\":\"" << hex2(static_cast<uint8_t>(h.message_type)) << "\","
       << "\"msg_type_name\":\"" << to_string(h.message_type) << "\","
       << "\"return_code\":\"" << hex2(static_cast<uint8_t>(h.return_code)) << "\","
       << "\"return_code_name\":\"" << to_string(h.return_code) << "\","
       << "\"is_tp\":" << (h.is_tp ? "true" : "false") << ",";

    if (h.is_tp) {
        ss << "\"tp_offset\":" << h.tp_offset << ","
           << "\"tp_more\":" << (h.tp_more_segments ? "true" : "false") << ",";
    }

    ss << "\"payload_len\":" << msg.payload_len << ","
       << "\"payload_hex\":\"" << msg.payload_hex_preview << "\"";

    // Detailed SOME/IP-SD JSON structure
    if (msg.is_sd) {
        ss << ",\"flags\":{"
           << "\"reboot\":" << (msg.sd.reboot_flag ? "true" : "false") << ","
           << "\"unicast\":" << (msg.sd.unicast_flag ? "true" : "false") << ","
           << "\"raw\":" << static_cast<unsigned>(msg.sd.raw_flags)
           << "},\"entries\":[";

        for (size_t i = 0; i < msg.sd.entries.size(); ++i) {
            if (i > 0) ss << ",";
            const auto& e = msg.sd.entries[i];
            ss << "{"
               << "\"type\":" << static_cast<unsigned>(e.type) << ","
               << "\"type_name\":\"" << e.type_name << "\","
               << "\"service\":\"" << hex4(e.service_id) << "\","
               << "\"service_id\":" << e.service_id << ","
               << "\"instance\":\"" << hex4(e.instance_id) << "\","
               << "\"instance_id\":" << e.instance_id << ","
               << "\"major\":" << static_cast<unsigned>(e.major_version) << ","
               << "\"minor\":" << e.minor_version << ","
               << "\"ttl\":" << e.ttl << ","
               << "\"eventgroup_id\":" << e.eventgroup_id << ","
               << "\"counter\":" << static_cast<unsigned>(e.counter) << ","
               << "\"endpoints\":[";

            for (size_t j = 0; j < e.endpoint_options.size(); ++j) {
                if (j > 0) ss << ",";
                const auto& ep = e.endpoint_options[j];
                ss << "{\"ip\":\"" << ep.ip << "\",\"port\":" << ep.port
                   << ",\"proto\":\"" << ep.proto << "\",\"type\":\"" << to_string(ep.type) << "\"}";
            }
            ss << "]}";
        }
        ss << "],\"options\":[";

        for (size_t i = 0; i < msg.sd.options.size(); ++i) {
            if (i > 0) ss << ",";
            const auto& opt = msg.sd.options[i];
            ss << "{"
               << "\"type\":" << static_cast<unsigned>(opt.type) << ","
               << "\"type_name\":\"" << to_string(opt.type) << "\","
               << "\"ip\":\"" << opt.ip << "\","
               << "\"port\":" << opt.port << ","
               << "\"proto\":\"" << opt.proto << "\"";
            if (!opt.config_string.empty()) {
                ss << ",\"config\":\"" << json_escape(opt.config_string) << "\"";
            }
            ss << "}";
        }
        ss << "]";
    }

    ss << "}";
    return ss.str();
}

} // namespace someip
