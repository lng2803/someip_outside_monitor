#ifndef SOMEIP_TYPES_H
#define SOMEIP_TYPES_H

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace someip {

// SOME/IP Message Types (AUTOSAR PRS_SOMEIP_Protocol)
enum class MessageType : uint8_t {
    REQUEST = 0x00,
    REQUEST_NO_RETURN = 0x01,
    NOTIFICATION = 0x02,
    REQUEST_ACK = 0x40,
    REQUEST_NO_RETURN_ACK = 0x41,
    NOTIFICATION_ACK = 0x42,
    RESPONSE = 0x80,
    ERROR = 0x81,
    RESPONSE_ACK = 0xC0,
    ERROR_ACK = 0xC1,
    // Transport Protocol (TP) flag (bit 5 = 0x20)
    TP_REQUEST = 0x20,
    TP_REQUEST_NO_RETURN = 0x21,
    TP_NOTIFICATION = 0x22,
    TP_RESPONSE = 0x23,
    TP_ERROR = 0x24,
    UNKNOWN = 0xFF
};

// SOME/IP Return Codes
enum class ReturnCode : uint8_t {
    E_OK = 0x00,
    E_NOT_OK = 0x01,
    E_UNKNOWN_SERVICE = 0x02,
    E_UNKNOWN_METHOD = 0x03,
    E_NOT_READY = 0x04,
    E_NOT_REACHABLE = 0x05,
    E_TIMEOUT = 0x06,
    E_WRONG_PROTOCOL_VERSION = 0x07,
    E_WRONG_INTERFACE_VERSION = 0x08,
    E_MALFORMED_MESSAGE = 0x09,
    E_WRONG_MESSAGE_TYPE = 0x0A,
    E_E2E_REPEATED = 0x0B,
    E_E2E_WRONG_SEQUENCE = 0x0C,
    E_E2E = 0x0D,
    E_E2E_NOT_AVAILABLE = 0x0E,
    E_E2E_NO_NEW_DATA = 0x0F,
    UNKNOWN = 0xFF
};

// SOME/IP-SD Entry Types
enum class SdEntryType : uint8_t {
    FIND_SERVICE = 0x00,
    OFFER_SERVICE = 0x01,
    SUBSCRIBE_EVENTGROUP = 0x06,
    SUBSCRIBE_EVENTGROUP_ACK = 0x07,
    UNKNOWN = 0xFF
};

// SOME/IP-SD Option Types
enum class SdOptionType : uint8_t {
    CONFIGURATION = 0x01,
    LOAD_BALANCING = 0x02,
    IPV4_ENDPOINT = 0x04,
    IPV6_ENDPOINT = 0x06,
    IPV4_MULTICAST = 0x14,
    IPV6_MULTICAST = 0x16,
    IPV4_SD_ENDPOINT = 0x24,
    IPV6_SD_ENDPOINT = 0x26,
    UNKNOWN = 0xFF
};

inline std::string to_string(MessageType type) {
    switch (type) {
        case MessageType::REQUEST: return "REQUEST";
        case MessageType::REQUEST_NO_RETURN: return "REQUEST_NO_RETURN";
        case MessageType::NOTIFICATION: return "NOTIFICATION";
        case MessageType::REQUEST_ACK: return "REQUEST_ACK";
        case MessageType::REQUEST_NO_RETURN_ACK: return "REQUEST_NO_RETURN_ACK";
        case MessageType::NOTIFICATION_ACK: return "NOTIFICATION_ACK";
        case MessageType::RESPONSE: return "RESPONSE";
        case MessageType::ERROR: return "ERROR";
        case MessageType::RESPONSE_ACK: return "RESPONSE_ACK";
        case MessageType::ERROR_ACK: return "ERROR_ACK";
        case MessageType::TP_REQUEST: return "TP_REQUEST";
        case MessageType::TP_REQUEST_NO_RETURN: return "TP_REQUEST_NO_RETURN";
        case MessageType::TP_NOTIFICATION: return "TP_NOTIFICATION";
        case MessageType::TP_RESPONSE: return "TP_RESPONSE";
        case MessageType::TP_ERROR: return "TP_ERROR";
        default: return "UNKNOWN";
    }
}

inline std::string to_string(ReturnCode code) {
    switch (code) {
        case ReturnCode::E_OK: return "E_OK";
        case ReturnCode::E_NOT_OK: return "E_NOT_OK";
        case ReturnCode::E_UNKNOWN_SERVICE: return "E_UNKNOWN_SERVICE";
        case ReturnCode::E_UNKNOWN_METHOD: return "E_UNKNOWN_METHOD";
        case ReturnCode::E_NOT_READY: return "E_NOT_READY";
        case ReturnCode::E_NOT_REACHABLE: return "E_NOT_REACHABLE";
        case ReturnCode::E_TIMEOUT: return "E_TIMEOUT";
        case ReturnCode::E_WRONG_PROTOCOL_VERSION: return "E_WRONG_PROTOCOL_VERSION";
        case ReturnCode::E_WRONG_INTERFACE_VERSION: return "E_WRONG_INTERFACE_VERSION";
        case ReturnCode::E_MALFORMED_MESSAGE: return "E_MALFORMED_MESSAGE";
        case ReturnCode::E_WRONG_MESSAGE_TYPE: return "E_WRONG_MESSAGE_TYPE";
        case ReturnCode::E_E2E_REPEATED: return "E_E2E_REPEATED";
        case ReturnCode::E_E2E_WRONG_SEQUENCE: return "E_E2E_WRONG_SEQUENCE";
        case ReturnCode::E_E2E: return "E_E2E";
        case ReturnCode::E_E2E_NOT_AVAILABLE: return "E_E2E_NOT_AVAILABLE";
        case ReturnCode::E_E2E_NO_NEW_DATA: return "E_E2E_NO_NEW_DATA";
        default: return "UNKNOWN";
    }
}

inline bool is_valid_message_type(uint8_t t) {
    switch (t) {
        case 0x00: // REQUEST
        case 0x01: // REQUEST_NO_RETURN
        case 0x02: // NOTIFICATION
        case 0x40: // REQUEST_ACK
        case 0x41: // REQUEST_NO_RETURN_ACK
        case 0x42: // NOTIFICATION_ACK
        case 0x80: // RESPONSE
        case 0x81: // ERROR
        case 0xC0: // RESPONSE_ACK
        case 0xC1: // ERROR_ACK
        case 0x20: // TP_REQUEST
        case 0x21: // TP_REQUEST_NO_RETURN
        case 0x22: // TP_NOTIFICATION
        case 0x23: // TP_RESPONSE
        case 0x24: // TP_ERROR
            return true;
        default:
            return false;
    }
}

inline bool is_valid_return_code(uint8_t /*msg_type*/, uint8_t rc) {
    // Accept any AUTOSAR-defined return code for all message types.
    // AUTOSAR spec says REQUEST/NOTIFICATION should use E_OK (0x00), but
    // non-conformant ECU implementations exist in the wild and hard-rejecting
    // them causes false negatives on real traffic.
    // We still filter out truly undefined reserved values (0x10-0x1F reserved,
    // and above 0x5F is also reserved) to discriminate from random garbage data.
    return (rc <= 0x0F) || (rc >= 0x20 && rc <= 0x5F);
}

inline std::string to_string(SdEntryType type, uint32_t ttl = 1) {
    switch (type) {
        case SdEntryType::FIND_SERVICE: return "FindService";
        case SdEntryType::OFFER_SERVICE: return ttl > 0 ? "OfferService" : "StopOfferService";
        case SdEntryType::SUBSCRIBE_EVENTGROUP: return ttl > 0 ? "SubscribeEventgroup" : "StopSubscribeEventgroup";
        case SdEntryType::SUBSCRIBE_EVENTGROUP_ACK: return ttl > 0 ? "SubscribeEventgroupAck" : "SubscribeEventgroupNack";
        default: return "UnknownEntry";
    }
}

inline std::string to_string(SdOptionType type) {
    switch (type) {
        case SdOptionType::CONFIGURATION: return "CONFIGURATION";
        case SdOptionType::LOAD_BALANCING: return "LOAD_BALANCING";
        case SdOptionType::IPV4_ENDPOINT: return "IPV4_ENDPOINT";
        case SdOptionType::IPV6_ENDPOINT: return "IPV6_ENDPOINT";
        case SdOptionType::IPV4_MULTICAST: return "IPV4_MULTICAST";
        case SdOptionType::IPV6_MULTICAST: return "IPV6_MULTICAST";
        case SdOptionType::IPV4_SD_ENDPOINT: return "IPV4_SD_ENDPOINT";
        case SdOptionType::IPV6_SD_ENDPOINT: return "IPV6_SD_ENDPOINT";
        default: return "UNKNOWN_OPTION";
    }
}

// Helpers for hex string formatting
inline std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

inline std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

inline std::string hex8(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << v;
    return s.str();
}

// Parsed SOME/IP Header
struct SomeIpHeader {
    uint16_t service_id{0};
    uint16_t method_id{0};
    bool is_event{false};       // bit 15 of method_id is set for events
    uint32_t length{0};         // Payload length from Request ID to end of message
    uint16_t client_id{0};
    uint16_t session_id{0};
    uint8_t protocol_version{1};
    uint8_t interface_version{1};
    MessageType message_type{MessageType::UNKNOWN};
    ReturnCode return_code{ReturnCode::UNKNOWN};

    // SOME/IP-TP (if message_type has TP flag 0x20)
    bool is_tp{false};
    uint32_t tp_offset{0};      // in bytes (offset field * 16)
    bool tp_more_segments{false};

    // Total size of this SOME/IP message including 16-byte header
    size_t total_size() const {
        return static_cast<size_t>(length) + 8;
    }
};

// Parsed SOME/IP-SD Option
struct SdOption {
    SdOptionType type{SdOptionType::UNKNOWN};
    uint8_t discardable{0};
    std::string ip;
    uint16_t port{0};
    std::string proto;          // "UDP" or "TCP"
    std::string config_string;  // for CONFIGURATION options
};

// Parsed SOME/IP-SD Entry
struct SdEntry {
    SdEntryType type{SdEntryType::UNKNOWN};
    std::string type_name;
    uint16_t service_id{0};
    uint16_t instance_id{0};
    uint8_t major_version{0};
    uint32_t minor_version{0};  // for Service entries
    uint32_t ttl{0};            // Time-to-live in seconds
    uint16_t eventgroup_id{0};  // for Eventgroup entries
    uint8_t counter{0};
    bool initial_data_requested{false};

    // Index / count of referenced options
    uint8_t opt1_index{0};
    uint8_t opt1_count{0};
    uint8_t opt2_index{0};
    uint8_t opt2_count{0};

    // Resolved options referenced by this entry
    std::vector<SdOption> endpoint_options;
};

// Parsed SOME/IP-SD Message
struct SomeIpSdMessage {
    bool reboot_flag{false};
    bool unicast_flag{false};
    bool explicit_initial_data_control{false};
    uint8_t raw_flags{0};

    std::vector<SdEntry> entries;
    std::vector<SdOption> options;
};

// Complete Dissected Message
struct DissectedMessage {
    std::string transport;      // "UDP" or "TCP"
    std::string src_ip;
    uint16_t src_port{0};
    std::string dst_ip;
    uint16_t dst_port{0};

    SomeIpHeader header;
    bool is_sd{false};
    SomeIpSdMessage sd;

    size_t payload_offset{0};
    size_t payload_len{0};
    std::string payload_hex_preview; // Hex string of payload bytes (up to limit)
};

} // namespace someip

#endif // SOMEIP_TYPES_H
