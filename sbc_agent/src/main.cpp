#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {
constexpr int kControlPort = 47000;
constexpr int kTelemetryPort = 47001;
constexpr uint16_t kSdPort = 30490;
constexpr uint32_t kSomeIpMagic = 0x00000000; // Reserved placeholder; SOME/IP has no fixed magic word.

std::atomic<bool> g_running{true};
std::atomic<bool> g_capture_enabled{true};
std::mutex g_state_mutex;
std::string g_filter = "udp or tcp";
std::string g_pc_ip = "192.168.1.10";
std::string g_iface = "eth0";
int g_udp_fd = -1;
sockaddr_in g_pc_addr{};
pcap_t* g_pcap = nullptr;

struct ServiceInfo {
    uint16_t service_id{};
    uint16_t instance_id{};
    uint8_t major_version{};
    uint32_t ttl{};
    std::string provider_ip;
    uint16_t provider_port{};
};

std::map<std::string, ServiceInfo> g_services;

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}
uint32_t be24(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << v;
    return s.str();
}
std::string json_escape(const std::string& in) {
    std::string out;
    for (unsigned char c : in) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c >= 0x20) out += static_cast<char>(c);
    }
    return out;
}
void send_json(const std::string& json) {
    if (g_udp_fd < 0) return;
    (void)sendto(g_udp_fd, json.data(), json.size(), 0,
                 reinterpret_cast<const sockaddr*>(&g_pc_addr), sizeof(g_pc_addr));
}
void send_status(const std::string& message) {
    std::ostringstream s;
    s << "{\"type\":\"status\",\"message\":\"" << json_escape(message)
      << "\",\"capture_enabled\":" << (g_capture_enabled.load() ? "true" : "false") << "}";
    send_json(s.str());
}
std::string service_key(uint16_t service, uint16_t instance, const std::string& ip) {
    return hex4(service) + ":" + hex4(instance) + "@" + ip;
}

void process_sd(const uint8_t* payload, size_t len, const std::string& src_ip,
                uint16_t src_port, const std::string& dst_ip, uint16_t dst_port) {
    // SOME/IP header = 16 bytes. SD payload starts at byte 16:
    // flags(1), reserved(3), entries_length(4), entries, options_length(4), options.
    if (len < 28) return;
    const uint16_t service_id = be16(payload);
    const uint16_t method_id = be16(payload + 2);
    if (service_id != 0xFFFF || method_id != 0x8100) return;

    size_t p = 16;
    const uint8_t flags = payload[p];
    (void)flags;
    p += 4;
    if (p + 4 > len) return;
    const uint32_t entries_len = be32(payload + p);
    p += 4;
    if (entries_len > len || p + entries_len > len) return;
    const size_t entries_end = p + entries_len;

    while (p + 16 <= entries_end) {
        const uint8_t type = payload[p];
        const uint16_t service = be16(payload + p + 1);
        const uint16_t instance = be16(payload + p + 3);
        const uint8_t major = payload[p + 5];
        const uint32_t ttl = be24(payload + p + 6);
        const uint32_t first_opt = payload[p + 9];
        const uint32_t second_opt = payload[p + 10];
        (void)first_opt; (void)second_opt;
        std::string event_name;
        if (type == 0x00) event_name = "FindService";
        else if (type == 0x01) event_name = "OfferService";
        else if (type == 0x06) event_name = "SubscribeEventgroup";
        else if (type == 0x07) event_name = "SubscribeEventgroupAck";
        else event_name = "SDEntry";
        const std::string key = service_key(service, instance, src_ip);
        if (type == 0x00) {
            std::ostringstream e;
            e << "{\"type\":\"sd\",\"event\":\"" << event_name << "\",\"service\":\""
              << hex4(service) << "\",\"instance\":\"" << hex4(instance)
              << "\",\"source_ip\":\"" << src_ip << "\",\"ttl\":" << ttl << "}";
            send_json(e.str());
        } else if (type == 0x01) {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            if (ttl == 0) g_services.erase(key);
            else g_services[key] = ServiceInfo{service, instance, major, ttl, src_ip, src_port};
            std::ostringstream e;
            e << "{\"type\":\"service\",\"event\":\"" << event_name << "\",\"service\":\""
              << hex4(service) << "\",\"instance\":\"" << hex4(instance)
              << "\",\"major\":" << static_cast<unsigned>(major) << ",\"ttl\":" << ttl
              << ",\"provider_ip\":\"" << src_ip << "\",\"provider_port\":" << src_port
              << ",\"active\":" << (ttl ? "true" : "false") << "}";
            send_json(e.str());
        } else {
            std::ostringstream e;
            e << "{\"type\":\"sd\",\"event\":\"" << event_name << "\",\"service\":\""
              << hex4(service) << "\",\"instance\":\"" << hex4(instance)
              << "\",\"source_ip\":\"" << src_ip << "\",\"ttl\":" << ttl << "}";
            send_json(e.str());
        }
        p += 16;
    }
    (void)dst_ip; (void)dst_port;
}

void packet_callback(u_char*, const pcap_pkthdr* hdr, const u_char* bytes) {
    if (!g_capture_enabled.load() || !bytes || hdr->caplen < 14) return;
    // Ethernet II, IPv4 only. VLAN and IPv6 support are future work.
    size_t off = 14;
    const uint16_t ethertype = be16(bytes + 12);
    if (ethertype != 0x0800 || hdr->caplen < off + 20) return;
    const uint8_t ihl = static_cast<uint8_t>((bytes[off] & 0x0F) * 4);
    if (ihl < 20 || hdr->caplen < off + ihl) return;
    const uint8_t proto = bytes[off + 9];
    char srcbuf[INET_ADDRSTRLEN]{}, dstbuf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, bytes + off + 12, srcbuf, sizeof(srcbuf));
    inet_ntop(AF_INET, bytes + off + 16, dstbuf, sizeof(dstbuf));
    const std::string src_ip(srcbuf), dst_ip(dstbuf);
    size_t l4 = off + ihl;
    if (proto != 17 && proto != 6) return;
    if (hdr->caplen < l4 + (proto == 17 ? 8 : 20)) return;
    const uint16_t src_port = be16(bytes + l4);
    const uint16_t dst_port = be16(bytes + l4 + 2);
    size_t app = l4 + (proto == 17 ? 8 : ((bytes[l4 + 12] >> 4) * 4));
    if (app > hdr->caplen) return;
    const size_t app_len = hdr->caplen - app;

    bool is_someip = false;
    uint16_t service = 0, method = 0;
    uint32_t msg_len = 0;
    if (app_len >= 16) {
        service = be16(bytes + app);
        method = be16(bytes + app + 2);
        msg_len = be32(bytes + app + 4);
        is_someip = (msg_len >= 8 && static_cast<uint64_t>(msg_len) + 8 <= app_len);
    }
    if (is_someip) {
        std::ostringstream e;
        e << "{\"type\":\"packet\",\"protocol\":\"SOME/IP\",\"transport\":\""
          << (proto == 17 ? "UDP" : "TCP") << "\",\"src_ip\":\"" << src_ip
          << "\",\"src_port\":" << src_port << ",\"dst_ip\":\"" << dst_ip
          << "\",\"dst_port\":" << dst_port << ",\"service\":\"" << hex4(service)
          << "\",\"method\":\"" << hex4(method) << "\",\"length\":" << msg_len + 8 << "}";
        send_json(e.str());
        if (service == 0xFFFF && method == 0x8100)
            process_sd(bytes + app, app_len, src_ip, src_port, dst_ip, dst_port);
    }
    (void)kSomeIpMagic;
}

void capture_thread() {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    g_pcap = pcap_open_live(g_iface.c_str(), 65535, 1, 100, errbuf);
    if (!g_pcap) {
        send_status(std::string("pcap_open_live failed: ") + errbuf);
        return;
    }
    while (g_running.load()) {
        std::string filter;
        {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            filter = g_filter;
        }
        bpf_program fp{};
        if (pcap_compile(g_pcap, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_setfilter(g_pcap, &fp);
            pcap_freecode(&fp);
        } else {
            send_status(std::string("Invalid capture filter: ") + pcap_geterr(g_pcap));
        }
        int rc = pcap_dispatch(g_pcap, 32, packet_callback, nullptr);
        if (rc == PCAP_ERROR) {
            send_status(std::string("pcap error: ") + pcap_geterr(g_pcap));
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    pcap_close(g_pcap);
    g_pcap = nullptr;
}

void control_thread() {
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { send_status("Cannot create control socket"); return; }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(kControlPort);
    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        send_status("Cannot bind control port 47000");
        close(fd);
        return;
    }
    char buf[2048];
    send_status("Control socket listening on UDP 47000");
    while (g_running.load()) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        const ssize_t n = recvfrom(fd, buf, sizeof(buf)-1, 0,
                                   reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n <= 0) continue;
        buf[n] = '\0';
        const std::string cmd(buf);
        if (cmd == "START") {
            g_capture_enabled.store(true); send_status("Capture enabled");
        } else if (cmd == "STOP") {
            g_capture_enabled.store(false); send_status("Capture disabled");
        } else if (cmd == "GET_STATUS") {
            send_status("Agent running");
        } else if (cmd == "GET_SERVICES") {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            for (const auto& kv : g_services) {
                const auto& s = kv.second;
                std::ostringstream e;
                e << "{\"type\":\"service\",\"event\":\"snapshot\",\"service\":\""
                  << hex4(s.service_id) << "\",\"instance\":\"" << hex4(s.instance_id)
                  << "\",\"major\":" << static_cast<unsigned>(s.major_version)
                  << ",\"ttl\":" << s.ttl << ",\"provider_ip\":\"" << s.provider_ip
                  << "\",\"provider_port\":" << s.provider_port << ",\"active\":true}";
                send_json(e.str());
            }
        } else if (cmd.rfind("SET_FILTER ", 0) == 0) {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            g_filter = cmd.substr(11);
            send_status("Capture filter updated");
        } else {
            send_status("Unknown command");
        }
    }
    close(fd);
}
void signal_handler(int) { g_running.store(false); }
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string a(argv[i]);
        if (a == "--iface" && i + 1 < argc) g_iface = argv[++i];
        else if (a == "--pc-ip" && i + 1 < argc) g_pc_ip = argv[++i];
        else if (a == "--help") {
            std::cout << "Usage: someip_agent --iface eth0 --pc-ip 192.168.1.5\n";
            return 0;
        }
    }
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0) { std::cerr << "Cannot create telemetry socket\n"; return 1; }
    g_pc_addr.sin_family = AF_INET;
    g_pc_addr.sin_port = htons(kTelemetryPort);
    if (inet_pton(AF_INET, g_pc_ip.c_str(), &g_pc_addr.sin_addr) != 1) {
        std::cerr << "Invalid PC IP: " << g_pc_ip << "\n";
        close(g_udp_fd); return 1;
    }
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::cout << "SOME/IP agent on " << g_iface << ", telemetry to " << g_pc_ip
              << ":" << kTelemetryPort << "\n";
    std::thread ctl(control_thread);
    std::thread cap(capture_thread);
    ctl.join();
    g_running.store(false);
    cap.join();
    close(g_udp_fd);
    return 0;
}
