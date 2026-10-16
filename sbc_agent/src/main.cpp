#include "someip/someip_dissector.h"
#include "someip/someip_types.h"
#include "capture/pcap_backend.h"
#include "capture/qnx_bpf_backend.h"
#include "capture/linux_raw_backend.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

int g_control_port = 47000;
int g_telemetry_port = 47001;
std::string g_filter = "(udp or tcp) and not (port 47000 or port 47001)";
std::string g_pc_ip = "192.168.1.10";
std::string g_iface = "eth0";
std::string g_backend_choice = "auto";
size_t g_preview_len = 256;

std::atomic<bool> g_running{true};
std::atomic<bool> g_capture_enabled{true};
std::atomic<uint64_t> g_captured_packets{0};
std::atomic<uint64_t> g_someip_messages{0};

std::mutex g_state_mutex;
int g_udp_fd = -1;
sockaddr_in g_pc_addr{};

struct DiscoveredService {
    uint16_t service_id{0};
    uint16_t instance_id{0};
    uint8_t major_version{0};
    uint32_t minor_version{0};
    uint32_t ttl{0};
    std::string provider_ip;
    uint16_t provider_port{0};
    std::string proto{"UDP"};
    std::chrono::steady_clock::time_point last_seen;
    bool active{true};
};

std::map<std::string, DiscoveredService> g_services;
std::unique_ptr<someip::SomeIpDissector> g_dissector;
std::unique_ptr<capture::ICaptureBackend> g_backend;

void send_json(const std::string& json) {
    if (g_udp_fd < 0) return;
    (void)sendto(g_udp_fd, json.data(), json.size(), 0,
                 reinterpret_cast<const sockaddr*>(&g_pc_addr), sizeof(g_pc_addr));
}

void send_status(const std::string& message) {
    std::ostringstream s;
    std::string backend_name = g_backend ? g_backend->backend_name() : "none";
    s << "{\"type\":\"status\",\"message\":\"" << someip::SomeIpDissector::json_escape(message)
      << "\",\"capture_enabled\":" << (g_capture_enabled.load() ? "true" : "false")
      << ",\"backend\":\"" << backend_name << "\""
      << ",\"packets\":" << g_captured_packets.load()
      << ",\"someip_msgs\":" << g_someip_messages.load() << "}";
    send_json(s.str());
}

std::string make_service_key(uint16_t service, uint16_t instance, const std::string& ip) {
    return someip::hex4(service) + ":" + someip::hex4(instance) + "@" + ip;
}

void process_sd_entries(const someip::DissectedMessage& msg) {
    std::lock_guard<std::mutex> lock(g_state_mutex);
    for (const auto& entry : msg.sd.entries) {
        if (entry.type == someip::SdEntryType::OFFER_SERVICE) {
            std::string provider_ip = msg.src_ip;
            uint16_t provider_port = msg.src_port;
            std::string proto = msg.transport;

            // Check if entry contains explicit endpoint option
            if (!entry.endpoint_options.empty()) {
                const auto& ep = entry.endpoint_options.front();
                if (!ep.ip.empty()) provider_ip = ep.ip;
                if (ep.port > 0) provider_port = ep.port;
                if (!ep.proto.empty()) proto = ep.proto;
            }

            const std::string key = make_service_key(entry.service_id, entry.instance_id, provider_ip);
            if (entry.ttl == 0) {
                // StopOfferService
                auto it = g_services.find(key);
                if (it != g_services.end()) {
                    it->second.active = false;
                    it->second.ttl = 0;
                }
            } else {
                DiscoveredService svc;
                svc.service_id = entry.service_id;
                svc.instance_id = entry.instance_id;
                svc.major_version = entry.major_version;
                svc.minor_version = entry.minor_version;
                svc.ttl = entry.ttl;
                svc.provider_ip = provider_ip;
                svc.provider_port = provider_port;
                svc.proto = proto;
                svc.last_seen = std::chrono::steady_clock::now();
                svc.active = true;
                g_services[key] = svc;
            }

            // Also emit legacy service notification for backward compatibility
            std::ostringstream leg;
            leg << "{\"type\":\"service\",\"event\":\"" << entry.type_name
                << "\",\"service\":\"" << someip::hex4(entry.service_id)
                << "\",\"instance\":\"" << someip::hex4(entry.instance_id)
                << "\",\"major\":" << static_cast<unsigned>(entry.major_version)
                << ",\"minor\":" << entry.minor_version
                << ",\"ttl\":" << entry.ttl
                << ",\"provider_ip\":\"" << provider_ip
                << "\",\"provider_port\":" << provider_port
                << ",\"active\":" << (entry.ttl > 0 ? "true" : "false") << "}";
            send_json(leg.str());
        }
    }
}

void packet_callback(const uint8_t* bytes, size_t len, void*) {
    if (!g_capture_enabled.load() || !bytes || len < 14) return;

    auto msgs = g_dissector->dissect_frame(bytes, len);
    for (const auto& m : msgs) {
        // Prevent loop: do not process agent's own telemetry or control packets
        if (m.src_port == g_telemetry_port || m.dst_port == g_telemetry_port ||
            m.src_port == g_control_port || m.dst_port == g_control_port) {
            continue;
        }

        g_captured_packets++;
        g_someip_messages++;
        std::string json = g_dissector->to_json(m);
        send_json(json);

        if (m.is_sd) {
            process_sd_entries(m);
        }
    }
}

void capture_thread() {
    std::string backend_name = g_backend ? g_backend->backend_name() : "none";
    std::cout << "Starting packet capture on " << g_iface
              << " using backend: " << backend_name << "\n";

    if (!g_backend->open(g_iface, g_filter)) {
        std::string err = g_backend->get_error();
        std::cerr << "Failed to open capture backend: " << err << "\n";
        send_status(std::string("Capture open failed: ") + err);
        return;
    }

    send_status(std::string("Capture started on ") + g_iface + " (" + backend_name + ")");

    while (g_running.load()) {
        int rc = g_backend->dispatch(32, packet_callback, nullptr);
        if (rc < 0) {
            send_status(std::string("Capture dispatch error: ") + g_backend->get_error());
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    g_backend->close();
    send_status("Capture stopped");
}

void control_thread() {
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        send_status("Cannot create control socket");
        return;
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(g_control_port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0) {
        send_status("Cannot bind control port");
        close(fd);
        return;
    }

    char buf[4096];
    send_status("Control socket listening on UDP " + std::to_string(g_control_port));

    while (g_running.load()) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        const ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                                   reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n <= 0) continue;
        buf[n] = '\0';
        const std::string cmd(buf);

        if (cmd == "START") {
            g_capture_enabled.store(true);
            send_status("Capture enabled");
        } else if (cmd == "STOP") {
            g_capture_enabled.store(false);
            send_status("Capture disabled");
        } else if (cmd == "GET_STATUS") {
            send_status("Agent running");
        } else if (cmd == "GET_SERVICES") {
            std::lock_guard<std::mutex> lock(g_state_mutex);
            for (const auto& kv : g_services) {
                const auto& s = kv.second;
                std::ostringstream e;
                e << "{\"type\":\"service\",\"event\":\"snapshot\",\"service\":\""
                  << someip::hex4(s.service_id) << "\",\"instance\":\"" << someip::hex4(s.instance_id)
                  << "\",\"major\":" << static_cast<unsigned>(s.major_version)
                  << ",\"minor\":" << s.minor_version
                  << ",\"ttl\":" << s.ttl << ",\"provider_ip\":\"" << s.provider_ip
                  << "\",\"provider_port\":" << s.provider_port
                  << ",\"proto\":\"" << s.proto
                  << "\",\"active\":" << (s.active ? "true" : "false") << "}";
                send_json(e.str());
            }
        } else if (cmd.rfind("SET_FILTER ", 0) == 0) {
            std::string new_filter = cmd.substr(11);
            {
                std::lock_guard<std::mutex> lock(g_state_mutex);
                g_filter = new_filter;
            }
            if (g_backend && g_backend->set_filter(new_filter)) {
                send_status("Capture filter updated: " + new_filter);
            } else {
                std::string err = g_backend ? g_backend->get_error() : "No backend";
                send_status("Failed to apply filter: " + err);
            }
        } else {
            send_status("Unknown command: " + cmd);
        }
    }

    close(fd);
}

void signal_handler(int) {
    g_running.store(false);
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --iface <iface>          Network interface to monitor (default: eth0)\n"
              << "  --pc-ip <ip>             IP address of monitoring PC (default: 192.168.1.10)\n"
              << "  --control-port <port>    UDP port for incoming control commands (default: 47000)\n"
              << "  --telemetry-port <port>  UDP port for telemetry stream to PC (default: 47001)\n"
              << "  --backend <auto|pcap|raw|bpf> Capture backend (default: auto)\n"
              << "                           auto: Best backend for platform\n"
              << "                           pcap: libpcap (Linux / Raspberry Pi / QNX)\n"
              << "                           raw:  Native Linux AF_PACKET raw socket (no libpcap needed)\n"
              << "                           bpf:  Native QNX /dev/bpf (QNX Neutrino RTOS only)\n"
              << "  --preview-len <bytes>    Max payload bytes previewed in hex (default: 256)\n"
              << "  --help                   Display this help message\n\n"
              << "Platforms supported:\n"
              << "  - Linux / Raspberry Pi: libpcap or native AF_PACKET raw sockets\n"
              << "  - QNX Neutrino RTOS 7.x / 8.0: Native /dev/bpf or libpcap\n";
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string a(argv[i]);
        if (a == "--iface" && i + 1 < argc) {
            g_iface = argv[++i];
        } else if (a == "--pc-ip" && i + 1 < argc) {
            g_pc_ip = argv[++i];
        } else if (a == "--control-port" && i + 1 < argc) {
            g_control_port = std::stoi(argv[++i]);
        } else if (a == "--telemetry-port" && i + 1 < argc) {
            g_telemetry_port = std::stoi(argv[++i]);
        } else if (a == "--backend" && i + 1 < argc) {
            g_backend_choice = argv[++i];
        } else if (a == "--preview-len" && i + 1 < argc) {
            g_preview_len = std::stoul(argv[++i]);
        } else if (a == "--help") {
            print_help(argv[0]);
            return 0;
        }
    }

#if defined(__linux__)
    if (::geteuid() != 0) {
        std::cerr << "Note: Packet capture on Linux/Raspberry Pi requires root privileges.\n"
                  << "If capture fails to open, run with: sudo " << argv[0] << " ...\n\n";
    }
#endif

    // Initialize dissector
    g_dissector = std::make_unique<someip::SomeIpDissector>(g_preview_len);

    // Select capture backend
    if (g_backend_choice == "bpf") {
#if defined(__linux__)
        std::cerr << "Warning: '--backend bpf' (/dev/bpf) is only for QNX Neutrino RTOS or BSD.\n"
                  << "On Linux / Raspberry Pi 4, use '--backend pcap' or '--backend raw' (or leave as auto).\n\n";
#endif
        g_backend = std::make_unique<capture::QnxBpfCaptureBackend>();
    } else if (g_backend_choice == "raw") {
        g_backend = std::make_unique<capture::LinuxRawCaptureBackend>();
    } else if (g_backend_choice == "pcap") {
        g_backend = std::make_unique<capture::PcapCaptureBackend>();
    } else {
        // Auto-selection:
#if defined(__QNX__) || defined(__QNXNTO__)
        // On QNX, prefer native BPF unless pcap is compiled in
#if defined(HAVE_PCAP)
        g_backend = std::make_unique<capture::PcapCaptureBackend>();
#else
        g_backend = std::make_unique<capture::QnxBpfCaptureBackend>();
#endif
#elif defined(__linux__)
        // On Linux / Raspberry Pi: prefer libpcap if available, else AF_PACKET raw socket
#if defined(HAVE_PCAP)
        g_backend = std::make_unique<capture::PcapCaptureBackend>();
#else
        g_backend = std::make_unique<capture::LinuxRawCaptureBackend>();
#endif
#else
        g_backend = std::make_unique<capture::PcapCaptureBackend>();
#endif
    }

    // Set up telemetry UDP socket
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0) {
        std::cerr << "Cannot create telemetry socket\n";
        return 1;
    }

    g_pc_addr.sin_family = AF_INET;
    g_pc_addr.sin_port = htons(g_telemetry_port);
    if (inet_pton(AF_INET, g_pc_ip.c_str(), &g_pc_addr.sin_addr) != 1) {
        std::cerr << "Invalid PC IP: " << g_pc_ip << "\n";
        close(g_udp_fd);
        return 1;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "SOME/IP Agent started.\n"
              << "  Interface:       " << g_iface << "\n"
              << "  Capture Backend: " << g_backend->backend_name() << "\n"
              << "  Control Port:    UDP " << g_control_port << "\n"
              << "  Telemetry:       " << g_pc_ip << ":" << g_telemetry_port << "\n";

    std::thread ctl(control_thread);
    std::thread cap(capture_thread);

    ctl.join();
    g_running.store(false);
    cap.join();

    close(g_udp_fd);
    return 0;
}
