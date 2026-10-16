#include "capture/linux_raw_backend.h"

#if defined(__linux__)
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace capture {

LinuxRawCaptureBackend::LinuxRawCaptureBackend() {
    buffer_.resize(65536);
}

LinuxRawCaptureBackend::~LinuxRawCaptureBackend() {
    close();
}

#if defined(__linux__)

bool LinuxRawCaptureBackend::open(const std::string& iface, const std::string& filter) {
    close();
    iface_ = iface;
    filter_ = filter;

    // Create AF_PACKET raw socket for all Ethernet protocols (ETH_P_ALL)
    raw_fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_fd_ < 0) {
        errbuf_ = std::string("Cannot create AF_PACKET raw socket (requires root/sudo): ") + std::strerror(errno);
        return false;
    }

    // Get interface index
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name) - 1);
    if (::ioctl(raw_fd_, SIOCGIFINDEX, &ifr) < 0) {
        errbuf_ = std::string("Interface ") + iface + " not found: " + std::strerror(errno);
        ::close(raw_fd_);
        raw_fd_ = -1;
        return false;
    }

    // Bind socket to specific interface
    struct sockaddr_ll sll{};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (::bind(raw_fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        errbuf_ = std::string("Cannot bind raw socket to ") + iface + ": " + std::strerror(errno);
        ::close(raw_fd_);
        raw_fd_ = -1;
        return false;
    }

    // Enable promiscuous mode
    struct packet_mreq mr{};
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    (void)::setsockopt(raw_fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    // PACKET_IGNORE_OUTGOING: Linux 5.2+ — do not receive our own outgoing packets.
    // This is the primary fix for the self-capture false-positive loop where the agent's
    // own JSON telemetry was being re-captured and incorrectly decoded as SOME/IP.
    // Silently no-op on older kernels; the recvmsg pkttype check below is the fallback.
#if defined(PACKET_IGNORE_OUTGOING)
    {
        int val = 1;
        (void)::setsockopt(raw_fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &val, sizeof(val));
    }
#endif

    // Set receive timeout so dispatch does not block indefinitely (50ms)
    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    (void)::setsockopt(raw_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return true;
}

void LinuxRawCaptureBackend::close() {
    if (raw_fd_ >= 0) {
        ::close(raw_fd_);
        raw_fd_ = -1;
    }
}

bool LinuxRawCaptureBackend::set_filter(const std::string& filter) {
    filter_ = filter;
    return true;
}

int LinuxRawCaptureBackend::dispatch(int max_packets, PacketHandler handler, void* user_data) {
    if (raw_fd_ < 0) {
        errbuf_ = "Raw socket not opened";
        return -1;
    }

    int count = 0;
    while (count < max_packets) {
        // Use recvmsg to read the sockaddr_ll so we can inspect sll_pkttype.
        // This lets us skip PACKET_OUTGOING frames on kernels < 5.2 that don't
        // support PACKET_IGNORE_OUTGOING.
        struct sockaddr_ll peer_ll{};
        struct iovec iov{ buffer_.data(), buffer_.size() };
        struct msghdr mhdr{};
        mhdr.msg_name    = &peer_ll;
        mhdr.msg_namelen = sizeof(peer_ll);
        mhdr.msg_iov     = &iov;
        mhdr.msg_iovlen  = 1;

        ssize_t n = ::recvmsg(raw_fd_, &mhdr, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                break; // Timeout reached, return current count
            }
            errbuf_ = std::string("recvmsg error: ") + std::strerror(errno);
            return -1;
        }

        if (n <= 0) continue;

        // PACKET_OUTGOING = 4: packet originated from this host (our own outbound traffic).
        // Skip it to prevent the agent's own UDP telemetry from being re-captured.
        if (peer_ll.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }

        if (handler) {
            handler(buffer_.data(), static_cast<size_t>(n), user_data);
            count++;
        }
    }

    return count;
}

std::string LinuxRawCaptureBackend::get_error() const {
    return errbuf_;
}

#else

bool LinuxRawCaptureBackend::open(const std::string&, const std::string&) {
    errbuf_ = "Linux raw socket backend is only supported on Linux.";
    return false;
}
void LinuxRawCaptureBackend::close() {}
bool LinuxRawCaptureBackend::set_filter(const std::string&) { return false; }
int LinuxRawCaptureBackend::dispatch(int, PacketHandler, void*) { return -1; }
std::string LinuxRawCaptureBackend::get_error() const { return errbuf_; }

#endif

} // namespace capture
