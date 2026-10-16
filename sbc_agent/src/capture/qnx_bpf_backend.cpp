#include "capture/qnx_bpf_backend.h"

#if defined(__QNX__) || defined(__QNXNTO__) || defined(HAVE_QNX_BPF)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace capture {

QnxBpfCaptureBackend::QnxBpfCaptureBackend() = default;

QnxBpfCaptureBackend::~QnxBpfCaptureBackend() {
    close();
}

#if defined(__QNX__) || defined(__QNXNTO__) || defined(HAVE_QNX_BPF)

bool QnxBpfCaptureBackend::open(const std::string& iface, const std::string& filter) {
    close();
    iface_ = iface;
    filter_ = filter;

    // Try opening /dev/bpf clone device first
    bpf_fd_ = ::open("/dev/bpf", O_RDWR);
    if (bpf_fd_ < 0) {
        // Fall back to trying numbered BPF devices (/dev/bpf0 .. /dev/bpf15)
        for (int i = 0; i < 16; ++i) {
            std::string dev_path = "/dev/bpf" + std::to_string(i);
            bpf_fd_ = ::open(dev_path.c_str(), O_RDWR);
            if (bpf_fd_ >= 0) {
                break;
            }
        }
    }

    if (bpf_fd_ < 0) {
        errbuf_ = std::string("Cannot open /dev/bpf or /dev/bpf[0..15]: ") + std::strerror(errno);
        return false;
    }

    // Set buffer size
    unsigned int buf_len = 65536;
    if (::ioctl(bpf_fd_, BIOCSBLEN, &buf_len) < 0) {
        // Try reading default buffer size
        if (::ioctl(bpf_fd_, BIOCGBLEN, &buf_len) < 0) {
            buf_len = 32768;
        }
    }
    buffer_len_ = buf_len;
    buffer_.resize(buffer_len_);

    // Bind to the specified network interface
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), sizeof(ifr.ifr_name) - 1);
    if (::ioctl(bpf_fd_, BIOCSETIF, &ifr) < 0) {
        errbuf_ = std::string("BIOCSETIF failed on ") + iface + ": " + std::strerror(errno);
        ::close(bpf_fd_);
        bpf_fd_ = -1;
        return false;
    }

    // Enable immediate mode: dispatch packets as soon as they arrive
    unsigned int immediate = 1;
    if (::ioctl(bpf_fd_, BIOCIMMEDIATE, &immediate) < 0) {
        // Warning only, continue
    }

    // Enable promiscuous mode
    (void)::ioctl(bpf_fd_, BIOCPROMISC, nullptr);

    // Apply filter if specified
    if (!filter.empty()) {
        set_filter(filter);
    }

    return true;
}

void QnxBpfCaptureBackend::close() {
    if (bpf_fd_ >= 0) {
        ::close(bpf_fd_);
        bpf_fd_ = -1;
    }
}

bool QnxBpfCaptureBackend::set_filter(const std::string& filter) {
    filter_ = filter;
    // Note: If libpcap is available, pcap_compile_nopcap could generate the bpf_program.
    // Without libpcap, software filtering is performed in the dissector.
    return true;
}

int QnxBpfCaptureBackend::dispatch(int max_packets, PacketHandler handler, void* user_data) {
    if (bpf_fd_ < 0) {
        errbuf_ = "BPF device not opened";
        return -1;
    }

    ssize_t n = ::read(bpf_fd_, buffer_.data(), buffer_.size());
    if (n < 0) {
        if (errno == EAGAIN || errno == EINTR) {
            return 0;
        }
        errbuf_ = std::string("BPF read error: ") + std::strerror(errno);
        return -1;
    }
    if (n == 0) {
        return 0;
    }

    const uint8_t* ptr = buffer_.data();
    const uint8_t* end = buffer_.data() + n;
    int count = 0;

    while (ptr < end && count < max_packets) {
        const auto* hdr = reinterpret_cast<const struct bpf_hdr*>(ptr);
        if (ptr + hdr->bh_hdrlen + hdr->bh_caplen > end) {
            break; // Truncated record in buffer
        }

        const uint8_t* pkt_data = ptr + hdr->bh_hdrlen;
        if (handler) {
            handler(pkt_data, hdr->bh_caplen, user_data);
        }
        count++;

        // Advance to next packet aligned on BPF word boundary
        ptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
    }

    return count;
}

std::string QnxBpfCaptureBackend::get_error() const {
    return errbuf_;
}

#else

bool QnxBpfCaptureBackend::open(const std::string&, const std::string&) {
    errbuf_ = "QNX BPF backend is only supported on QNX Neutrino RTOS or BSD systems.";
    return false;
}
void QnxBpfCaptureBackend::close() {}
bool QnxBpfCaptureBackend::set_filter(const std::string&) { return false; }
int QnxBpfCaptureBackend::dispatch(int, PacketHandler, void*) { return -1; }
std::string QnxBpfCaptureBackend::get_error() const { return errbuf_; }

#endif

} // namespace capture
