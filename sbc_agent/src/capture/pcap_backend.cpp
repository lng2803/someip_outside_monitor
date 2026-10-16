#include "capture/pcap_backend.h"
#include <iostream>

namespace capture {

#ifdef HAVE_PCAP

struct CallbackWrapper {
    PacketHandler handler;
    void* user_data;
};

void PcapCaptureBackend::pcap_callback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    if (!user || !bytes || !h) return;
    auto* wrapper = reinterpret_cast<CallbackWrapper*>(user);
    if (wrapper && wrapper->handler) {
        wrapper->handler(bytes, h->caplen, wrapper->user_data);
    }
}

PcapCaptureBackend::PcapCaptureBackend() = default;

PcapCaptureBackend::~PcapCaptureBackend() {
    close();
}

bool PcapCaptureBackend::open(const std::string& iface, const std::string& filter) {
    close();
    char errbuf[PCAP_ERRBUF_SIZE]{};
    handle_ = pcap_open_live(iface.c_str(), 65535, 1, 100, errbuf);
    if (!handle_) {
        errbuf_ = std::string("pcap_open_live failed: ") + errbuf;
        return false;
    }
    if (!filter.empty()) {
        set_filter(filter);
    }
    return true;
}

void PcapCaptureBackend::close() {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PcapCaptureBackend::set_filter(const std::string& filter) {
    if (!handle_) {
        errbuf_ = "Capture handle not opened";
        return false;
    }
    bpf_program fp{};
    if (pcap_compile(handle_, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        errbuf_ = std::string("pcap_compile failed: ") + pcap_geterr(handle_);
        return false;
    }
    if (pcap_setfilter(handle_, &fp) != 0) {
        errbuf_ = std::string("pcap_setfilter failed: ") + pcap_geterr(handle_);
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    return true;
}

int PcapCaptureBackend::dispatch(int max_packets, PacketHandler handler, void* user_data) {
    if (!handle_) {
        errbuf_ = "Capture handle not opened";
        return -1;
    }
    CallbackWrapper wrapper{handler, user_data};
    int rc = pcap_dispatch(handle_, max_packets, pcap_callback, reinterpret_cast<u_char*>(&wrapper));
    if (rc == PCAP_ERROR) {
        errbuf_ = std::string("pcap_dispatch error: ") + pcap_geterr(handle_);
        return -1;
    }
    return rc;
}

std::string PcapCaptureBackend::get_error() const {
    return errbuf_;
}

#else

PcapCaptureBackend::PcapCaptureBackend() = default;
PcapCaptureBackend::~PcapCaptureBackend() = default;
bool PcapCaptureBackend::open(const std::string&, const std::string&) { return false; }
void PcapCaptureBackend::close() {}
bool PcapCaptureBackend::set_filter(const std::string&) { return false; }
int PcapCaptureBackend::dispatch(int, PacketHandler, void*) { return -1; }
std::string PcapCaptureBackend::get_error() const { return errbuf_; }

#endif

} // namespace capture
