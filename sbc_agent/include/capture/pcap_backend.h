#ifndef PCAP_BACKEND_H
#define PCAP_BACKEND_H

#include "capture/capture_backend.h"

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

namespace capture {

class PcapCaptureBackend : public ICaptureBackend {
public:
    PcapCaptureBackend();
    ~PcapCaptureBackend() override;

    bool open(const std::string& iface, const std::string& filter) override;
    void close() override;
    bool set_filter(const std::string& filter) override;
    int dispatch(int max_packets, PacketHandler handler, void* user_data) override;
    std::string get_error() const override;
    std::string backend_name() const override { return "libpcap"; }

private:
#ifdef HAVE_PCAP
    pcap_t* handle_{nullptr};
    std::string errbuf_;
    static void pcap_callback(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes);
#else
    std::string errbuf_{"libpcap support not compiled in"};
#endif
};

} // namespace capture

#endif // PCAP_BACKEND_H
