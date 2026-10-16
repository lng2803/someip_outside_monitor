#ifndef QNX_BPF_BACKEND_H
#define QNX_BPF_BACKEND_H

#include "capture/capture_backend.h"
#include <string>
#include <vector>

namespace capture {

class QnxBpfCaptureBackend : public ICaptureBackend {
public:
    QnxBpfCaptureBackend();
    ~QnxBpfCaptureBackend() override;

    bool open(const std::string& iface, const std::string& filter) override;
    void close() override;
    bool set_filter(const std::string& filter) override;
    int dispatch(int max_packets, PacketHandler handler, void* user_data) override;
    std::string get_error() const override;
    std::string backend_name() const override { return "qnx_bpf"; }

private:
    int bpf_fd_{-1};
    std::string iface_;
    std::string filter_;
    std::string errbuf_;
    std::vector<uint8_t> buffer_;
    unsigned int buffer_len_{65536};
};

} // namespace capture

#endif // QNX_BPF_BACKEND_H
