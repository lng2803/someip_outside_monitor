#ifndef LINUX_RAW_BACKEND_H
#define LINUX_RAW_BACKEND_H

#include "capture/capture_backend.h"
#include <string>
#include <vector>

namespace capture {

class LinuxRawCaptureBackend : public ICaptureBackend {
public:
    LinuxRawCaptureBackend();
    ~LinuxRawCaptureBackend() override;

    bool open(const std::string& iface, const std::string& filter) override;
    void close() override;
    bool set_filter(const std::string& filter) override;
    int dispatch(int max_packets, PacketHandler handler, void* user_data) override;
    std::string get_error() const override;
    std::string backend_name() const override { return "linux_raw_socket"; }

private:
    int raw_fd_{-1};
    std::string iface_;
    std::string filter_;
    std::string errbuf_;
    std::vector<uint8_t> buffer_;
};

} // namespace capture

#endif // LINUX_RAW_BACKEND_H
