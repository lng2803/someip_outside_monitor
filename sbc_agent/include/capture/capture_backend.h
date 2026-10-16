#ifndef CAPTURE_BACKEND_H
#define CAPTURE_BACKEND_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace capture {

using PacketHandler = void (*)(const uint8_t* data, size_t len, void* user_data);

class ICaptureBackend {
public:
    virtual ~ICaptureBackend() = default;

    // Open network interface for packet capture
    virtual bool open(const std::string& iface, const std::string& filter) = 0;

    // Close capture device
    virtual void close() = 0;

    // Update capture filter (BPF expression or internal filter)
    virtual bool set_filter(const std::string& filter) = 0;

    // Dispatch up to max_packets to handler. Returns number of packets or < 0 on error.
    virtual int dispatch(int max_packets, PacketHandler handler, void* user_data) = 0;

    // Returns last error message
    virtual std::string get_error() const = 0;

    // Returns human readable backend name (e.g. "libpcap" or "qnx_bpf")
    virtual std::string backend_name() const = 0;
};

} // namespace capture

#endif // CAPTURE_BACKEND_H
