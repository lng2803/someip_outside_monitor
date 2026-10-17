import asyncio
import struct
import logging

from someipy import (
    Event,
    EventGroup,
    ServiceBuilder,
    TransportLayerProtocol,
    connect_to_someipy_daemon,
)
from someipy.client_service_instance import ClientServiceInstance
from someipy.someipy_logging import set_someipy_log_level

# Change to the consumer machine's Ethernet IP
INTERFACE_IP = "192.168.1.10"

SERVICE_ID = 0x1234
INSTANCE_ID = 0x5678
EVENTGROUP_ID = 0x0321
EVENT_ID = 0x0123


def on_event(event_id: int, payload: bytes):
    if event_id != EVENT_ID:
        return

    if len(payload) != 8:
        print(f"Unexpected payload length: {len(payload)}")
        return

    counter, temperature = struct.unpack(">If", payload)

    print(
        f"RX event=0x{event_id:04X}, "
        f"counter={counter}, "
        f"temperature={temperature:.1f} C"
    )


async def main():
    set_someipy_log_level(logging.INFO)

    daemon = await connect_to_someipy_daemon()

    event = Event(
        id=EVENT_ID,
        protocol=TransportLayerProtocol.UDP,
    )

    event_group = EventGroup(
        id=EVENTGROUP_ID,
        events=[event],
    )

    service = (
        ServiceBuilder()
        .with_service_id(SERVICE_ID)
        .with_major_version(1)
        .with_eventgroup(event_group)
        .build()
    )

    client = ClientServiceInstance(
        daemon=daemon,
        service=service,
        instance_id=INSTANCE_ID,
        endpoint_ip=INTERFACE_IP,
        endpoint_port=3002,
    )

    client.register_callback(on_event)
    client.subscribe_eventgroup(event_group, 100)

    print(f"Subscribed to service 0x{SERVICE_ID:04X}")
    print("Waiting for SOME/IP events...")

    try:
        await asyncio.Future()
    finally:
        await daemon.disconnect_from_daemon()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
