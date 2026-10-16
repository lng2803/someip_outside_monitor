"""
SOME/IP and SOME/IP-SD Protocol Decoder for Python.
Conforms to AUTOSAR PRS_SOMEIP_Protocol and PRS_SOMEIPServiceDiscoveryProtocol.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class MessageType(Enum):
    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    REQUEST_ACK = 0x40
    REQUEST_NO_RETURN_ACK = 0x41
    NOTIFICATION_ACK = 0x42
    RESPONSE = 0x80
    ERROR = 0x81
    RESPONSE_ACK = 0xC0
    ERROR_ACK = 0xC1
    # Transport Protocol (TP) flag (bit 5 = 0x20)
    TP_REQUEST = 0x20
    TP_REQUEST_NO_RETURN = 0x21
    TP_NOTIFICATION = 0x22
    TP_RESPONSE = 0x23
    TP_ERROR = 0x24
    UNKNOWN = 0xFF

    @classmethod
    def from_int(cls, val: int) -> MessageType:
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


class ReturnCode(Enum):
    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_NOT_REACHABLE = 0x05
    E_TIMEOUT = 0x06
    E_WRONG_PROTOCOL_VERSION = 0x07
    E_WRONG_INTERFACE_VERSION = 0x08
    E_MALFORMED_MESSAGE = 0x09
    E_WRONG_MESSAGE_TYPE = 0x0A
    E_E2E_REPEATED = 0x0B
    E_E2E_WRONG_SEQUENCE = 0x0C
    E_E2E = 0x0D
    E_E2E_NOT_AVAILABLE = 0x0E
    E_E2E_NO_NEW_DATA = 0x0F
    # E2E error range 0x20–0x5F (implementation-specific E2E return codes)
    # These are valid AUTOSAR return codes used by E2E protection layer.
    # We use a sentinel range value to represent any code in this range.
    E2E_RANGE_START = 0x20   # Lowest E2E implementation-specific code
    UNKNOWN = 0xFF

    @classmethod
    def from_int(cls, val: int) -> ReturnCode:
        # E2E range: 0x20–0x5F is valid but not individually enumerated
        if 0x20 <= val <= 0x5F:
            return cls.E2E_RANGE_START
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN



class SdEntryType(Enum):
    FIND_SERVICE = 0x00
    OFFER_SERVICE = 0x01
    SUBSCRIBE_EVENTGROUP = 0x06
    SUBSCRIBE_EVENTGROUP_ACK = 0x07
    UNKNOWN = 0xFF

    @classmethod
    def from_int(cls, val: int) -> SdEntryType:
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


class SdOptionType(Enum):
    CONFIGURATION = 0x01
    LOAD_BALANCING = 0x02
    IPV4_ENDPOINT = 0x04
    IPV6_ENDPOINT = 0x06
    IPV4_MULTICAST = 0x14
    IPV6_MULTICAST = 0x16
    IPV4_SD_ENDPOINT = 0x24
    IPV6_SD_ENDPOINT = 0x26
    UNKNOWN = 0xFF

    @classmethod
    def from_int(cls, val: int) -> SdOptionType:
        try:
            return cls(val)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class SomeIpHeader:
    service_id: int
    method_id: int
    is_event: bool
    length: int
    client_id: int
    session_id: int
    protocol_version: int
    interface_version: int
    message_type: MessageType
    return_code: ReturnCode

    # SOME/IP-TP fields
    is_tp: bool = False
    tp_offset: int = 0
    tp_more_segments: bool = False

    @property
    def total_size(self) -> int:
        return self.length + 8


@dataclass
class SdOption:
    option_type: SdOptionType
    type_name: str
    discardable: bool
    ip: str = ""
    port: int = 0
    proto: str = ""
    config_string: str = ""


@dataclass
class SdEntry:
    entry_type: SdEntryType
    type_name: str
    service_id: int
    instance_id: int
    major_version: int
    minor_version: int
    ttl: int
    eventgroup_id: int = 0
    counter: int = 0
    initial_data_requested: bool = False
    opt1_index: int = 0
    opt1_count: int = 0
    opt2_index: int = 0
    opt2_count: int = 0
    endpoint_options: List[SdOption] = field(default_factory=list)


@dataclass
class SomeIpSdMessage:
    reboot_flag: bool
    unicast_flag: bool
    explicit_initial_data_control: bool
    raw_flags: int
    entries: List[SdEntry] = field(default_factory=list)
    options: List[SdOption] = field(default_factory=list)


@dataclass
class SomeIpMessage:
    header: SomeIpHeader
    payload: bytes
    is_sd: bool = False
    sd: Optional[SomeIpSdMessage] = None


def decode_someip(data: bytes, offset: int = 0) -> List[SomeIpMessage]:
    """
    Decodes one or more SOME/IP messages from binary data.
    """
    messages: List[SomeIpMessage] = []
    data_len = len(data)

    while offset + 16 <= data_len:
        service_id, raw_method, length = struct.unpack(">HHI", data[offset : offset + 8])
        if length < 8:
            break

        total_pdu_size = length + 8
        # Message must not exceed remaining bytes or sanity bound (16MB)
        if total_pdu_size > (data_len - offset) or total_pdu_size > 16777216:
            break

        client_id, session_id, proto_ver, iface_ver, raw_type, raw_code = struct.unpack(
            ">HHBBBB", data[offset + 8 : offset + 16]
        )

        # In AUTOSAR SOME/IP, Protocol Version MUST be 1
        if proto_ver != 1:
            break

        msg_type = MessageType.from_int(raw_type)
        if msg_type == MessageType.UNKNOWN:
            break

        return_code = ReturnCode.from_int(raw_code)
        if return_code == ReturnCode.UNKNOWN:
            # rc 0xFF (our sentinel) or any undefined code — not a valid SOME/IP message.
            # Note: 0x00-0x0F and E2E 0x20-0x5F are defined; anything else is reserved.
            # ReturnCode.from_int() returns UNKNOWN for any value not in the defined enum,
            # so this single check covers all invalid return codes without needing extra range tests.
            break

        # Validate SOME/IP-SD (0xFFFF:0x8100) specifics
        is_sd = (service_id == 0xFFFF and raw_method == 0x8100)
        if is_sd and (client_id != 0x0000 or raw_type not in (0x02, 0x00) or raw_code != 0x00):
            break


        is_event = bool(raw_method & 0x8000)
        is_tp = bool(raw_type & 0x20)

        header_size = 16
        tp_offset = 0
        tp_more = False

        if is_tp and (offset + 20 <= data_len):
            (tp_word,) = struct.unpack(">I", data[offset + 16 : offset + 20])
            tp_offset = tp_word & 0xFFFFFFF0
            tp_more = bool(tp_word & 0x01)
            header_size = 20

        header = SomeIpHeader(
            service_id=service_id,
            method_id=raw_method,
            is_event=is_event,
            length=length,
            client_id=client_id,
            session_id=session_id,
            protocol_version=proto_ver,
            interface_version=iface_ver,
            message_type=msg_type,
            return_code=return_code,
            is_tp=is_tp,
            tp_offset=tp_offset,
            tp_more_segments=tp_more,
        )

        avail_pdu_bytes = min(data_len - offset, total_pdu_size)
        payload_bytes = b""
        if avail_pdu_bytes > header_size:
            payload_bytes = data[offset + header_size : offset + avail_pdu_bytes]

        is_sd = (service_id == 0xFFFF and raw_method == 0x8100)
        sd_obj: Optional[SomeIpSdMessage] = None
        if is_sd and payload_bytes:
            sd_obj = decode_sd(payload_bytes)

        msg = SomeIpMessage(
            header=header,
            payload=payload_bytes,
            is_sd=is_sd,
            sd=sd_obj,
        )
        messages.append(msg)

        if total_pdu_size <= 0:
            break
        offset += total_pdu_size

    return messages


def decode_sd(payload: bytes) -> Optional[SomeIpSdMessage]:
    """
    Decodes SOME/IP-SD payload starting at the SD header (flags).
    """
    if len(payload) < 12:
        return None

    raw_flags = payload[0]
    reboot_flag = bool(raw_flags & 0x80)
    unicast_flag = bool(raw_flags & 0x40)
    explicit_init = bool(raw_flags & 0x20)

    (entries_len,) = struct.unpack(">I", payload[4:8])
    entries_start = 8
    entries_end = entries_start + entries_len
    if entries_end > len(payload):
        return None

    # Parse options first
    options_len_pos = entries_end
    all_options: List[SdOption] = []

    if options_len_pos + 4 <= len(payload):
        (options_len,) = struct.unpack(
            ">I", payload[options_len_pos : options_len_pos + 4]
        )
        opt_start = options_len_pos + 4
        opt_end = min(len(payload), opt_start + options_len)

        curr = opt_start
        while curr + 4 <= opt_end:
            opt_len, raw_type, discardable_byte = struct.unpack(
                ">HBB", payload[curr : curr + 4]
            )
            # In AUTOSAR SD, length excludes Length (2) and Type (1), so record len is opt_len + 3
            record_len = opt_len + 3
            if opt_len == 10:
                record_len = 12

            if record_len < 4 or curr + record_len > opt_end:
                break

            opt_type = SdOptionType.from_int(raw_type)
            discardable = bool(discardable_byte & 0x80)

            ip_str = ""
            proto_str = ""
            port_num = 0
            cfg_str = ""

            if opt_type in (
                SdOptionType.IPV4_ENDPOINT,
                SdOptionType.IPV4_MULTICAST,
                SdOptionType.IPV4_SD_ENDPOINT,
            ):
                if record_len >= 12:
                    ip_bytes = payload[curr + 4 : curr + 8]
                    ip_str = str(ipaddress.IPv4Address(ip_bytes))
                    proto_val = payload[curr + 9]
                    proto_str = "UDP" if proto_val == 17 else "TCP" if proto_val == 6 else str(proto_val)
                    (port_num,) = struct.unpack(">H", payload[curr + 10 : curr + 12])
            elif opt_type in (
                SdOptionType.IPV6_ENDPOINT,
                SdOptionType.IPV6_MULTICAST,
                SdOptionType.IPV6_SD_ENDPOINT,
            ):
                if record_len >= 24:
                    ip_bytes = payload[curr + 4 : curr + 20]
                    ip_str = str(ipaddress.IPv6Address(ip_bytes))
                    proto_val = payload[curr + 21]
                    proto_str = "UDP" if proto_val == 17 else "TCP" if proto_val == 6 else str(proto_val)
                    (port_num,) = struct.unpack(">H", payload[curr + 22 : curr + 24])
            elif opt_type == SdOptionType.CONFIGURATION:
                if record_len > 4:
                    cfg_str = payload[curr + 4 : curr + record_len].decode("utf-8", errors="replace")

            opt = SdOption(
                option_type=opt_type,
                type_name=opt_type.name,
                discardable=discardable,
                ip=ip_str,
                port=port_num,
                proto=proto_str,
                config_string=cfg_str,
            )
            all_options.append(opt)
            curr += record_len

    # Parse entries
    entries: List[SdEntry] = []
    curr_e = entries_start

    while curr_e + 16 <= entries_end:
        type_val, opt1_idx, opt2_idx, num_opts = struct.unpack(
            ">BBBB", payload[curr_e : curr_e + 4]
        )
        opt1_count = (num_opts >> 4) & 0x0F
        opt2_count = num_opts & 0x0F

        service_id, instance_id, major_ver = struct.unpack(
            ">HHB", payload[curr_e + 4 : curr_e + 9]
        )
        # 24-bit TTL
        ttl = (payload[curr_e + 9] << 16) | (payload[curr_e + 10] << 8) | payload[curr_e + 11]

        entry_type = SdEntryType.from_int(type_val)

        minor_ver = 0
        eventgroup_id = 0
        counter = 0
        initial_data_flag = False

        if entry_type in (SdEntryType.FIND_SERVICE, SdEntryType.OFFER_SERVICE):
            (minor_ver,) = struct.unpack(">I", payload[curr_e + 12 : curr_e + 16])
            if entry_type == SdEntryType.FIND_SERVICE:
                type_name = "FindService"
            else:
                type_name = "OfferService" if ttl > 0 else "StopOfferService"
        elif entry_type in (
            SdEntryType.SUBSCRIBE_EVENTGROUP,
            SdEntryType.SUBSCRIBE_EVENTGROUP_ACK,
        ):
            b12 = payload[curr_e + 12]
            counter = b12 & 0x0F
            initial_data_flag = bool(b12 & 0x10)
            (eventgroup_id,) = struct.unpack(">H", payload[curr_e + 14 : curr_e + 16])
            if entry_type == SdEntryType.SUBSCRIBE_EVENTGROUP:
                type_name = "SubscribeEventgroup" if ttl > 0 else "StopSubscribeEventgroup"
            else:
                type_name = "SubscribeEventgroupAck" if ttl > 0 else "SubscribeEventgroupNack"
        else:
            type_name = f"UnknownEntry(0x{type_val:02X})"

        # Resolve options referenced by this entry
        ref_options: List[SdOption] = []
        for i in range(opt1_count):
            idx = opt1_idx + i
            if idx < len(all_options):
                ref_options.append(all_options[idx])
        for i in range(opt2_count):
            idx = opt2_idx + i
            if idx < len(all_options):
                ref_options.append(all_options[idx])

        entry = SdEntry(
            entry_type=entry_type,
            type_name=type_name,
            service_id=service_id,
            instance_id=instance_id,
            major_version=major_ver,
            minor_version=minor_ver,
            ttl=ttl,
            eventgroup_id=eventgroup_id,
            counter=counter,
            initial_data_requested=initial_data_flag,
            opt1_index=opt1_idx,
            opt1_count=opt1_count,
            opt2_index=opt2_idx,
            opt2_count=opt2_count,
            endpoint_options=ref_options,
        )
        entries.append(entry)
        curr_e += 16

    return SomeIpSdMessage(
        reboot_flag=reboot_flag,
        unicast_flag=unicast_flag,
        explicit_initial_data_control=explicit_init,
        raw_flags=raw_flags,
        entries=entries,
        options=all_options,
    )


def format_hex_dump(data: bytes, width: int = 16) -> str:
    """
    Formats binary data as a Wireshark-style hex dump with offset and ASCII.
    """
    if not data:
        return "(No payload data)"

    lines: List[str] = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        # Pad hex display if line is short
        if len(chunk) < width:
            hex_bytes += "   " * (width - len(chunk))
        ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_bytes}  |{ascii_repr}|")

    return "\n".join(lines)


def interpret_payload(data: bytes, offset: int = 0) -> Dict[str, Any]:
    """
    Attempts common field interpretations from the start of data (or at given offset).
    """
    res: Dict[str, Any] = {}
    if offset > 0:
        data = data[offset:]
    length = len(data)
    res["Length (bytes)"] = length

    if length >= 1:
        res["Uint8"] = data[0]
        res["Int8"] = struct.unpack(">b", data[:1])[0]

    if length >= 2:
        res["Uint16 (BE)"] = struct.unpack(">H", data[:2])[0]
        res["Int16 (BE)"] = struct.unpack(">h", data[:2])[0]

    if length >= 4:
        res["Uint32 (BE)"] = struct.unpack(">I", data[:4])[0]
        res["Int32 (BE)"] = struct.unpack(">i", data[:4])[0]
        try:
            res["Float32 (BE)"] = round(struct.unpack(">f", data[:4])[0], 4)
        except (ValueError, OverflowError):
            pass

    if length >= 8:
        res["Uint64 (BE)"] = struct.unpack(">Q", data[:8])[0]
        try:
            res["Float64 (BE)"] = round(struct.unpack(">d", data[:8])[0], 4)
        except (ValueError, OverflowError):
            pass
        # Common pattern: uint32 counter + float32 value (e.g., telemetry sensors)
        try:
            cnt, val = struct.unpack(">If", data[:8])
            res["Telemetry (>If)"] = f"Counter={cnt}, Value={val:.2f}"
        except Exception:
            pass

    # Try ASCII decode
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    if length > 0 and (printable / length) > 0.7:
        res["ASCII string"] = data.decode("utf-8", errors="replace")

    return res
